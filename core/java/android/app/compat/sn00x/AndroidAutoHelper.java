/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.app.compat.sn00x;

import android.app.ActivityThread;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.IPackageManager;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningDetails;
import android.content.pm.SigningInfo;
import android.os.Build;
import android.os.RemoteException;
import android.provider.Settings;
import android.util.ArraySet;
import android.util.PackageUtils;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * This class provides helpers for Android Auto, screen2auto and media app compatibility.
 *
 * @hide
 */
public final class AndroidAutoHelper {
    private static final String PACKAGE_ANDROIDAUTO = "com.google.android.projection.gearhead";
    private static final String SIGNATURE_ANDROIDAUTO = "FDB00C43DBDE8B51CB312AA81D3B5FA17713ADB94B28F598D77F8EB89DACEEDF"; // CN=gearhead, OU=Android, O=Google Inc., L=Mountain View, ST=California, C=US
    // change the following two lines for screen2auto support
    private static final String PACKAGE_SCREEN2AUTO = null;
    private static final String SIGNATURE_SCREEN2AUTO = null;
    private static final List<String> PACKAGES_MEDIAAPPS = Arrays.asList(
            "com.netflix.mediaclient", // Netflix
            "com.amazon.avod.thirdpartyclient", // Amazon Prime
            "com.disney.disneyplus", // Disney+
            "com.spotify.music" // Spotify
    );

    private static boolean androidAutoActive = false;
    private static boolean screenCaptureActive = false;

    // Define additionally allowed permissions for AndroidAuto
    private static final ArrayList<String> PERMISSIONS_ANDROIDAUTO = new ArrayList<String>(
            Arrays.asList(
                    "android.permission.INTERNAL_SYSTEM_WINDOW",
                    "android.permission.MANAGE_COMPANION_DEVICES",
                    "android.permission.MANAGE_USB",
                    "android.permission.MODIFY_AUDIO_ROUTING",
                    "android.permission.READ_PHONE_STATE",
                    "android.permission.READ_PRIVILEGED_PHONE_STATE",
                    "android.permission.REQUEST_COMPANION_SELF_MANAGED",
                    "android.permission.BLUETOOTH_PRIVILEGED",
                    "android.permission.LOCAL_MAC_ADDRESS",
                    "android.permission.CONTROL_INCALL_EXPERIENCE",
                    "android.permission.COMPANION_APPROVE_WIFI_CONNECTIONS",
                    "android.permission.START_ACTIVITIES_FROM_BACKGROUND"
            )
    );

    /* Define additionally allowed permissions for Screen2Auto - these will only be allowed when car is connected(!) */
    private static final ArrayList<String> PERMISSIONS_SCREEN2AUTO = new ArrayList<String>(
            Arrays.asList(
                    "android.permission.CAPTURE_VIDEO_OUTPUT", // avoid cast confirmation dialog
                    "android.permission.SYSTEM_APPLICATION_OVERLAY", // display over other apps
                    "android.permission.START_ACTIVITIES_FROM_BACKGROUND"
            )
    );
    // grant additional permissions while screen2auto is capturing the screen
    private static final ArrayList<String> PERMISSIONS_SCREEN2AUTO_DURING_SCREENCAPTURE = new ArrayList<String>(
            Arrays.asList(
                    "android.permission.BIND_ACCESSIBILITY_SERVICE"
            )
    );

    // Spoof permission checks for Screen2Auto
    private static final ArrayList<String> SPOOF_PERMISSIONS_SCREEN2AUTO = new ArrayList<String>(
            Arrays.asList(
                    "android.permission.SYSTEM_APPLICATION_OVERLAY" // display over other apps
            )
    );

    private static boolean isAndroidAuto = false;
    private static boolean isScreen2Auto = false;
    private static boolean isMediaApp = false;
    private static Context context;

    private static int androidAutoUid = -1;
    private static int screen2AutoUid = -1;

    // Static only
    private AndroidAutoHelper() { }

    /** @hide */
    public static Context appContext() {
        return context;
    }

    private static boolean uidBelongsToOneOfPackages(int uid, List<String> packages) {
        if (uid == 0) {
            return false;
        }
        try {
            return packages.stream().anyMatch(
                    e -> Arrays.asList(context.getPackageManager().getPackagesForUid(uid)).contains(e)
            );
        } catch (Exception ignored) {}
        return false;
    }

    private static boolean uidBelongsToPackage(int uid, String packageName) {
        return uidBelongsToOneOfPackages(uid, Collections.singletonList(packageName));
    }

    private static boolean validateCertDigests(Signature[] signatures, Set<String> validSignatureDigests) throws NoSuchAlgorithmException {
        for (Signature signature : signatures) {
            String signatureDigest = PackageUtils.computeSha256Digest(signature.toByteArray());

            if (validSignatureDigests.contains(signatureDigest)) {
                return true;
            }
        }
        return false;
    }

    private static boolean packageMatchesSignatureDigests(String packageName, Set<String> validSignatureDigests) {
        IPackageManager pm = ActivityThread.getPackageManager();
        try {
            PackageInfo pkg = pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES, 0);

            SigningInfo si = pkg.signingInfo;
            Signature[] signatures = si.getApkContentsSigners();

            boolean validCert = validateCertDigests(signatures, validSignatureDigests);

            if (!validCert && si.hasPastSigningCertificates()) {
                Signature[] pastSignatures = si.getSigningCertificateHistory();
                validCert = validateCertDigests(pastSignatures, validSignatureDigests);
            }

            return validCert;
        } catch (RemoteException e) {
            e.rethrowFromSystemServer();
        } catch (NoSuchAlgorithmException ignore) {} // won't happen

        return false;
    }

    /**
     * Checks if packageName is AndroidAuto and package has matching signature
     *
     * @hide
     */
    public static boolean isAndroidAuto(String packageName) {
        if (!PACKAGE_ANDROIDAUTO.equals(packageName)) {
            return false;
        }

        IPackageManager pm = ActivityThread.getPackageManager();
        try {
            ApplicationInfo ai = pm.getApplicationInfo(packageName, 0, 0);
            if (ai.uid == androidAutoUid) {
                return true;
            } else if (androidAutoUid == -1) {
                if (packageMatchesSignatureDigests(packageName, new ArraySet<>(Collections.singletonList(SIGNATURE_ANDROIDAUTO)))) {
                    synchronized (AndroidAutoHelper.class) {
                        androidAutoUid = ai.uid;
                    }
                    return true;
                }
            }
        } catch (RemoteException e) {
            e.rethrowFromSystemServer();
        }

        return false;
    }

    /**
     * Checks if uid belongs to AndroidAuto, and package has matching signature
     *
     * @hide
     */
    public static boolean isAndroidAuto(int uid) {
        if ((uid != -1) && (uid == androidAutoUid)) {
            return true;
        }
        return uidBelongsToPackage(uid, PACKAGE_ANDROIDAUTO) && isAndroidAuto(PACKAGE_ANDROIDAUTO);
    }

    /**
     * Checks if packageName and uid belong to AndroidAuto, and package has matching signature
     *
     * @hide
     */
    public static boolean isAndroidAuto(String packageName, int uid) {
        if (PACKAGE_ANDROIDAUTO.equals(packageName) && isAndroidAuto(uid)) {
            return true;
        }
        return false;
    }

    /**
     * Checks if packageName is AndroidAuto and signingDetails match
     *
     * @hide
     */
    public static boolean isAndroidAuto(String packageName, SigningDetails signingDetails) {
        if (PACKAGE_ANDROIDAUTO.equals(packageName)
                && signingDetails.hasAncestorOrSelfWithDigest(new ArraySet<>(Collections.singletonList(SIGNATURE_ANDROIDAUTO)))) {
            return true;
        }
        return false;
    }

    /**
     * Checks if packageName is Screen2Auto and package has matching signature
     *
     * @hide
     */
    public static boolean isScreen2Auto(String packageName) {
        if (PACKAGE_SCREEN2AUTO == null) {
            return false;
        }
        if (!PACKAGE_SCREEN2AUTO.equals(packageName)) {
            return false;
        }

        IPackageManager pm = ActivityThread.getPackageManager();
        try {
            ApplicationInfo ai = pm.getApplicationInfo(packageName, 0, 0);
            if (ai.uid == screen2AutoUid) {
                return true;
            } else if (screen2AutoUid == -1) {
                if (packageMatchesSignatureDigests(packageName, new ArraySet<>(Collections.singletonList(SIGNATURE_SCREEN2AUTO)))) {
                    synchronized (AndroidAutoHelper.class) {
                        screen2AutoUid = ai.uid;
                    }
                    return true;
                }
            }
        } catch (RemoteException e) {
            e.rethrowFromSystemServer();
        }

        return false;
    }

    /**
     * Checks if uid belongs to Screen2Auto, and package has matching signature
     *
     * @hide
     */
    public static boolean isScreen2Auto(int uid) {
        if (PACKAGE_SCREEN2AUTO == null) {
            return false;
        }
        if ((uid != -1) && (uid == screen2AutoUid)) {
            return true;
        }
        return uidBelongsToPackage(uid, PACKAGE_SCREEN2AUTO) && isScreen2Auto(PACKAGE_SCREEN2AUTO);
    }

    /**
     * Checks if packageName is Screen2Auto and signingDetails match
     *
     * @hide
     */
    public static boolean isScreen2Auto(String packageName, SigningDetails signingDetails) {
        if (PACKAGE_SCREEN2AUTO == null) {
            return false;
        }
        if (PACKAGE_SCREEN2AUTO.equals(packageName)
                && signingDetails.hasAncestorOrSelfWithDigest(new ArraySet<>(Collections.singletonList(SIGNATURE_SCREEN2AUTO)))) {
            return true;
        }
        return false;
    }

    /**
     * Checks if additional permission should be granted
     *
     * @hide
     */
    public static boolean hasAdditionalPermission(String packageName, String permissionName, SigningDetails signingDetails) {

        if (PACKAGE_ANDROIDAUTO.equals(packageName) && isAndroidAuto(packageName, signingDetails)
                && PERMISSIONS_ANDROIDAUTO.contains(permissionName)) {
            return true;
        }

        if (PACKAGE_SCREEN2AUTO == null) {
            return false;
        }

        if (PACKAGE_SCREEN2AUTO.equals(packageName) && androidAutoActive && isScreen2Auto(packageName, signingDetails)) {
            if (PERMISSIONS_SCREEN2AUTO.contains(permissionName)) {
                return true;
            }
            if (screenCaptureActive && PERMISSIONS_SCREEN2AUTO_DURING_SCREENCAPTURE.contains(permissionName)) {
                return true;
            }
        }

        return false;
    }

    /** @hide */
    public static boolean isMediaAppContext() {
        return isMediaApp;
    }

    /** @hide */
    public static boolean isMediaApp(int uid) {
        return uidBelongsToOneOfPackages(uid, PACKAGES_MEDIAAPPS);
    }

    /** @hide */
    public static void applicationStart(Context context) {
        AndroidAutoHelper.context = context;
        ApplicationInfo appInfo = context.getApplicationInfo();

        if (appInfo == null || !appInfo.enabled) {
            return;
        }

        String pkgName = appInfo.packageName;

        isAndroidAuto = isAndroidAuto(pkgName); // also checks signature
        isScreen2Auto = isScreen2Auto(pkgName); // also checks signature
        isMediaApp = PACKAGES_MEDIAAPPS.contains(pkgName);
    }

    private static void handleDisplayChanged(String name, int ownerUid, boolean added)
    {
        if (name.equals("Dashboard") && isAndroidAuto(ownerUid)) {
            androidAutoActive = added;
        }
        if (name.equals("ScreenCapture") && isScreen2Auto(ownerUid)) {
            setScreenCaptureActive(added);
        }
    }

    /** @hide */
    public static void handleDisplayAdded(String name, int ownerUid) {
        handleDisplayChanged(name, ownerUid, true);
    }

    /** @hide */
    public static void handleDisplayRemoved(String name, int ownerUid) {
        handleDisplayChanged(name, ownerUid, false);
    }

    /**
     * adds/removes Screen2Auto's accessibility service when "ScreenCapture" display device is added/removed.
     * */
    private static void setScreenCaptureActive(boolean screenCaptureActiveStatus) {
        screenCaptureActive = screenCaptureActiveStatus;

        String accessibilityService = PACKAGE_SCREEN2AUTO + "/ru.inceptive.screentwoauto.services.SplitScreenService";

        int accessibilityEnabled = 0;

        try {
            accessibilityEnabled = Settings.Secure.getInt(
                    context.getContentResolver(),
                    android.provider.Settings.Secure.ACCESSIBILITY_ENABLED);

            if (accessibilityEnabled == 0) {
                Settings.Secure.putInt(context.getContentResolver(),
                        android.provider.Settings.Secure.ACCESSIBILITY_ENABLED, 1);
            }

            String services = Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);
            if (screenCaptureActiveStatus && ((services == null) || !services.contains(accessibilityService))) {
                if (services == null) {
                    services = "";
                }
                if (services.length() > 0) {
                    services += ":";
                }
                services += accessibilityService;
            } else if (!screenCaptureActiveStatus && (services != null) && services.contains(accessibilityService)) {
                services = services.replace(accessibilityService, "");
            }

            services = services.replace("::", ":");
            if (services.length() <= 1) {
                services = null;
            }

            Settings.Secure.putString(context.getContentResolver(),
                    Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES, services);
        } catch (Exception ignored) {}
    }

    /** @hide */
    public static boolean isScreenCaptureActive() {
        return screenCaptureActive;
    }

    /** @hide */
    public static boolean shouldSpoofSelfPermissionCheck(String perm) {
        return isScreen2Auto && SPOOF_PERMISSIONS_SCREEN2AUTO.contains(perm);
    }
}
