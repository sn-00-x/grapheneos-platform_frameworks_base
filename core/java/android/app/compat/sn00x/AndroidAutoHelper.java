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
import android.util.ArraySet;
import android.util.PackageUtils;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * This class provides helpers for Android Auto
 *
 * @hide
 */
public final class AndroidAutoHelper {
    private static final String PACKAGE_ANDROIDAUTO = "com.google.android.projection.gearhead";
    private static final String SIGNATURE_ANDROIDAUTO = "FDB00C43DBDE8B51CB312AA81D3B5FA17713ADB94B28F598D77F8EB89DACEEDF"; // CN=gearhead, OU=Android, O=Google Inc., L=Mountain View, ST=California, C=US

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

    private static boolean isAndroidAuto = false;
    private static Context context;

    private static int androidAutoUid = -1;

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
     * Checks if additional permission should be granted
     *
     * @hide
     */
    public static boolean hasAdditionalPermission(String packageName, String permissionName, SigningDetails signingDetails) {

        if (PACKAGE_ANDROIDAUTO.equals(packageName) && isAndroidAuto(packageName, signingDetails)
                && PERMISSIONS_ANDROIDAUTO.contains(permissionName)) {
            return true;
        }

        return false;
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
    }
}
