/*
Filename: agentAndroidClasses.js
Author: Michael Krueger (mkrueger@nowsecure.com)
Date: 2026-04-08
Version: 1.0
Description:
    This Frida agent performs Android runtime SDK discovery by scanning loaded Java classes and
    native library load events against regex patterns compiled from the shared signatures.json file.
    It is intended to be compiled with frida-compile and loaded by frida-androidClassScan.js to
    emit runtime evidence about likely third-party SDK presence. For more help, see the README.
*/
import Java from 'frida-java-bridge';

let appPackage = "";
let signatures = [];
const reported = new Set();

function normalizePattern(pattern) {
    try {
        return new RegExp(pattern, 'i');
    } catch (error) {
        send({
            type: 'warning',
            message: `Skipping invalid signature pattern: ${pattern}`,
            error: String(error)
        });
        return null;
    }
}

function scanForSignatures(nameToTest, type) {
    if (!nameToTest) {
        return false;
    }

    const normalizedName = String(nameToTest);

    if (appPackage && normalizedName.startsWith(appPackage)) {
        return false;
    }

    for (const item of signatures) {
        for (const pattern of item.patterns) {
            if (pattern.test(normalizedName)) {
                const reportKey = `${item.name}:${type}`;
                if (!reported.has(reportKey)) {
                    reported.add(reportKey);
                    send({
                        type: 'match',
                        sdkName: item.name,
                        evidence: normalizedName,
                        evidenceType: type
                    });
                }
                return true;
            }
        }
    }

    return false;
}

function startScan() {
    Java.perform(function() {
        Java.enumerateLoadedClasses({
            onMatch: (className) => scanForSignatures(className, 'JAVA_CLASS'),
            onComplete: () => {}
        });

        const System = Java.use('java.lang.System');
        const loadLibrary = System.loadLibrary.overload('java.lang.String');
        loadLibrary.implementation = function(lib) {
            scanForSignatures(lib, 'JAVA_LOAD_LIB');
            return loadLibrary.call(this, lib);
        };

        const dlopenPtr = Module.findExportByName(null, 'android_dlopen_ext') ||
            Module.findExportByName(null, 'dlopen');

        if (dlopenPtr) {
            Interceptor.attach(dlopenPtr, {
                onEnter(args) {
                    this.path = args[0].isNull() ? null : args[0].readUtf8String();
                },
                onLeave() {
                    if (this.path && this.path.includes('.so')) {
                        const fileName = this.path.split('/').pop();
                        scanForSignatures(fileName, 'NATIVE_DLOPEN');
                    }
                }
            });
        } else {
            send({
                type: 'warning',
                message: 'Unable to locate dlopen export; native library hook not installed.'
            });
        }

        send({
            type: 'ready',
            loadedSignatureCount: signatures.length
        });
    });
}

recv('config', (message) => {
    const payload = message.payload || {};
    appPackage = payload.appPackage || "";
    signatures = (payload.signatures || [])
        .map((item) => ({
            name: item.name,
            patterns: (item.patterns || [])
                .map(normalizePattern)
                .filter(Boolean)
        }))
        .filter((item) => item.patterns.length > 0);

    startScan();
});
