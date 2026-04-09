/*
Filename: agentAndroidNetworkSignatures.js
Author: Michael Krueger (mkrueger@nowsecure.com)
Date: 2026-04-08
Version: 1.0
Description:
    This Frida agent performs Android runtime SDK network attribution by hooking common Java and
    OkHttp networking APIs, capturing stack traces, and correlating them with regex patterns derived
    from the shared signatures.json file. It is intended to be compiled with frida-compile and
    loaded by frida-androidNetworkSignatures.js to emit attribution and diagnostic events for likely
    third-party SDK network activity. For more help, see the README.
*/
import Java from 'frida-java-bridge';

let appPackage = "";
let signatures = [];
const reported = new Set();
const sdkNamespaces = new Map();
const alertThrottle = new Map();
const MAX_NAMESPACE_SEGMENTS = 3;
const ALERT_THROTTLE_MS = 2500;
const DEBUG_LOGS = true;

function forceString(value) {
    if (value === null || value === undefined) {
        return '';
    }
    if (typeof value === 'string') {
        return value;
    }
    try {
        return String(value);
    } catch (_) {
        return '';
    }
}

function normalizePattern(pattern) {
    try {
        return new RegExp(pattern, 'i');
    } catch (error) {
        send({
            type: 'AGENT_ERROR',
            where: 'normalizePattern',
            error: `Skipping invalid signature pattern: ${pattern}`,
            stack: forceString(error && error.stack ? error.stack : error)
        });
        return null;
    }
}

function patternToNamespaceCandidates(patternText) {
    const raw = forceString(patternText);
    if (!raw) {
        return [];
    }

    const normalized = raw
        .replace(/\\\./g, '.')
        .replace(/\\b/g, '')
        .replace(/\(\?:/g, '(')
        .replace(/[\^\$\?\+\*\[\]\(\)\|]/g, ' ')
        .replace(/[^a-zA-Z0-9._-]/g, ' ');

    return normalized
        .split(/\s+/)
        .map((part) => part.trim())
        .filter((part) => part.includes('.'))
        .filter((part) => /[a-zA-Z]/.test(part));
}

function deriveNamespace(input) {
    if (!input) {
        return null;
    }

    const cleaned = forceString(input)
        .replace(/^\[?L/, '')
        .replace(/;$/, '')
        .replace(/\$/g, '.')
        .replace(/[^a-zA-Z0-9._]/g, '');

    const parts = cleaned.split('.').filter(Boolean);
    if (parts.length < 2) {
        return null;
    }

    const last = parts[parts.length - 1];
    const likelyClassName = /^[A-Z]/.test(last);
    const end = likelyClassName ? parts.length - 1 : parts.length;
    if (end < 2) {
        return null;
    }

    return parts.slice(0, Math.min(MAX_NAMESPACE_SEGMENTS, end)).join('.');
}

function addNamespace(sdkName, candidate) {
    const ns = deriveNamespace(candidate);
    if (!ns || !sdkName) {
        return;
    }

    if (!sdkNamespaces.has(sdkName)) {
        sdkNamespaces.set(sdkName, new Set());
    }

    sdkNamespaces.get(sdkName).add(ns);
}

function reportDebug(message, extra) {
    if (!DEBUG_LOGS) {
        return;
    }

    send({
        type: 'DEBUG',
        message,
        extra: extra || null
    });
}

function reportAgentError(where, err) {
    try {
        send({
            type: 'AGENT_ERROR',
            where: forceString(where),
            error: forceString(err && err.message ? err.message : err),
            stack: forceString(err && err.stack ? err.stack : '')
        });
    } catch (_) {
        // Avoid recursive failures in diagnostics.
    }
}

function recordSignatureMatch(item, evidence, evidenceType) {
    const reportKey = `${item.name}:${evidenceType}`;
    if (reported.has(reportKey)) {
        return;
    }

    reported.add(reportKey);
    send({
        type: 'SIGNATURE_MATCH',
        sdkName: item.name,
        evidence,
        evidenceType
    });
}

function scanForSignatures(nameToTest, evidenceType) {
    const candidate = forceString(nameToTest);
    if (!candidate) {
        return false;
    }

    if (appPackage && candidate.startsWith(appPackage)) {
        return false;
    }

    for (const item of signatures) {
        for (const regex of item.regexes) {
            if (regex.test(candidate)) {
                addNamespace(item.name, candidate);
                recordSignatureMatch(item, candidate, evidenceType);
                return true;
            }
        }
    }

    return false;
}

function configureSignatures(payload) {
    appPackage = forceString(payload.appPackage);
    signatures = (payload.signatures || [])
        .map((item) => {
            const regexes = (item.patterns || [])
                .map((pattern) => ({
                    raw: pattern,
                    regex: normalizePattern(pattern)
                }))
                .filter((entry) => entry.regex);

            const namespaces = new Set();
            for (const entry of regexes) {
                for (const candidate of patternToNamespaceCandidates(entry.raw)) {
                    const ns = deriveNamespace(candidate);
                    if (ns) {
                        namespaces.add(ns);
                    }
                }
            }

            return {
                name: item.name,
                regexes: regexes.map((entry) => entry.regex),
                rawPatterns: regexes.map((entry) => entry.raw),
                namespaces: Array.from(namespaces)
            };
        })
        .filter((item) => item.regexes.length > 0);

    sdkNamespaces.clear();
    for (const item of signatures) {
        for (const namespace of item.namespaces) {
            addNamespace(item.name, namespace);
        }
    }
}

function startScan() {
    Java.perform(function() {
        const Exception = Java.use('java.lang.Exception');
        const Log = Java.use('android.util.Log');

        function getStackTrace() {
            try {
                return Log.getStackTraceString(Exception.$new());
            } catch (_) {
                return '';
            }
        }

        function getStackHead(stack) {
            if (!stack) {
                return '';
            }
            return stack.split('\n').slice(1, 8).join('\n');
        }

        function safeToString(obj) {
            try {
                if (!obj) {
                    return '';
                }
                const raw = (typeof obj.toString === 'function') ? obj.toString() : obj;
                return forceString(raw);
            } catch (_) {
                return '';
            }
        }

        function getOkHttpRequestUrl(callLike, args) {
            try {
                if (callLike && typeof callLike.request === 'function') {
                    const req = callLike.request();
                    if (req && typeof req.url === 'function') {
                        return safeToString(req.url());
                    }
                    return safeToString(req);
                }
            } catch (_) {}

            try {
                if (args && args.length > 0) {
                    const maybeReqOrChain = args[0];
                    if (maybeReqOrChain && typeof maybeReqOrChain.request === 'function') {
                        const req = maybeReqOrChain.request();
                        if (req && typeof req.url === 'function') {
                            return safeToString(req.url());
                        }
                        return safeToString(req);
                    }
                    if (maybeReqOrChain && typeof maybeReqOrChain.url === 'function') {
                        return safeToString(maybeReqOrChain.url());
                    }
                    return safeToString(maybeReqOrChain);
                }
            } catch (_) {}

            return '';
        }

        function matchSdksFromStack(stack) {
            if (!stack) {
                return [];
            }

            const matches = [];

            for (const item of signatures) {
                const matchedNamespaces = Array.from(sdkNamespaces.get(item.name) || [])
                    .filter((namespace) => stack.includes(namespace));

                const matchedPatterns = item.rawPatterns.filter((pattern, index) => {
                    const regex = item.regexes[index];
                    return regex && regex.test(stack);
                });

                if (matchedNamespaces.length > 0 || matchedPatterns.length > 0) {
                    matches.push({
                        sdkName: item.name,
                        matchedNamespaces,
                        matchedPatterns
                    });
                }
            }

            return matches;
        }

        function reportNetworkCall(hook, target) {
            const stack = getStackTrace();
            if (!stack) {
                return;
            }

            if (target) {
                scanForSignatures(target, 'NETWORK_TARGET');
            }

            const matches = matchSdksFromStack(stack);
            for (const match of matches) {
                const key = [
                    match.sdkName,
                    hook,
                    target || hook,
                    match.matchedNamespaces.join(','),
                    match.matchedPatterns.join(',')
                ].join('|');

                const now = Date.now();
                const last = alertThrottle.get(key) || 0;
                if (now - last < ALERT_THROTTLE_MS) {
                    continue;
                }
                alertThrottle.set(key, now);

                send({
                    type: 'NETWORK_STACK_MATCH',
                    sdkName: match.sdkName,
                    hook,
                    evidence: target || hook,
                    matchedNamespaces: match.matchedNamespaces,
                    matchedPatterns: match.matchedPatterns,
                    stackTop: getStackHead(stack)
                });
            }
        }

        function hookAllOverloads(className, methodName, getTarget) {
            try {
                const K = Java.use(className);
                if (!K[methodName] || !K[methodName].overloads) {
                    reportDebug(`Hook skipped: ${className}.${methodName} not found`);
                    return;
                }

                reportDebug(`Hooking ${className}.${methodName} (${K[methodName].overloads.length} overloads)`);
                K[methodName].overloads.forEach((overload) => {
                    overload.implementation = function() {
                        const args = Array.prototype.slice.call(arguments);
                        try {
                            const target = getTarget ? getTarget.call(this, args) : '';
                            reportNetworkCall(`${className}.${methodName}`, target);
                        } catch (err) {
                            reportAgentError(`hook impl ${className}.${methodName}`, err);
                        }

                        return overload.call(this, ...args);
                    };
                });
            } catch (err) {
                const message = forceString(err && err.message ? err.message : err);
                if (message.includes('ClassNotFoundException')) {
                    reportDebug(`Hook skipped: ${className}.${methodName} class unavailable`);
                    return;
                }
                reportAgentError(`hook setup ${className}.${methodName}`, err);
            }
        }

        reportDebug('Startup class/native scan disabled for stability');
        reportDebug('Signature and namespace data loaded from signatures.json-compatible config');

        hookAllOverloads('java.net.URL', 'openConnection', function() {
            return safeToString(this);
        });
        hookAllOverloads('java.net.URLConnection', 'connect', function() {
            return safeToString(this.getURL ? this.getURL() : this);
        });
        hookAllOverloads('java.net.URLConnection', 'getInputStream', function() {
            return safeToString(this.getURL ? this.getURL() : this);
        });
        hookAllOverloads('java.net.URLConnection', 'getOutputStream', function() {
            return safeToString(this.getURL ? this.getURL() : this);
        });
        hookAllOverloads('javax.net.ssl.HttpsURLConnection', 'connect', function() {
            return safeToString(this.getURL ? this.getURL() : this);
        });
        reportDebug('Built-in java.net hooks installed');

        hookAllOverloads('okhttp3.RealCall', 'execute', function(args) {
            return getOkHttpRequestUrl(this, args);
        });
        hookAllOverloads('okhttp3.RealCall', 'enqueue', function(args) {
            return getOkHttpRequestUrl(this, args);
        });
        hookAllOverloads('okhttp3.OkHttpClient', 'newCall', function(args) {
            return getOkHttpRequestUrl(null, args);
        });
        hookAllOverloads('okhttp3.internal.http.CallServerInterceptor', 'intercept', function(args) {
            return getOkHttpRequestUrl(null, args);
        });
        reportDebug('okhttp3 hooks installed');

        send({
            type: 'DEBUG',
            message: 'Agent initialization complete',
            extra: {
                loadedSignatureCount: signatures.length
            }
        });
    });
}

recv('config', (message) => {
    configureSignatures(message.payload || {});
    startScan();
});
