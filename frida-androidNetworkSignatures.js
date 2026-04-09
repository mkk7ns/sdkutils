const frida = require('frida');
const fs = require('fs');
const path = require('path');

const DEFAULT_AGENT_PATH = path.join(__dirname, '_agentAndroidNetworkSignatures.js');
const DEFAULT_SIGNATURES_PATH = path.join(__dirname, 'signatures.json');
const DEFAULT_DEVICE_TIMEOUT = 5000;

function usage() {
    console.log(`Usage:
  node frida-androidNetworkSignatures.js <package> --spawn [options]
  node frida-androidNetworkSignatures.js <pid> --attach [options]

Options:
  --spawn                 Spawn the target package, attach, then resume it
  --attach                Attach to an already-running numeric PID
  --signatures <path>     Signature JSON file to load (default: ./signatures.json)
  --agent <path>          Compiled Frida agent bundle (default: ./_agentAndroidNetworkSignatures.js)
  --device-timeout <ms>   Timeout for locating the USB device (default: 5000)
  --no-color              Disable ANSI color output
  -h, --help              Show this help text`);
}

function fail(message) {
    console.error(`[!] ${message}`);
    process.exit(1);
}

function parseArgs(argv) {
    if (argv.length === 0 || argv.includes('-h') || argv.includes('--help')) {
        usage();
        process.exit(0);
    }

    const target = argv[0];
    let mode = null;
    let signaturesPath = DEFAULT_SIGNATURES_PATH;
    let agentPath = DEFAULT_AGENT_PATH;
    let deviceTimeout = DEFAULT_DEVICE_TIMEOUT;
    let color = true;

    for (let i = 1; i < argv.length; i += 1) {
        const arg = argv[i];

        if (arg === '--spawn' || arg === '--attach') {
            if (mode) {
                fail('Specify only one of --spawn or --attach.');
            }
            mode = arg;
            continue;
        }

        if (arg === '--signatures') {
            i += 1;
            signaturesPath = argv[i];
            if (!signaturesPath) {
                fail('Missing value for --signatures.');
            }
            continue;
        }

        if (arg === '--agent') {
            i += 1;
            agentPath = argv[i];
            if (!agentPath) {
                fail('Missing value for --agent.');
            }
            continue;
        }

        if (arg === '--device-timeout') {
            i += 1;
            deviceTimeout = Number(argv[i]);
            if (!Number.isFinite(deviceTimeout) || deviceTimeout <= 0) {
                fail('--device-timeout must be a positive integer.');
            }
            continue;
        }

        if (arg === '--no-color') {
            color = false;
            continue;
        }

        fail(`Unknown argument: ${arg}`);
    }

    if (!target) {
        fail('Missing target package or PID.');
    }

    if (!mode) {
        fail('Specify either --spawn or --attach.');
    }

    if (mode === '--attach' && !/^\d+$/.test(target)) {
        fail('For --attach, pass a numeric PID.');
    }

    return {
        target,
        mode,
        signaturesPath: path.resolve(signaturesPath),
        agentPath: path.resolve(agentPath),
        deviceTimeout,
        color
    };
}

function loadSignatureMap(signaturePath) {
    const raw = JSON.parse(fs.readFileSync(signaturePath, 'utf8'));
    const signatures = raw.signatures || {};

    return Object.entries(signatures)
        .map(([name, value]) => ({
            name,
            patterns: Array.isArray(value.patterns) ? value.patterns : []
        }))
        .filter((item) => item.patterns.length > 0);
}

function colorize(text, ansiCode, enabled) {
    if (!enabled) {
        return text;
    }
    return `\x1b[${ansiCode}m${text}\x1b[0m`;
}

async function run() {
    const options = parseArgs(process.argv.slice(2));

    if (!fs.existsSync(options.agentPath)) {
        fail(`Agent bundle not found at ${options.agentPath}. Run: npm install && npm run build:networkHookAndAlert`);
    }

    if (!fs.existsSync(options.signaturesPath)) {
        fail(`Signature file not found at ${options.signaturesPath}.`);
    }

    const signatureMap = loadSignatureMap(options.signaturesPath);
    if (signatureMap.length === 0) {
        fail(`No usable signatures found in ${options.signaturesPath}.`);
    }

    const device = await frida.getUsbDevice({ timeout: options.deviceTimeout });
    let appPackage = "";
    let session;
    let spawnedPid = null;

    if (options.mode === '--spawn') {
        spawnedPid = await device.spawn([options.target]);
        session = await device.attach(spawnedPid);
        appPackage = options.target;
    } else {
        const pid = Number(options.target);
        session = await device.attach(pid);
        const processes = await device.enumerateProcesses();
        const proc = processes.find((processInfo) => processInfo.pid === pid);
        appPackage = proc ? proc.name : "";
    }

    const source = fs.readFileSync(options.agentPath, 'utf8');
    const script = await session.createScript(source);

    session.detached.connect((reason, crash) => {
        console.error(colorize(`[SESSION DETACHED] reason=${reason}`, '31', options.color));
        if (crash) {
            console.error(`    crash: ${JSON.stringify(crash)}`);
        }
    });

    script.message.connect((message) => {
        if (message.type === 'error') {
            console.error(colorize(`[SCRIPT ERROR] ${message.description || 'Unknown error'}`, '31', options.color));
            if (message.stack) {
                console.error(message.stack);
            }
            return;
        }

        if (message.type !== 'send' || !message.payload) {
            return;
        }

        const payload = message.payload;

        if (payload.type === 'DEBUG') {
            console.log(colorize(`[DEBUG] ${payload.message}`, '90', options.color));
            if (payload.extra) {
                console.log(`    ${JSON.stringify(payload.extra)}`);
            }
            return;
        }

        if (payload.type === 'AGENT_ERROR') {
            console.error(colorize(`[AGENT ERROR] ${payload.where}: ${payload.error}`, '31', options.color));
            if (payload.stack) {
                console.error(payload.stack);
            }
            return;
        }

        if (payload.type === 'NETWORK_STACK_MATCH') {
            console.log(colorize(`[NETWORK STACK MATCH] ${payload.sdkName}`, '36', options.color));
            console.log(`    Hook: ${payload.hook}`);
            console.log(`    Target: ${payload.evidence}`);
            if ((payload.matchedNamespaces || []).length > 0) {
                console.log(`    Namespace Match: ${payload.matchedNamespaces.join(', ')}`);
            }
            if ((payload.matchedPatterns || []).length > 0) {
                console.log(`    Pattern Match: ${payload.matchedPatterns.join(', ')}`);
            }
            if (payload.stackTop) {
                console.log(`    Stack:\n${payload.stackTop}`);
            }
            return;
        }

        if (payload.type === 'SIGNATURE_MATCH') {
            console.log(colorize(`[SIGNATURE MATCH] ${payload.sdkName}`, '33', options.color));
            console.log(`    Evidence: ${payload.evidence} (${payload.evidenceType})`);
        }
    });

    await script.load();
    script.post({
        type: 'config',
        payload: {
            appPackage,
            signatures: signatureMap
        }
    });

    if (spawnedPid !== null) {
        await device.resume(spawnedPid);
    }

    console.log(`[!] Monitoring ${appPackage || options.target} with ${signatureMap.length} signatures from ${options.signaturesPath}`);
}

run().catch((error) => {
    console.error(error && error.stack ? error.stack : error);
    process.exit(1);
});
