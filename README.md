# SDK Utils

Utility scripts for SDK and mobile app analysis.

## Table of Contents

- [SDK Finder](#sdk-finder)

Written by Michael Krueger, mkrueger@nowsecure.com.

Released under the MIT License.

## SDK Finder

`sdk_finder.py` is a heuristic scanner for finding likely third-party SDKs and components inside iOS and Android app artifacts.

It currently supports:

- Android APKs (`.apk`)
- iOS IPAs (`.ipa`)
- unpacked iOS app bundles (`.app`)

The scanner is designed to help with audit triage rather than produce a definitive software bill of materials. It combines filename, framework/library, package namespace, asset marker, manifest/config, string, and optional JADX-derived evidence into a ranked report.

## Usage

```bash
python3 sdk_finder.py <target> --signatures signatures.json
```

Example:

```bash
python3 sdk_finder.py MyApp.apk --signatures signatures.json
```

## Command-Line Flags

### Required

- `target`
  - Path to the target app artifact.
  - Supported inputs: `.apk`, `.ipa`, `.app`

- `--signatures SIGNATURES`
  - Path to the signature file.
  - The file must be a JSON object with a top-level `signatures` key.

### Optional

- `--json`
  - Emit machine-readable JSON to stdout instead of the human-readable text report.

- `--csv-out <path>`
  - Write the ranked summary to a CSV file.

- `--top <n>`
  - Control how many top findings appear in the text report.
  - Default: `5`
  - This does not affect JSON or CSV output.

- `--use-jadx`
  - For Android APKs, run JADX if it is installed and then scan the decompiled output for additional evidence.
  - If JADX is not installed or fails, the script continues and prints a warning to stderr.

- `--quiet`
  - Suppress phase/status updates on stderr.
  - Useful if you want completely quiet terminal behavior except for final output and warnings.

- `--no-simple-search`
  - Skip the broad fallback scan that checks:
    - general filenames
    - likely text files
    - `strings` output from relevant files
  - Structured scans still run, including:
    - iOS framework and xcframework names
    - Android DEX package namespaces
    - Android `lib/` artifact names
    - Android `assets/` and `META-INF` markers
    - optional JADX output when `--use-jadx` is enabled

## Signature Format

`signatures.json` is expected to look like this:

```json
{
  "signatures": {
    "SDK Name": {
      "category": "analytics",
      "patterns": [
        "com\\.vendor\\.sdk",
        "\\bVendorSDK\\b",
        "vendor\\.com"
      ]
    }
  }
}
```

Each signature contains:

- SDK display name
- `category`
- `patterns`: regular expressions tested case-insensitively

In practice, patterns work best when they prefer:

- package namespaces
- class names
- framework/library names
- config filenames
- vendor-specific hostnames

Patterns that are only generic English words tend to create false positives.

## Evidence and Scoring

Each match is assigned an evidence type and weight. Stronger evidence contributes more confidence.

Current evidence classes include:

- `ios_framework_name`
- `ios_bundle_identifier`
- `android_package_namespace`
- `android_library_name`
- `android_asset_marker`
- `namespace_mismatch`
- `android_filename`
- `config_file`
- `hostname`
- `symbol_or_class`
- `jadx_source`
- `generic_string`

The final report combines:

- total hits
- weighted confidence
- evidence diversity
- category-specific risk profile

This produces:

- confidence label
- risk total
- priority label
- suggested next test areas

Unknown namespace candidates are added as findings with:

- category `unknown`
- medium-risk review priority by default
- evidence showing the mismatched namespace and the inferred app namespace

## Examples

Basic text report:

```bash
python3 sdk_finder.py MyApp.apk --signatures signatures.json
```

JSON output:

```bash
python3 sdk_finder.py MyApp.apk --signatures signatures.json --json
```

JSON output without status lines:

```bash
python3 sdk_finder.py MyApp.apk --signatures signatures.json --json --quiet
```

Structured-only scan without broad text matching:

```bash
python3 sdk_finder.py MyApp.apk --signatures signatures.json --no-simple-search
```

Write CSV:

```bash
python3 sdk_finder.py MyApp.apk --signatures signatures.json --csv-out findings.csv
```

Use JADX for deeper Android scanning:

```bash
python3 sdk_finder.py MyApp.apk --signatures signatures.json --use-jadx
```

Limit the text report to the top 10 entries:

```bash
python3 sdk_finder.py MyApp.apk --signatures signatures.json --top 10
```

Scan an unpacked iOS app bundle:

```bash
python3 sdk_finder.py Payload/MyApp.app --signatures signatures.json
```

## Notes and Limitations

- This is a heuristic scanner, not a complete dependency resolver.
- Stripped or renamed binaries can reduce detection quality.
- Some Android native libraries have generic names and may not identify the vendor clearly.
- Optional JADX scanning improves recall but depends on JADX being installed and working.
- Signature quality matters more than regex quantity. Tight, vendor-specific markers outperform broad word matches.
