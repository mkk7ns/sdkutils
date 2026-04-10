"""
Filename: sdk_finder.py
Author: Michael Krueger (mkrueger@nowsecure.com)
Date: 2026-02-17
Version: 1.0
Description: 
    This script performs basic mobile app SDK discovery and triage scoring based on static analysis 
    of iOS and Android app bundles. It uses a signature-based approach to identify likely SDKs/components 
    and assigns risk and testing priority based on the type and amount of evidence found. The script is 
    designed to be a starting point for security analysts to quickly identify high-risk third-party SDKs 
    in mobile applications. For more help, see the README or run with --help. Need more advanced analysis?
    Visit https://www.nowsecure.com/.
"""
import argparse
import collections
import concurrent.futures
import csv
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Optional


TEXT_FILE_EXTS = {
    ".xml", ".json", ".txt", ".plist", ".html", ".js", ".kt", ".java",
    ".swift", ".m", ".mm", ".yaml", ".yml", ".properties", ".cfg", ".md"
}

HIGH_SIGNAL_FILENAMES = {
    "google-services.json",
    "GoogleService-Info.plist",
    "AndroidManifest.xml",
    "Info.plist",
    "classes.dex",
}

CATEGORY_PROFILES = {
    "ads": {
        "data_access": 4, "egress": 5, "triggerability": 5, "business_impact": 4,
        "test_next": "cold start, consent flow, ad display, install/open flow",
    },
    "analytics": {
        "data_access": 4, "egress": 5, "triggerability": 5, "business_impact": 4,
        "test_next": "cold start, screen views, signup, button taps",
    },
    "analytics_ads": {
        "data_access": 4, "egress": 5, "triggerability": 5, "business_impact": 4,
        "test_next": "cold start, login, attribution path, consent flow",
    },
    "attribution": {
        "data_access": 4, "egress": 5, "triggerability": 5, "business_impact": 4,
        "test_next": "first launch, reinstall, deep link open, consent flow",
    },
    "session_replay": {
        "data_access": 5, "egress": 5, "triggerability": 4, "business_impact": 5,
        "test_next": "login, checkout, profile screens, text entry, consent flow",
    },
    "feature_flags": {
        "data_access": 2, "egress": 4, "triggerability": 4, "business_impact": 4,
        "test_next": "cold start, login, kill-switch behavior, pre-consent init",
    },
    "crash_reporting": {
        "data_access": 3, "egress": 3, "triggerability": 2, "business_impact": 3,
        "test_next": "forced crash, exception path, breadcrumb-heavy user flows",
    },
    "observability": {
        "data_access": 3, "egress": 4, "triggerability": 3, "business_impact": 3,
        "test_next": "startup, network actions, errors, performance-heavy flows",
    },
    "payments": {
        "data_access": 5, "egress": 4, "triggerability": 3, "business_impact": 5,
        "test_next": "checkout, add card, payment auth, error paths",
    },
    "messaging": {
        "data_access": 3, "egress": 4, "triggerability": 4, "business_impact": 3,
        "test_next": "push registration, identify user, inbox open, notification tap",
    },
    "support_chat": {
        "data_access": 4, "egress": 5, "triggerability": 4, "business_impact": 4,
        "test_next": "open chat, submit message, attach screenshot, login",
    },
    "ai_remote": {
        "data_access": 5, "egress": 5, "triggerability": 4, "business_impact": 5,
        "test_next": "submit prompt, attach file/image, microphone input, tool use, fallback path",
    },
    "ai_local": {
        "data_access": 4, "egress": 1, "triggerability": 4, "business_impact": 4,
        "test_next": "camera/image scan, OCR, speech, local inference path",
    },
    "ai_orchestration": {
        "data_access": 5, "egress": 4, "triggerability": 4, "business_impact": 5,
        "test_next": "prompt submit, retrieval/tool invocation, fallback behavior",
    },
    "unknown": {
        "data_access": 4, "egress": 3, "triggerability": 3, "business_impact": 3,
        "test_next": "review namespace owner, initialization path, network calls, consent timing",
    },
}

EVIDENCE_WEIGHTS = {
    "ios_framework_name": 5,
    "ios_bundle_identifier": 4,
    "android_package_namespace": 5,
    "android_library_name": 5,
    "android_asset_marker": 4,
    "namespace_mismatch": 4,
    "android_filename": 5,
    "config_file": 4,
    "hostname": 3,
    "symbol_or_class": 3,
    "jadx_source": 4,
    "generic_string": 1,
}

HOSTNAME_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
PACKAGE_NAMESPACE_RE = re.compile(
    r"\b(?:com|io|org|net|ai)\.(?:[a-z0-9_]+\.){1,6}[a-z0-9_]+\b",
    re.IGNORECASE,
)
ANDROID_MANIFEST_PACKAGE_RE = re.compile(r'\bpackage\s*=\s*"([A-Za-z0-9_.]+)"')


def print_status(message: str, enabled: bool = True) -> None:
    if enabled:
        print(f"[sdk_finder] {message}", file=sys.stderr, flush=True)


def print_progress(prefix: str, current: int, total: int, enabled: bool = True) -> None:
    if not enabled or total <= 0:
        return
    width = 30
    filled = min(width, int((current / total) * width))
    bar = "#" * filled + "-" * (width - filled)
    print(
        f"\r[sdk_finder] {prefix} [{bar}] {current}/{total}",
        file=sys.stderr,
        end="",
        flush=True,
    )
    if current >= total:
        print(file=sys.stderr, flush=True)


def should_emit_progress_update(
    current: int,
    total: int,
    last_percent_bucket: int,
    file_step: int = 25,
    percent_step: int = 5,
) -> tuple[bool, int]:
    if total <= 0:
        return False, last_percent_bucket

    percent_bucket = min(100, (current * 100) // total)
    reached_percent_step = percent_bucket >= last_percent_bucket + percent_step
    reached_file_step = current % file_step == 0
    is_boundary = current == 1 or current == total

    if is_boundary or reached_percent_step or reached_file_step:
        return True, percent_bucket
    return False, last_percent_bucket


def run_strings(path: Path) -> str:
    try:
        result = subprocess.run(
            ["strings", "-a", str(path)],
            capture_output=True,
            text=True,
            errors="ignore",
            check=False,
        )
        return result.stdout
    except FileNotFoundError:
        return ""


def safe_read_text(path: Path, max_bytes: int = 2_000_000) -> str:
    try:
        if path.stat().st_size > max_bytes:
            return ""
        return path.read_text(errors="ignore")
    except Exception:
        return ""


def safe_read_plist(path: Path, max_bytes: int = 2_000_000):
    try:
        if path.stat().st_size > max_bytes:
            return None
        with path.open("rb") as f:
            return plistlib.load(f)
    except Exception:
        return None


def unzip_to_temp(src: Path, temp_dir: Path) -> None:
    with zipfile.ZipFile(src, "r") as zf:
        zf.extractall(temp_dir)


def collect_files(root: Path):
    for p in root.rglob("*"):
        if p.is_file():
            yield p


def is_probably_text(path: Path) -> bool:
    return path.suffix.lower() in TEXT_FILE_EXTS or path.name in HIGH_SIGNAL_FILENAMES


def should_run_strings(path: Path) -> bool:
    name = path.name
    suffix = path.suffix.lower()
    if name in HIGH_SIGNAL_FILENAMES:
        return True
    if suffix in {".so", ".dylib", ".a", ".dex", ".bin", ".o"}:
        return True
    if ".framework" in str(path):
        return True
    try:
        size = path.stat().st_size
    except OSError:
        return False
    return 200 <= size <= 100_000_000


def detect_type(path: Path) -> str:
    name = path.name.lower()
    if path.is_dir() and name.endswith(".app"):
        return "ios"
    if name.endswith(".ipa"):
        return "ios"
    if name.endswith(".apk"):
        return "android"
    return "unknown"


def load_signatures(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "signatures" not in data:
        raise ValueError("Signature file must be a JSON object with a top-level 'signatures' key")
    return data["signatures"]


def compile_signatures(signatures: dict) -> list[dict]:
    compiled = []
    for sdk_name, meta in signatures.items():
        category = meta.get("category", "unknown")
        patterns = []
        for pat in meta.get("patterns", []):
            try:
                patterns.append(re.compile(pat, re.IGNORECASE))
            except re.error:
                continue
        if patterns:
            compiled.append({
                "sdk_name": sdk_name,
                "category": category,
                "patterns": patterns,
            })
    return compiled


def classify_evidence(source: str, snippet: str) -> str:
    s = source.lower()
    snip = snippet.lower()

    if source.startswith("framework-name:"):
        return "ios_framework_name"
    if source.startswith("ios-bundle-id:"):
        return "ios_bundle_identifier"
    if source.startswith("android-package:"):
        return "android_package_namespace"
    if source.startswith("android-lib:"):
        return "android_library_name"
    if source.startswith("namespace-mismatch:"):
        return "namespace_mismatch"
    if source.startswith("android-asset:") or source.startswith("android-meta-inf:"):
        return "android_asset_marker"
    if source.startswith("filename:"):
        return "android_filename"
    if source.startswith("jadx:"):
        return "jadx_source"
    if s.endswith("google-services.json") or s.endswith("googleservice-info.plist") or s.endswith("info.plist") or s.endswith("androidmanifest.xml"):
        return "config_file"
    if HOSTNAME_RE.search(snip):
        return "hostname"
    if "objc_class" in snip or "com." in snip or "sdk" in snip or "lib" in snip:
        return "symbol_or_class"
    return "generic_string"


def add_evidence(results, sdk_name: str, category: str, source: str, snippet: str) -> None:
    evidence_type = classify_evidence(source, snippet)
    score = EVIDENCE_WEIGHTS.get(evidence_type, 1)

    item = results[sdk_name]
    item["sdk"] = sdk_name
    item["category"] = category
    item["hits"] += 1
    item["confidence_points"] += score
    item["evidence_types"].add(evidence_type)

    key = f"{source}:{snippet[:120]}"
    if key not in item["seen"] and len(item["evidence"]) < 20:
        item["seen"].add(key)
        item["evidence"].append({
            "source": source,
            "match": snippet[:240],
            "evidence_type": evidence_type,
            "score": score,
        })


def set_unknown_group_count(results, sdk_name: str, count: int) -> None:
    item = results[sdk_name]
    item["unknown_group_count"] = max(item.get("unknown_group_count", 0), count)


def scan_content_matches(text: str, source: str, compiled_signatures: list[dict]) -> list[tuple[str, str, str, str]]:
    lowered = text.lower()
    matches = []
    for item in compiled_signatures:
        for pattern in item["patterns"]:
            m = pattern.search(lowered)
            if m:
                start = max(0, m.start() - 50)
                end = min(len(text), m.end() + 140)
                snippet = text[start:end].replace("\n", " ")
                matches.append((item["sdk_name"], item["category"], source, snippet))
                break
    return matches


def scan_content(text: str, source: str, compiled_signatures: list[dict], results) -> None:
    for sdk_name, category, source_name, snippet in scan_content_matches(text, source, compiled_signatures):
        add_evidence(results, sdk_name, category, source_name, snippet)


def extract_package_namespaces(text: str, max_hits: Optional[int] = None) -> list[str]:
    found = []
    seen = set()
    for match in PACKAGE_NAMESPACE_RE.finditer(text):
        namespace = match.group(0)
        if namespace in seen:
            continue
        seen.add(namespace)
        found.append(namespace)
        if max_hits is not None and len(found) >= max_hits:
            break
    return found


def get_namespace_prefix(namespace: str, segments: int = 2) -> str:
    parts = [part for part in namespace.split(".") if part]
    return ".".join(parts[:segments])


def collapse_unknown_namespace(namespace: str, max_segments: int = 4) -> str:
    parts = [part for part in namespace.split(".") if part]
    if not parts:
        return namespace

    package_parts = []
    for part in parts:
        if any(ch.isupper() for ch in part):
            break
        package_parts.append(part)

    if not package_parts:
        package_parts = parts[:max_segments]

    collapsed = package_parts[:max_segments]
    if len(collapsed) >= 3:
        return ".".join(collapsed)
    return ".".join(package_parts or parts[:max_segments])


def get_unknown_vendor_root(namespace: str) -> str:
    parts = [part for part in namespace.split(".") if part]
    if len(parts) >= 2:
        return ".".join(parts[:2])
    return namespace


def namespace_matches_app(candidate: str, app_namespace: Optional[str]) -> bool:
    if not app_namespace:
        return False
    if candidate == app_namespace:
        return True
    if candidate.startswith(app_namespace + ".") or app_namespace.startswith(candidate + "."):
        return True
    candidate_prefix = get_namespace_prefix(candidate, segments=2)
    app_prefix = get_namespace_prefix(app_namespace, segments=2)
    return bool(candidate_prefix and candidate_prefix == app_prefix)


def namespace_matches_known_signature(namespace: str, signatures: dict) -> bool:
    lowered = namespace.lower()
    for meta in signatures.values():
        for pat in meta.get("patterns", []):
            if re.search(pat, lowered, re.IGNORECASE):
                return True
    return False


def infer_android_app_namespace(root: Path, package_hits: list[tuple[str, str]]) -> Optional[str]:
    manifest = root / "AndroidManifest.xml"
    manifest_sources = []
    if manifest.exists():
        manifest_text = safe_read_text(manifest)
        if manifest_text:
            manifest_sources.append(manifest_text)
        manifest_strings = run_strings(manifest)
        if manifest_strings:
            manifest_sources.append(manifest_strings)

    for source in manifest_sources:
        match = ANDROID_MANIFEST_PACKAGE_RE.search(source)
        if match:
            return match.group(1)

    prefix_counts = collections.Counter()
    full_counts = collections.Counter()
    for _, namespace in package_hits:
        full_counts[namespace] += 1
        prefix = get_namespace_prefix(namespace, segments=3) or namespace
        prefix_counts[prefix] += 1

    if prefix_counts:
        return prefix_counts.most_common(1)[0][0]
    if full_counts:
        return full_counts.most_common(1)[0][0]
    return None


def infer_ios_app_namespace(root: Path) -> Optional[str]:
    info_plist = root / "Info.plist"
    plist_data = safe_read_plist(info_plist)
    if isinstance(plist_data, dict):
        bundle_id = plist_data.get("CFBundleIdentifier")
        if isinstance(bundle_id, str) and bundle_id:
            return bundle_id

    info_text = safe_read_text(info_plist)
    if info_text:
        namespaces = extract_package_namespaces(info_text, max_hits=10)
        if namespaces:
            return namespaces[0]

    info_strings = run_strings(info_plist)
    if info_strings:
        namespaces = extract_package_namespaces(info_strings, max_hits=10)
        if namespaces:
            return namespaces[0]
    return None


def collect_ios_framework_bundle_ids(root: Path) -> list[tuple[str, str]]:
    hits = []
    seen = set()
    for framework_dir in root.rglob("*.framework"):
        if not framework_dir.is_dir():
            continue
        info_plist = framework_dir / "Info.plist"
        plist_data = safe_read_plist(info_plist)
        bundle_id = plist_data.get("CFBundleIdentifier") if isinstance(plist_data, dict) else None
        if isinstance(bundle_id, str) and bundle_id and bundle_id not in seen:
            rel = str(framework_dir.relative_to(root))
            seen.add(bundle_id)
            hits.append((f"ios-bundle-id:{rel}", bundle_id))
    return hits


def add_unknown_namespace_candidates(
    results,
    app_namespace: Optional[str],
    candidates: list[tuple[str, str]],
    signatures: dict,
) -> None:
    grouped = collections.defaultdict(list)
    for source, namespace in candidates:
        collapsed_namespace = collapse_unknown_namespace(namespace)
        if not app_namespace:
            continue
        if namespace_matches_app(collapsed_namespace, app_namespace):
            continue
        if namespace_matches_known_signature(collapsed_namespace, signatures):
            continue
        vendor_root = get_unknown_vendor_root(collapsed_namespace)
        grouped[vendor_root].append((source, namespace, collapsed_namespace))

    for vendor_root, entries in grouped.items():
        unique_grouped_namespaces = []
        seen_grouped = set()
        for _, _, collapsed_namespace in entries:
            if collapsed_namespace in seen_grouped:
                continue
            seen_grouped.add(collapsed_namespace)
            unique_grouped_namespaces.append(collapsed_namespace)

        total = len(unique_grouped_namespaces)
        sdk_name = f"Unknown: {vendor_root}"
        set_unknown_group_count(results, sdk_name, total)
        emitted = set()
        evidence_count = 0
        for source, namespace, collapsed_namespace in entries:
            if collapsed_namespace in emitted:
                continue
            emitted.add(collapsed_namespace)
            if evidence_count >= 20:
                break
            evidence_count += 1
            add_evidence(
                results,
                sdk_name,
                "unknown",
                f"namespace-mismatch:{source}",
                (
                    f"{namespace} (grouped under {vendor_root}; "
                    f"{total} distinct namespace groups; app namespace: {app_namespace})"
                ),
            )


def scan_ios_framework_names(root: Path, compiled_signatures: list[dict], results) -> None:
    seen = set()
    for framework_dir in root.rglob("*.framework"):
        if framework_dir.is_dir():
            rel = str(framework_dir.relative_to(root))
            if rel not in seen:
                seen.add(rel)
                scan_content(framework_dir.name, f"framework-name:{rel}", compiled_signatures, results)

    for framework_dir in root.rglob("*.xcframework"):
        if framework_dir.is_dir():
            rel = str(framework_dir.relative_to(root))
            if rel not in seen:
                seen.add(rel)
                scan_content(framework_dir.name, f"framework-name:{rel}", compiled_signatures, results)


def scan_android_library_names(root: Path, compiled_signatures: list[dict], results) -> None:
    lib_root = root / "lib"
    if not lib_root.exists():
        return

    for p in lib_root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() not in {".so", ".jar", ".aar"}:
            continue
        rel = str(p.relative_to(root))
        scan_content(p.name, f"android-lib:{rel}", compiled_signatures, results)


def scan_android_package_namespaces(root: Path, compiled_signatures: list[dict], results) -> list[tuple[str, str]]:
    hits = []
    for p in root.glob("classes*.dex"):
        if not p.is_file():
            continue

        rel = str(p.relative_to(root))
        dex_strings = run_strings(p)
        if not dex_strings:
            continue

        namespaces = []
        seen = set()
        for match in PACKAGE_NAMESPACE_RE.finditer(dex_strings):
            namespace = match.group(0)
            if namespace in seen:
                continue
            seen.add(namespace)
            namespaces.append(namespace)
            hits.append((f"android-package:{rel}", namespace))
            if len(namespaces) >= 500:
                break

        if namespaces:
            scan_content("\n".join(namespaces), f"android-package:{rel}", compiled_signatures, results)
    return hits


def scan_android_asset_markers(root: Path, compiled_signatures: list[dict], results) -> None:
    for prefix, base in (("android-asset", root / "assets"), ("android-meta-inf", root / "META-INF")):
        if not base.exists():
            continue

        for p in base.rglob("*"):
            rel = str(p.relative_to(root))
            scan_content(p.name, f"{prefix}:{rel}", compiled_signatures, results)

            if p.is_file() and is_probably_text(p):
                txt = safe_read_text(p, max_bytes=500_000)
                if txt:
                    scan_content(txt, f"{prefix}:{rel}", compiled_signatures, results)


def score_confidence(confidence_points: int, evidence_types: set[str]) -> tuple[int, str]:
    diversity_bonus = max(0, len(evidence_types) - 1)
    raw = min(5, max(1, (confidence_points // 4) + diversity_bonus))
    label = {
        1: "weak",
        2: "low",
        3: "medium",
        4: "high",
        5: "very_high",
    }[raw]
    return raw, label


def score_risk(category: str, confidence_score: int) -> dict:
    profile = CATEGORY_PROFILES.get(
        category,
        {"data_access": 3, "egress": 3, "triggerability": 3, "business_impact": 3, "test_next": "startup and primary user flows"},
    )
    risk_total = (
        profile["data_access"]
        + profile["egress"]
        + profile["triggerability"]
        + profile["business_impact"]
        + confidence_score
    )
    return {
        "data_access": profile["data_access"],
        "egress": profile["egress"],
        "triggerability": profile["triggerability"],
        "business_impact": profile["business_impact"],
        "test_next": profile["test_next"],
        "risk_total": risk_total,
    }


def priority_label(risk_total: int) -> str:
    if risk_total >= 22:
        return "test_first"
    if risk_total >= 18:
        return "test_soon"
    if risk_total >= 14:
        return "review"
    return "low"


def summarize_output(output: str, max_lines: int = 5, max_chars: int = 600) -> str:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if not lines:
        return ""

    summary = "\n".join(lines[:max_lines])
    if len(summary) > max_chars:
        summary = summary[: max_chars - 3].rstrip() + "..."
    return summary


def run_jadx(apk_path: Path, out_dir: Path) -> tuple[bool, bool, str]:
    if shutil.which("jadx") is None:
        return False, False, "jadx executable was not found in PATH"
    result = subprocess.run(
        ["jadx", "-q", "-d", str(out_dir), str(apk_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    has_output = out_dir.exists() and any(out_dir.rglob("*"))
    if result.returncode == 0:
        return True, has_output, ""

    stderr_summary = summarize_output(result.stderr) or summarize_output(result.stdout)
    prefix = f"jadx exited with code {result.returncode}"

    if has_output:
        if stderr_summary:
            return True, True, f"{prefix} but produced partial output:\n{stderr_summary}"
        return True, True, f"{prefix} but produced partial output"

    if stderr_summary:
        return False, False, f"{prefix} and produced no usable output:\n{stderr_summary}"
    return False, False, f"{prefix} and produced no usable output or diagnostics"


def scan_jadx_output(jadx_dir: Path, compiled_signatures: list[dict], results, progress_enabled: bool = True) -> None:
    if not jadx_dir.exists():
        return

    candidates = []
    for p in jadx_dir.rglob("*"):
        if p.is_file() and p.suffix.lower() in {".java", ".xml", ".json", ".txt", ".kt"}:
            candidates.append(p)

    if not candidates:
        return

    def scan_one_file(p: Path) -> list[tuple[str, str, str, str]]:
        rel = str(p.relative_to(jadx_dir))
        txt = safe_read_text(p, max_bytes=5_000_000)
        if not txt:
            return []
        return scan_content_matches(txt, f"jadx:{rel}", compiled_signatures)

    max_workers = min(32, max(4, (os.cpu_count() or 4) * 2))
    total = len(candidates)
    if progress_enabled:
        print_status(f"JADX scan: {total} files, {max_workers} workers", enabled=True)

    completed = 0
    last_percent_bucket = 0
    started = time.monotonic()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_path = {executor.submit(scan_one_file, candidate): candidate for candidate in candidates}
        for future in concurrent.futures.as_completed(future_to_path):
            matches = future.result()
            for sdk_name, category, source_name, snippet in matches:
                add_evidence(results, sdk_name, category, source_name, snippet)

            completed += 1
            should_emit, last_percent_bucket = should_emit_progress_update(
                completed,
                total,
                last_percent_bucket,
            )
            if should_emit:
                print_progress("scanning JADX output", completed, total, enabled=progress_enabled)

    if progress_enabled:
        elapsed = time.monotonic() - started
        print_status(f"JADX scan complete in {elapsed:.1f}s", enabled=True)


def scan_ios(root: Path, signatures: dict, compiled_signatures: list[dict], results, progress=None, include_simple_search: bool = True) -> Optional[str]:
    app_namespace = infer_ios_app_namespace(root)
    if progress and app_namespace:
        progress(f"iOS: app namespace {app_namespace}")

    if progress:
        progress("iOS: scanning framework names")
    scan_ios_framework_names(root, compiled_signatures, results)

    if progress:
        progress("iOS: collecting framework bundle identifiers")
    add_unknown_namespace_candidates(
        results,
        app_namespace,
        collect_ios_framework_bundle_ids(root),
        signatures,
    )

    if not include_simple_search:
        if progress:
            progress("iOS: skipping filename/text/strings fallback search")
        return app_namespace

    if progress:
        progress("iOS: scanning files and extracted strings")
    for p in collect_files(root):
        rel = str(p.relative_to(root))

        if is_probably_text(p):
            txt = safe_read_text(p)
            if txt:
                scan_content(txt, rel, compiled_signatures, results)

        if should_run_strings(p):
            s = run_strings(p)
            if s:
                scan_content(s, rel, compiled_signatures, results)
    return app_namespace


def scan_android(root: Path, signatures: dict, compiled_signatures: list[dict], results, progress=None, include_simple_search: bool = True) -> Optional[str]:
    if progress:
        progress("Android: scanning DEX package namespaces")
    package_hits = scan_android_package_namespaces(root, compiled_signatures, results)
    app_namespace = infer_android_app_namespace(root, package_hits)
    if progress and app_namespace:
        progress(f"Android: app namespace {app_namespace}")
    add_unknown_namespace_candidates(results, app_namespace, package_hits, signatures)

    if progress:
        progress("Android: scanning lib/ artifact names")
    scan_android_library_names(root, compiled_signatures, results)

    if progress:
        progress("Android: scanning assets/ and META-INF markers")
    scan_android_asset_markers(root, compiled_signatures, results)

    if not include_simple_search:
        if progress:
            progress("Android: skipping filename/text/strings fallback search")
        return app_namespace

    if progress:
        progress("Android: scanning filenames, text files, and extracted strings")
    for p in collect_files(root):
        rel = str(p.relative_to(root))
        scan_content(p.name, f"filename:{rel}", compiled_signatures, results)

        if is_probably_text(p):
            txt = safe_read_text(p)
            if txt:
                scan_content(txt, rel, compiled_signatures, results)

        if should_run_strings(p):
            s = run_strings(p)
            if s:
                scan_content(s, rel, compiled_signatures, results)
    return app_namespace


def build_summary(results) -> list[dict]:
    rows = []
    for sdk_name, item in results.items():
        confidence_score, confidence_label = score_confidence(
            item["confidence_points"], item["evidence_types"]
        )
        risk = score_risk(item["category"], confidence_score)

        row = {
            "sdk": sdk_name,
            "category": item["category"],
            "hits": item["hits"],
            "confidence_score": confidence_score,
            "confidence_label": confidence_label,
            "unknown_group_count": item.get("unknown_group_count", 0),
            "data_access": risk["data_access"],
            "egress": risk["egress"],
            "triggerability": risk["triggerability"],
            "business_impact": risk["business_impact"],
            "risk_total": risk["risk_total"],
            "priority": priority_label(risk["risk_total"]),
            "test_next": risk["test_next"],
            "evidence": item["evidence"],
        }
        rows.append(row)

    rows.sort(
        key=lambda r: (
            {"test_first": 0, "test_soon": 1, "review": 2, "low": 3}[r["priority"]],
            -r["risk_total"],
            -r["confidence_score"],
            -r["hits"],
            r["sdk"].lower(),
        )
    )
    return rows


def print_report(target: Path, platform: str, rows: list[dict], top_n: int) -> None:
    print(f"\nTarget:   {target}")
    print(f"Platform: {platform}\n")

    if not rows:
        print("No likely SDKs/components matched.")
        return

    print("Top candidates to test first:\n")
    for idx, row in enumerate(rows[:top_n], start=1):
        print(
            f"{idx}. {row['sdk']} "
            f"[category={row['category']}, priority={row['priority']}, "
            f"risk={row['risk_total']}, confidence={row['confidence_label']}, hits={row['hits']}]"
        )
        if row["unknown_group_count"]:
            print(f"   grouped namespaces: {row['unknown_group_count']}")
        print(f"   test next: {row['test_next']}")
        for ev in row["evidence"][:3]:
            print(f"   evidence: {ev['source']} ({ev['evidence_type']}, +{ev['score']})")
            print(f"             {ev['match']}")
        print()

    print("Full ranked list:\n")
    for row in rows:
        print(
            f"- {row['sdk']}: category={row['category']}, priority={row['priority']}, "
            f"risk={row['risk_total']}, confidence={row['confidence_label']}, hits={row['hits']}"
            + (
                f", grouped_namespaces={row['unknown_group_count']}"
                if row["unknown_group_count"] else ""
            )
        )


def write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "sdk",
                "category",
                "priority",
                "risk_total",
                "confidence_score",
                "confidence_label",
                "hits",
                "unknown_group_count",
                "data_access",
                "egress",
                "triggerability",
                "business_impact",
                "test_next",
                "evidence_summary",
            ],
        )
        writer.writeheader()
        for row in rows:
            evidence_summary = " | ".join(
                f"{ev['source']}::{ev['evidence_type']}" for ev in row["evidence"][:5]
            )
            writer.writerow({
                "sdk": row["sdk"],
                "category": row["category"],
                "priority": row["priority"],
                "risk_total": row["risk_total"],
                "confidence_score": row["confidence_score"],
                "confidence_label": row["confidence_label"],
                "hits": row["hits"],
                "unknown_group_count": row["unknown_group_count"],
                "data_access": row["data_access"],
                "egress": row["egress"],
                "triggerability": row["triggerability"],
                "business_impact": row["business_impact"],
                "test_next": row["test_next"],
                "evidence_summary": evidence_summary,
            })


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Heuristic SDK finder and triage scorer for iOS and Android binaries"
    )
    parser.add_argument("target", help="Path to .ipa, .app, or .apk")
    parser.add_argument("--signatures", required=True, help="Path to signatures.json")
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    parser.add_argument("--csv-out", help="Write ranked summary to CSV")
    parser.add_argument("--top", type=int, default=5, help="How many top candidates to print")
    parser.add_argument("--use-jadx", action="store_true", help="Use JADX for Android APKs if available")
    parser.add_argument("--quiet", action="store_true", help="Suppress status updates on stderr")
    parser.add_argument(
        "--simple-text-search",
        action="store_true",
        help="Enable broad filename, text-file, and extracted-strings fallback scanning",
    )
    args = parser.parse_args()

    target = Path(args.target).resolve()
    sig_path = Path(args.signatures).resolve()

    if not target.exists():
        print(f"Target not found: {target}", file=sys.stderr)
        return 1
    if not sig_path.exists():
        print(f"Signature file not found: {sig_path}", file=sys.stderr)
        return 1

    platform = detect_type(target)
    if platform == "unknown":
        print("Unsupported target. Use .ipa, .app, or .apk", file=sys.stderr)
        return 2

    status = lambda message: print_status(message, enabled=not args.quiet)

    status(f"loading signatures from {sig_path}")

    try:
        signatures = load_signatures(sig_path)
        compiled_signatures = compile_signatures(signatures)
    except Exception as e:
        print(f"Failed to load signatures: {e}", file=sys.stderr)
        return 2

    results = collections.defaultdict(
        lambda: {
            "sdk": "",
            "category": "",
            "hits": 0,
            "unknown_group_count": 0,
            "confidence_points": 0,
            "evidence_types": set(),
            "evidence": [],
            "seen": set(),
        }
    )

    with tempfile.TemporaryDirectory(prefix="sdk_finder_v3_") as td:
        work = Path(td)

        if target.is_dir():
            status(f"using app bundle directory {target}")
            scan_root = target
            source_apk_for_jadx = None
        else:
            status(f"extracting {target.name} to temporary workspace")
            unzip_to_temp(target, work)
            if platform == "ios":
                apps = list((work / "Payload").glob("*.app"))
                if not apps:
                    print("Could not find .app inside IPA", file=sys.stderr)
                    return 3
                scan_root = apps[0]
                source_apk_for_jadx = None
                status(f"resolved iOS app bundle {scan_root.name}")
            else:
                scan_root = work
                source_apk_for_jadx = target
                status("resolved Android APK contents")

        if platform == "ios":
            status("starting iOS scan")
            scan_ios(
                scan_root,
                signatures,
                compiled_signatures,
                results,
                progress=status,
                include_simple_search=args.simple_text_search,
            )
        else:
            status("starting Android scan")
            scan_android(
                scan_root,
                signatures,
                compiled_signatures,
                results,
                progress=status,
                include_simple_search=args.simple_text_search,
            )

            if args.use_jadx and source_apk_for_jadx is not None:
                jadx_out = work / "jadx_out"
                status("running JADX")
                should_scan_jadx, has_jadx_output, jadx_message = run_jadx(source_apk_for_jadx, jadx_out)
                if jadx_message:
                    print(f"Warning: {jadx_message}", file=sys.stderr)
                if should_scan_jadx and has_jadx_output:
                    status("scanning JADX output")
                    scan_jadx_output(jadx_out, compiled_signatures, results, progress_enabled=not args.quiet)

    status(f"building summary from {len(results)} matched SDK candidates")
    rows = build_summary(results)

    if args.csv_out:
        status(f"writing CSV to {Path(args.csv_out).resolve()}")
        write_csv(Path(args.csv_out), rows)

    if args.json:
        status("emitting JSON report")
        print(json.dumps({
            "target": str(target),
            "platform": platform,
            "findings": rows,
        }, indent=2))
    else:
        status("printing text report")
        print_report(target, platform, rows, args.top)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
