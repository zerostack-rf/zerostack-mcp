# Copyright (c) 2026 SMLIGHT
# SPDX-License-Identifier: Apache-2.0

"""Comprehensive unit, schema, performance, and OPSEC tests for `zerostack-mcp`."""

from __future__ import annotations

import json
import re
import struct
import subprocess
import time
import tomllib
from pathlib import Path

import jsonschema
import pytest

from zerostack_mcp.catalog import load_diagnostics_catalog, load_remediation_meta
from zerostack_mcp.models import (
    MAX_FLOODING_DEVICES,
    MAX_LOG_BYTES,
    MAX_PROMPT_LOG_CHARS,
)
from zerostack_mcp.server import (
    MCP_SERVER_VERSION,
    REMEDIATION_META,
    ZEROSTACK_FIRMWARE_VERSION,
    ZEROSTACK_MARKETING_URL,
    ZEROSTACK_RELEASE_NAME,
    __version__,
    analyze_zigbee_thread_log,
    check_coordinator_capacity,
    decode_silicon_register,
    diagnose_zigbee_log,
    get_zerostack_benchmarks,
    main,
    mcp,
    resource_benchmarks_summary,
    resource_diagnostics_catalog,
    resource_supported_models,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = Path(__file__).resolve().parent / "schemas" / "server_2025_12_11.schema.json"

# Construct forbidden OPSEC regexes via concatenation so this test file itself never
# contains raw forbidden literals when scanning repository source text or git history.
# Note: High-level marketing mention of "Rust" / "Memory-Safe" is explicitly ALLOWED.
_FORBIDDEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("opsec-rule-01", re.compile(r"\bno_" + r"std\b", re.IGNORECASE)),
    ("opsec-rule-02", re.compile(r"\bcar" + r"go\b", re.IGNORECASE)),
    ("opsec-rule-03", re.compile(r"zerostack-" + r"mac", re.IGNORECASE)),
    ("opsec-rule-04", re.compile(r"zerostack-" + r"nwk", re.IGNORECASE)),
    ("opsec-rule-05", re.compile(r"\bcc2" + r"755\w*", re.IGNORECASE)),
    ("opsec-rule-06", re.compile(r"(?<![0-9a-f])cc2" + r"7(?![0-9a-f]{3,})\w*", re.IGNORECASE)),
    ("opsec-rule-07", re.compile(r"\bs2\.m" + r"g\w*", re.IGNORECASE)),
    ("opsec-rule-08", re.compile(r"\blrf" + r"dpbe\b", re.IGNORECASE)),
    ("opsec-rule-09", re.compile(r"\beip-" + r"130\b", re.IGNORECASE)),
    ("opsec-rule-10", re.compile(r"slzb-" + r"ultima", re.IGNORECASE)),
    ("opsec-rule-11", re.compile(r"slzb-" + r"mr", re.IGNORECASE)),
    ("opsec-rule-12", re.compile(r"_v2\." + r"bin", re.IGNORECASE)),
    ("opsec-rule-13", re.compile(r"\btl" + r"sf\b", re.IGNORECASE)),
    ("opsec-rule-14", re.compile(r"cobs-" + r"mux", re.IGNORECASE)),
    ("opsec-rule-15", re.compile(r"3-in-" + r"1", re.IGNORECASE)),
    ("opsec-rule-16", re.compile(r"dirty-" + r"bit", re.IGNORECASE)),
    ("opsec-rule-17", re.compile(r"lru\s+" + r"cache", re.IGNORECASE)),
    ("opsec-rule-18", re.compile(r"40\+\s+direct\s+" + r"sleepy", re.IGNORECASE)),
    ("opsec-rule-19", re.compile(r"72\+\s+" + r"sleepy", re.IGNORECASE)),
    ("opsec-rule-20", re.compile(r"128\+\s+" + r"sleepy", re.IGNORECASE)),
    ("opsec-rule-21", re.compile(r"64-" + r"slot", re.IGNORECASE)),
    ("opsec-rule-22", re.compile(r"/usr/" + r"local", re.IGNORECASE)),
    ("opsec-rule-23", re.compile(r"\b192\.16" + r"8\.", re.IGNORECASE)),
    ("opsec-rule-24", re.compile(r"\bcra" + r"te\b", re.IGNORECASE)),
    ("opsec-rule-25", re.compile(r"c/ru" + r"st\s+abi", re.IGNORECASE)),
    ("opsec-rule-26", re.compile(r"\bf" + r"fi\b", re.IGNORECASE)),
    ("opsec-rule-27", re.compile(r"pure-" + r"rust", re.IGNORECASE)),
    ("opsec-rule-28", re.compile(r"zerostack-" + r"zdo", re.IGNORECASE)),
    ("opsec-rule-29", re.compile(r"znp_" + r"shim", re.IGNORECASE)),
    ("opsec-rule-30", re.compile(r"mg" + r"26\w*", re.IGNORECASE)),
    ("opsec-rule-31", re.compile(r"ti_" + r"f3", re.IGNORECASE)),
    ("opsec-rule-32", re.compile(r"silabs_" + r"s3", re.IGNORECASE)),
    (
        "opsec-rule-33",
        re.compile(r"zerostack[-_\s]*spin" + r"el|spin" + r"el[-_]+rcp", re.IGNORECASE),
    ),
    ("opsec-rule-34", re.compile(r"\bzr" + r"el\b", re.IGNORECASE)),
    ("opsec-rule-35", re.compile(r"\bhad" + r"ron\b", re.IGNORECASE)),
    ("opsec-rule-36", re.compile(r"mys" + r"tic\.lan", re.IGNORECASE)),
)


def _scan_text_for_forbidden_terms(text: str, source_label: str) -> None:
    for label, pattern in _FORBIDDEN_PATTERNS:
        match = pattern.search(text)
        assert match is None, (
            f"OPSEC violation ({label}) matched {match.group(0)!r} in {source_label}"
        )


def _assert_no_forbidden_terms(payload: object, label: str = "payload") -> None:
    serialized = payload if isinstance(payload, str) else json.dumps(payload)
    _scan_text_for_forbidden_terms(serialized, label)


def test_opsec_scanner_rejects_every_forbidden_token_and_allows_marketing_terms() -> None:
    samples = (
        "uses " + "no_" + "std runtime",
        "built with " + "car" + "go build",
        "internal " + "zerostack-" + "mac module",
        "internal " + "zerostack-" + "nwk module",
        "ti " + "cc2" + "755r10 target",
        "ti " + "cc2" + "7xx family",
        "bench " + "s2." + "mg24 node",
        "radio " + "lrf" + "dpbe register",
        "crypto " + "eip-" + "130 engine",
        "board " + "slzb-" + "ultima",
        "board " + "slzb-" + "mr",
        "image fw" + "_v2." + "bin",
        "heap " + "tl" + "sf allocator",
        "serial " + "cobs-" + "mux framing",
        "mode " + "3-in-" + "1 firmware",
        "nvm " + "dirty-" + "bit tracking",
        "table " + "lru " + "cache",
        "supports " + "40+ direct " + "sleepy sensors",
        "supports " + "72+ " + "sleepy sensors",
        "supports " + "128+ " + "sleepy sensors",
        "hardware " + "64-" + "slot table",
        "path /usr/" + "local/src/project",
        "socket 192." + "168.1.50:6638",
        "internal " + "cra" + "te dependency",
        "verified " + "C/Ru" + "st ABI invariants",
        "calls " + "F" + "FI boundary",
        "engine " + "Pure-" + "Rust stack",
        "module " + "zerostack-" + "zdo",
        "glue " + "znp_" + "shim layer",
        "silabs efr32" + "mg" + "26 target",
        "platform " + "ti_" + "f3",
        "platform " + "silabs_" + "s3",
        "module " + "zerostack-" + "spinel",
        "bridge " + "zr" + "el stream",
        "host " + "had" + "ron server",
        "domain " + "mys" + "tic.lan",
    )
    for bad in samples:
        with pytest.raises(AssertionError, match="OPSEC violation"):
            _assert_no_forbidden_terms(bad, "negative-self-test")

    # High-level Rust / Memory-Safe marketing terms, TCLK, and RFC 5737 IPs are allowed
    _assert_no_forbidden_terms(
        "Memory-Safe Rust Protocol Engine & Trust Center Link Key (TCLK) on 192.0.2.50:6638",
        "allowed-marketing-and-zigbee-terms",
    )


def _extract_pdf_text(pdf_path: Path) -> str:
    res = subprocess.run(
        ["pdftotext", str(pdf_path), "-"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert len(res.stdout.strip()) > 500, f"pdftotext extracted empty text from {pdf_path}"
    return res.stdout


def _verify_png_dimensions_and_clean_metadata(
    png_path: Path, expected_size: tuple[int, int]
) -> None:
    data = png_path.read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n", f"Invalid PNG signature in {png_path}"
    width, height = struct.unpack(">II", data[16:24])
    assert (width, height) == expected_size, (
        f"Expected {expected_size} for {png_path.name}, got {(width, height)}"
    )
    pos = 8
    forbidden_chunks = {b"tEXt", b"iTXt", b"zTXt"}
    while pos < len(data):
        length = struct.unpack(">I", data[pos : pos + 4])[0]
        chunk_type = data[pos + 4 : pos + 8]
        assert chunk_type not in forbidden_chunks, (
            f"Metadata chunk {chunk_type!r} found in {png_path.name}"
        )
        pos += 12 + length


def test_opsec_across_all_repository_files_and_synced_catalogs() -> None:
    skip_dirs = {".git", ".venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
    legacy_semver = "0.9.9-beta" + "1"
    legacy_badge_semver = "0.9.9--beta" + "1"
    raw_latex_re = re.compile(r"\$" + r"(?:O\(|\\Delta|\\cdot|\\times|D\s*=|k\s*=)")
    scanned_files = 0
    for path in sorted(REPO_ROOT.rglob("*")):
        if any(part in skip_dirs for part in path.parts) or not path.is_file():
            continue
        if path.suffix in {".pyc", ".png", ".whl"}:
            continue
        if path.suffix == ".pdf":
            _scan_text_for_forbidden_terms(
                _extract_pdf_text(path),
                f"pdf:{path.relative_to(REPO_ROOT)}",
            )
            scanned_files += 1
            continue
        content = path.read_text(encoding="utf-8")
        _scan_text_for_forbidden_terms(content, str(path.relative_to(REPO_ROOT)))
        assert legacy_semver not in content and legacy_badge_semver not in content, (
            f"Unstandardized SemVer in {path.relative_to(REPO_ROOT)}"
        )
        if path.suffix == ".md":
            assert not raw_latex_re.search(content), (
                f"Raw LaTeX math found in {path.relative_to(REPO_ROOT)}"
            )
        scanned_files += 1
    assert scanned_files >= 12

    parent_sample_logs = REPO_ROOT.parent / "SAMPLE_LOGS.md"
    if parent_sample_logs.is_file():
        assert (REPO_ROOT / "SAMPLE_LOGS.md").read_bytes() == parent_sample_logs.read_bytes()

    sibling_repo = REPO_ROOT.parent / "smlight-tech-zerostack"
    if sibling_repo.is_dir():
        mcp_cat = (
            REPO_ROOT / "src" / "zerostack_mcp" / "data" / "diagnosticsCatalog.json"
        ).read_bytes()
        diag_cat = (sibling_repo / "diagnostics" / "diagnosticsCatalog.json").read_bytes()
        docs_cat = (sibling_repo / "docs" / "diagnosticsCatalog.json").read_bytes()
        assert mcp_cat == diag_cat == docs_cat

        assert (sibling_repo / "LICENSE").is_file()
        assert (sibling_repo / "NOTICE").is_file()
        assert (sibling_repo / "FIRMWARE_LICENSE.md").is_file()

        index_html = (sibling_repo / "docs" / "index.html").read_text(encoding="utf-8")
        parsed_cat = json.loads(mcp_cat.decode("utf-8"))
        expected_wm = json.dumps(
            parsed_cat["signatures"], ensure_ascii=False, separators=(",", ":")
        )
        expected_hm = json.dumps(
            parsed_cat["remediationMeta"], ensure_ascii=False, separators=(",", ":")
        )
        assert f"const Wm={expected_wm},Hm={expected_hm}" in index_html
        assert "<noscript>" not in index_html
        assert re.search(r'<div id="root">\s*<main\b', index_html) is not None
        assert '<img src="./assets/smlight-logo.png" alt="SMLIGHT" height="24">' in index_html
        assert "https://smlight.tech/software/zerostack/og-image.png" in index_html

        hero_url = (
            "https://raw.githubusercontent.com/smlight-tech/zerostack/main/"
            "docs/assets/zerostack-hero-banner.png"
        )
        sibling_readme = (sibling_repo / "README.md").read_text(encoding="utf-8")
        assert hero_url in (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        assert hero_url in sibling_readme
        assert "(`Adversarial & Fault-Injection Suite`)" in sibling_readme
        assert "`Whitepaper Part 2`" not in sibling_readme
        assert "No on `v1`" not in sibling_readme
        assert (
            "| **SLZB-06P7** / **SLZB-06P7v1** | **TI CC2652P7 (`CC1352P7`)** | "
            "ARM Cortex-M4F @ 48 MHz + Cortex-M0 CPE | 704 KB Flash / **144 KB SRAM** | "
            "No (`rtscts: false`) |"
        ) in sibling_readme

        docs_dir = sibling_repo / "docs"
        _verify_png_dimensions_and_clean_metadata(docs_dir / "apple-touch-icon.png", (180, 180))
        _verify_png_dimensions_and_clean_metadata(docs_dir / "icon-192.png", (192, 192))
        _verify_png_dimensions_and_clean_metadata(docs_dir / "icon-512.png", (512, 512))
        _verify_png_dimensions_and_clean_metadata(docs_dir / "og-image.png", (1200, 630))
        _verify_png_dimensions_and_clean_metadata(
            docs_dir / "assets" / "smlight-logo-2x.png", (1800, 512)
        )
        _verify_png_dimensions_and_clean_metadata(
            docs_dir / "assets" / "smlight-logo-darkbg.png", (1800, 512)
        )
        _verify_png_dimensions_and_clean_metadata(
            docs_dir / "assets" / "smlight-logo.png", (360, 102)
        )
        _verify_png_dimensions_and_clean_metadata(
            docs_dir / "assets" / "zerostack-hero-banner.png", (1600, 320)
        )

        ico_bytes = (docs_dir / "favicon.ico").read_bytes()
        reserved, ico_type, ico_count = struct.unpack("<HHH", ico_bytes[:6])
        assert (reserved, ico_type, ico_count) == (0, 1, 3)
        ico_dims = {(ico_bytes[6 + i * 16], ico_bytes[7 + i * 16]) for i in range(3)}
        assert ico_dims == {(16, 16), (32, 32), (48, 48)}

        scanned_pdfs = 0
        for pub_file in sorted(sibling_repo.rglob("*")):
            if any(part in skip_dirs for part in pub_file.parts) or not pub_file.is_file():
                continue
            if pub_file.suffix in {".png", ".svg", ".ico"}:
                continue
            if pub_file.suffix == ".pdf":
                _scan_text_for_forbidden_terms(
                    _extract_pdf_text(pub_file),
                    f"smlight-tech-zerostack/{pub_file.relative_to(sibling_repo)}",
                )
                scanned_pdfs += 1
                continue
            pub_text = pub_file.read_text(encoding="utf-8")
            rel_pub = f"smlight-tech-zerostack/{pub_file.relative_to(sibling_repo)}"
            _scan_text_for_forbidden_terms(pub_text, rel_pub)
            assert legacy_semver not in pub_text and legacy_badge_semver not in pub_text, (
                f"Unstandardized SemVer in {rel_pub}"
            )
            if pub_file.suffix == ".md":
                assert not raw_latex_re.search(pub_text), f"Raw LaTeX math found in {rel_pub}"
        assert scanned_pdfs >= 1

    for bench_pdf in sorted(
        REPO_ROOT.parents[1].glob("*/docs/benchmarks/ZeroStack Whitepaper Part *.pdf")
    ):
        _scan_text_for_forbidden_terms(
            _extract_pdf_text(bench_pdf),
            bench_pdf.name,
        )


def test_server_json_validates_against_2025_12_11_schema_and_packaging() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    server_manifest = json.loads((REPO_ROOT / "server.json").read_text(encoding="utf-8"))

    validator = jsonschema.Draft7Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    )
    errors = list(validator.iter_errors(server_manifest))
    assert errors == [], f"server.json failed 2025-12-11 schema validation: {errors}"

    assert (
        server_manifest["$schema"]
        == "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"
    )
    assert len(server_manifest["description"]) <= 100
    assert "homepage" not in server_manifest
    assert server_manifest["websiteUrl"] == ZEROSTACK_MARKETING_URL
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    expected_pypi_ver = str(pyproject["project"]["version"])
    assert expected_pypi_ver == "0.9.9"
    assert __version__ == expected_pypi_ver
    assert MCP_SERVER_VERSION == expected_pypi_ver
    assert mcp.version == expected_pypi_ver
    assert ZEROSTACK_FIRMWARE_VERSION == "0.9.9-beta.1"
    assert server_manifest["version"] == pyproject["project"]["version"]
    assert server_manifest["packages"][0]["version"] == pyproject["project"]["version"]
    pkg = server_manifest["packages"][0]
    assert pkg == {
        "registryType": "pypi",
        "identifier": "zerostack-mcp",
        "version": expected_pypi_ver,
        "runtimeHint": "uvx",
        "transport": {"type": "stdio"},
    }

    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert 'CMD ["zerostack-mcp"]' in dockerfile
    assert "ENTRYPOINT" not in dockerfile
    assert (REPO_ROOT / "glama.json").is_file()
    assert (REPO_ROOT / "llms.txt").is_file()
    llms_txt = (REPO_ROOT / "llms.txt").read_text(encoding="utf-8")
    assert (
        "> MCP Server Version: 0.9.9 | Firmware Catalog: ZeroStack Release Zero (0.9.9-beta.1)"
        in llms_txt
    )

    ci_yml = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "3.11" not in ci_yml
    assert 'python-version: ["3.12", "3.13", "3.14"]' in ci_yml
    assert "uv run ruff format --check src/ tests/" in ci_yml

    sample_logs = (REPO_ROOT / "SAMPLE_LOGS.md").read_text(encoding="utf-8")
    assert "verify_coordinator_capacity" not in sample_logs
    assert "check_coordinator_capacity" in sample_logs


def test_catalog_loader_fails_fast_on_missing_or_corrupt_json(tmp_path: Path) -> None:
    missing_path = tmp_path / "does_not_exist.json"
    with pytest.raises(FileNotFoundError):
        load_diagnostics_catalog(missing_path)
    with pytest.raises(FileNotFoundError):
        load_remediation_meta(missing_path)

    corrupt_path = tmp_path / "corrupt.json"
    corrupt_path.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid JSON"):
        load_diagnostics_catalog(corrupt_path)

    empty_sigs_path = tmp_path / "empty_sigs.json"
    empty_sigs_path.write_text(json.dumps({"signatures": {}}), encoding="utf-8")
    with pytest.raises(ValueError, match="non-empty 'signatures'"):
        load_diagnostics_catalog(empty_sigs_path)

    rules = load_diagnostics_catalog()
    assert len(rules) >= 14
    for rule in rules:
        assert rule.description
        assert rule.remediation_key is not None

    meta = load_remediation_meta()
    assert "TI SimpleLink F2 ZNP coordinators" in meta["issue-ezsp-version"]["zeroStackFix"]
    assert "not EZSP" in meta["issue-ezsp-version"]["zeroStackFix"]


def test_analyze_log_empty_clean_and_benign_hex_payload_no_false_positives() -> None:
    empty = analyze_zigbee_thread_log("   ")
    assert empty["status"] == "empty_input"
    assert empty["matched_count"] == 0
    assert empty["truncated"] is False
    assert empty["total_input_lines"] == 0
    assert empty["marketing_url"] == ZEROSTACK_MARKETING_URL
    assert empty["release"] == ZEROSTACK_RELEASE_NAME

    # Benign ZCL hex payload dumps containing 0xb2, 0xc7, 0xf0, 0xf1, 0x72, 0xa1, 0x10, 0x11, 0xe9
    benign_hex_dump = "\n".join(
        [
            "info 2026-10-29 12:00:01: Zigbee2MQTT started normally on channel 20",
            (
                "debug 2026-10-29 12:00:02: Raw ZCL payload "
                "0xb2 0xc7 0xf0 0xf1 0x72 0xa1 0x10 0x11 0x66 0xe1 0xe9"
            ),
            (
                "debug 2026-10-29 12:00:03: ZCL manufacturer cluster "
                "bytes=[0xf0, 0xf1, 0xb2, 0xc7, 0x72, 0xa1]"
            ),
            (
                "info 2026-10-29 12:00:04: Device 'sensor_0xf0' joined "
                "with shortAddr 0xb2c7 and endpoint 233"
            ),
        ]
    )
    clean = analyze_zigbee_thread_log(benign_hex_dump)
    assert clean["status"] == "no_known_fault_signatures"
    assert clean["matched_count"] == 0
    assert clean["truncated"] is False
    assert clean["total_input_lines"] == 4


def test_analyze_log_znp_srsp_warm_reset_and_ezsp_legacy_version() -> None:
    warm_log = "Error: Failed to connect to the adapter (Error: SRSP - SYS - ping after 6000ms)"
    res_warm = analyze_zigbee_thread_log(warm_log)
    assert res_warm["status"] == "fault_signatures_detected"
    sig_ids = [m["signature_id"] for m in res_warm["matches"]]
    assert "ZNP_WARM_RESET_SYS_PING_TIMEOUT" in sig_ids
    assert "ZNP_SRSP_6000MS_TIMEOUT" not in sig_ids
    assert "remediation_meta" in res_warm["matches"][0]
    _assert_no_forbidden_terms(res_warm)

    af_log = "zh:zstack:znp: Error: SRSP - AF - dataRequest after 6000ms"
    res_af = analyze_zigbee_thread_log(af_log)
    assert res_af["status"] == "fault_signatures_detected"
    af_match = res_af["matches"][0]
    assert af_match["signature_id"] == "ZNP_SRSP_6000MS_TIMEOUT"
    assert "82.7" in af_match["zeroStackFix"]
    assert ZEROSTACK_MARKETING_URL in af_match["zeroStackFix"]
    _assert_no_forbidden_terms(res_af)

    ezsp_log = (
        "zh:ember: Adapter EZSP protocol version (8) is not supported by Host\n"
        "z2m: Configured channel '20' does not match adapter channel '11'\n"
        "z2m: USB adapter discovery error\n"
        "z2m: Configuration is not consistent with adapter state\n"
        "z2m: PAN ID conflict detected on channel 20\n"
        "zh:ember:uart:ash: Received frame with CRC error\n"
        "z2m: Opening serial port timed out"
    )
    res_ezsp = analyze_zigbee_thread_log(ezsp_log)
    assert res_ezsp["status"] == "fault_signatures_detected"
    by_id = {m["signature_id"]: m for m in res_ezsp["matches"]}
    assert "EZSP_LEGACY_PROTOCOL_VERSION" in by_id
    assert "not EZSP" in by_id["EZSP_LEGACY_PROTOCOL_VERSION"]["zeroStackFix"]
    assert "CHANNEL_MISMATCH_AUTO_SWITCH" in by_id
    assert "ADAPTER_DISCOVERY_ERROR" in by_id
    assert "ADAPTER_CONFIG_MISMATCH" in by_id
    assert "PAN_ID_CONFLICT" in by_id
    assert "ASH_UART_LINK_ERROR" in by_id
    assert "ADAPTER_STARTUP_TIMEOUT" in by_id
    assert len(REMEDIATION_META) == 15
    _assert_no_forbidden_terms(res_ezsp)


def test_analyze_log_unquoted_status_strings_and_zha_sl_status() -> None:
    log_text = "\n".join(
        [
            "error: Data request failed with error: MAC channel access failure (225)",
            "error: Data request failed with error: MAC no ack (233)",
            "error: zigpy.exceptions.DeliveryError: <sl_Status.MAC_NO_ACK_RECEIVED: 233>",
            "error: zigpy.exceptions.DeliveryError: <sl_Status.MAC_NO_ACK_RECEIVED: 0xe9>",
            "error: DataConfirm error: MAC transaction expired (240)",
            "error: DataConfirm error: MAC transaction overflow (241)",
            "error: Data request failed with error: NWK no route (205)",
            "error: Data request failed with error: APS no ack (167)",
            "error: Data request failed with error: APS table full (178)",
            "error: Data request failed with error: NWK table full (199)",
        ]
    )
    res = analyze_zigbee_thread_log(log_text)
    assert res["status"] == "fault_signatures_detected"
    found = {m["signature_id"]: m for m in res["matches"]}
    assert found["MAC_0XE1_CHANNEL_ACCESS_FAILURE"]["occurrences"] == 1
    assert found["MAC_0XE9_NO_ACK"]["occurrences"] == 3
    assert "50%" in found["MAC_0XE9_NO_ACK"]["zeroStackFix"]
    assert "FP=1" in found["MAC_0XE9_NO_ACK"]["siliconRootCause"]
    assert "11.11 ms" in found["MAC_0XE9_NO_ACK"]["siliconRootCause"]
    assert found["MAC_0XF0_TRANSACTION_EXPIRED"]["occurrences"] == 1
    assert "50%" in found["MAC_0XF0_TRANSACTION_EXPIRED"]["zeroStackFix"]
    assert found["MAC_0XF1_TRANSACTION_OVERFLOW"]["occurrences"] == 1
    assert "50%" in found["MAC_0XF1_TRANSACTION_OVERFLOW"]["zeroStackFix"]
    assert found["ZNP_0XCD_NWK_NO_ROUTE"]["occurrences"] == 1
    assert found["ZNP_TCLK_INTERVIEW_TIMEOUT"]["occurrences"] == 1
    assert found["ZNP_0XB2_APS_TABLE_FULL"]["occurrences"] == 1
    assert found["ZNP_0XC7_NWK_TABLE_FULL"]["occurrences"] == 1
    _assert_no_forbidden_terms(res)


def test_sample_logs_md_prompts_end_to_end() -> None:
    sample_md = (REPO_ROOT / "SAMPLE_LOGS.md").read_text(encoding="utf-8")
    blocks = re.findall(r"```text\n(.*?)```", sample_md, flags=re.DOTALL)
    assert len(blocks) == 3

    # Prompt 1: 2-msg sub-second kitchen_plug_2 + 3-msg living_room_plug_1 + 205 + 6000ms SRSP
    res1 = analyze_zigbee_thread_log(blocks[0])
    assert res1["status"] == "fault_signatures_detected"
    # Deterministic ranking: 6000ms SRSP freeze outranks NWK_NO_ROUTE and warning flood
    assert res1["matches"][0]["signature_id"] == "ZNP_SRSP_6000MS_TIMEOUT"
    found1 = {m["signature_id"]: m for m in res1["matches"]}
    assert "ZNP_0XCD_NWK_NO_ROUTE" in found1
    assert "ZCL_TELEMETRY_DELTA_ZERO_FLOOD" in found1
    flood_devs = {
        d["device"]: d for d in found1["ZCL_TELEMETRY_DELTA_ZERO_FLOOD"]["flooding_devices"]
    }
    assert "living_room_plug_1" in flood_devs
    assert "kitchen_plug_2" in flood_devs
    assert flood_devs["kitchen_plug_2"]["delta_zero_duplicates"] == 1

    # Prompt 2: (240), (241), 0x10, 0x11, (225), (233), <sl_Status.MAC_NO_ACK_RECEIVED: 233>, 0xC7
    res2 = analyze_zigbee_thread_log(blocks[1])
    assert res2["status"] == "fault_signatures_detected"
    assert res2["matches"][0]["signature_id"] == "ZNP_0X10_MEM_ERROR"
    found2 = {m["signature_id"]: m for m in res2["matches"]}
    for expected_id in (
        "MAC_0XF0_TRANSACTION_EXPIRED",
        "MAC_0XF1_TRANSACTION_OVERFLOW",
        "ZNP_0X10_MEM_ERROR",
        "ZNP_0X11_BUFFER_FULL",
        "MAC_0XE1_CHANNEL_ACCESS_FAILURE",
        "MAC_0XE9_NO_ACK",
        "ZNP_0XC7_NWK_TABLE_FULL",
    ):
        assert expected_id in found2
    assert found2["MAC_0XE9_NO_ACK"]["occurrences"] == 2

    # Prompt 3: Interview / TCLK timeout + SRSP ZDO timeout -> TCLK (2 hits) outranks SRSP (1 hit)
    res3 = analyze_zigbee_thread_log(blocks[2])
    assert res3["status"] == "fault_signatures_detected"
    assert res3["matches"][0]["signature_id"] == "ZNP_TCLK_INTERVIEW_TIMEOUT"
    found3 = {m["signature_id"]: m for m in res3["matches"]}
    assert "ZNP_SRSP_6000MS_TIMEOUT" in found3


def test_analyze_log_efr32_otbr_attribute_report_and_gentime_floods() -> None:
    log_text = "\n".join(
        [
            "bellows.ezsp: sendUnicast failed with status=0x72 (EMBER_MAX_MESSAGE_LIMIT_REACHED)",
            "bellows.ezsp: sendBroadcast failed with status=0xa1 (EMBER_NETWORK_BUSY)",
            "bellows.ash: ASH_NCP_FATAL_ERROR / EZSP_ERROR_OVERFLOW",
            "bellows.zigbee.application: Delivery failed for '0x1234' (EMBER_DELIVERY_FAILED)",
            "otbr-agent: RadioSpinel::HandleResponse() Timeout / WaitForWritable() timed out",
            (
                "debug 2026-10-29 12:00:01: Received Zigbee message from 'tuya_plug_raw', "
                "type 'attributeReport', cluster 'haElectricalMeasurement', "
                'data \'{"rmsVoltage":230,"activePower":85}\''
            ),
            (
                "debug 2026-10-29 12:00:01: Received Zigbee message from 'tuya_plug_raw', "
                "type 'attributeReport', cluster 'haElectricalMeasurement', "
                'data \'{"rmsVoltage":230,"activePower":85}\''
            ),
            (
                "debug 2026-10-29 12:00:02: Received Zigbee message from 'tuya_siren', "
                "type 'read', cluster 'genTime', data '[\"localTime\"]'"
            ),
            (
                "debug 2026-10-29 12:00:02: Received Zigbee message from 'tuya_siren', "
                "type 'read', cluster 'genTime', data '[\"localTime\"]'"
            ),
            (
                "debug 2026-10-29 12:00:03: Received Zigbee message from 'tuya_siren', "
                "type 'read', cluster 'genTime', data '[\"localTime\"]'"
            ),
        ]
    )
    res = analyze_zigbee_thread_log(log_text)
    found = {m["signature_id"]: m for m in res["matches"]}
    assert "EMBER_0X72_MAX_MESSAGE_LIMIT" in found
    assert "EMBER_0XA1_NETWORK_BUSY" in found
    assert "EMBER_ASH_NCP_FATAL_ERROR" in found
    assert "EMBER_DELIVERY_FAILED" in found
    assert "50%" in found["EMBER_DELIVERY_FAILED"]["zeroStackFix"]
    assert "FP=1" in found["EMBER_DELIVERY_FAILED"]["zeroStackFix"]
    assert "OTBR_SPINEL_TIMEOUT" in found
    assert "ZCL_TELEMETRY_DELTA_ZERO_FLOOD" in found
    assert (
        found["ZCL_TELEMETRY_DELTA_ZERO_FLOOD"]["flooding_devices"][0]["device"] == "tuya_plug_raw"
    )
    assert "ZCL_GENTIME_READ_FLOOD" in found
    assert found["ZCL_GENTIME_READ_FLOOD"]["remediation_key"] == "gentime-floods"
    _assert_no_forbidden_terms(res)


def test_flooding_devices_capped_at_20_and_sorted_by_rate() -> None:
    lines: list[str] = []
    for dev_idx in range(25):
        repeats = 2 + (dev_idx % 5)
        for rep in range(repeats):
            lines.append(
                f"info 2026-10-29 12:00:00.{rep:03d}: MQTT publish: topic "
                f"'zigbee2mqtt/plug_{dev_idx:02d}', payload '{{\"power\":{100 + dev_idx}}}'"
            )
    res = analyze_zigbee_thread_log("\n".join(lines))
    flood = next(m for m in res["matches"] if m["signature_id"] == "ZCL_TELEMETRY_DELTA_ZERO_FLOOD")
    devs = flood["flooding_devices"]
    assert len(devs) == MAX_FLOODING_DEVICES
    rates = [d["rate_msg_per_sec"] for d in devs]
    assert rates == sorted(rates, reverse=True)


def test_100k_line_log_bounded_truncation_and_sub_500ms_performance() -> None:
    filler = [f"info 2026-10-29 12:00:00: Normal router heartbeat seq={i}" for i in range(99_998)]
    all_lines = [
        "error 2026-10-29 11:59:59: SREQ AF_DataRequest failed with 0x10: MEM_ERROR",
        *filler,
        "error 2026-10-29 12:05:00: AREQ - SYS - resetInd",
    ]
    huge_log = "\n".join(all_lines)

    cpu_t0 = time.process_time()
    t0 = time.perf_counter()
    res = analyze_zigbee_thread_log(huge_log)
    elapsed_s = time.perf_counter() - t0
    cpu_s = time.process_time() - cpu_t0

    assert cpu_s < 0.25, f"100k-line log CPU time {cpu_s:.3f}s (exceeded 0.25s CPU budget)"
    assert elapsed_s < 0.5, f"100k-line log took {elapsed_s:.3f}s (exceeded 0.5s budget)"
    assert res["truncated"] is True
    assert res["total_input_lines"] == 100_000
    found = {m["signature_id"]: m for m in res["matches"]}
    # Both head fault (line 1) and tail fault (line 100,000) must be preserved!
    assert "ZNP_0X10_MEM_ERROR" in found
    assert found["ZNP_0X10_MEM_ERROR"]["matching_lines"][0]["line_number"] == 1
    assert "ZNP_SYS_RESET_IND" in found
    assert found["ZNP_SYS_RESET_IND"]["matching_lines"][0]["line_number"] == 100_000
    # MCU Reset (prio 100) deterministically outranks MEM_ERROR (prio 86)
    assert res["matches"][0]["signature_id"] == "ZNP_SYS_RESET_IND"

    # Also verify MAX_LOG_BYTES windowing on >2 MB input
    oversized_bytes_log = ("info 2026-10-29: benign filler line " + ("x" * 180) + "\n") * 11_000
    assert len(oversized_bytes_log.encode("utf-8")) > MAX_LOG_BYTES
    res_bytes = analyze_zigbee_thread_log(oversized_bytes_log)
    assert res_bytes["truncated"] is True
    assert res_bytes["total_input_lines"] == 11_000

    # Also verify pure MAX_LOG_LINES truncation (<2 MB total bytes, >25,000 lines)
    lines_only_log = (
        "error 2026-10-29: SREQ AF_DataRequest failed with 0x10: MEM_ERROR\n"
        + ("ok\n" * 29_998)
        + "error 2026-10-29: AREQ - SYS - resetInd"
    )
    assert len(lines_only_log.encode("utf-8")) < MAX_LOG_BYTES
    res_lines = analyze_zigbee_thread_log(lines_only_log)
    assert res_lines["truncated"] is True
    assert res_lines["total_input_lines"] == 30_000
    found_lines = {m["signature_id"]: m for m in res_lines["matches"]}
    assert found_lines["ZNP_0X10_MEM_ERROR"]["matching_lines"][0]["line_number"] == 1
    assert found_lines["ZNP_SYS_RESET_IND"]["matching_lines"][0]["line_number"] == 30_000

    publish_yml = (REPO_ROOT / ".github" / "workflows" / "python-publish.yml").read_text(
        encoding="utf-8"
    )
    assert "url: https://pypi.org/p/zerostack-mcp" in publish_yml


def test_decode_silicon_register_f2_and_efr32() -> None:
    rx_abort = decode_silicon_register("CC2652P7", "CMD_IEEE_RX", "0x0807")
    assert rx_abort["register"] == "CMD_IEEE_RX"
    assert rx_abort["healthy"] is False
    assert rx_abort["bitfields"]["STATUS_NAME"] == "DONE_ABORT"
    assert rx_abort["marketing_url"] == ZEROSTACK_MARKETING_URL
    assert rx_abort["release"] == ZEROSTACK_RELEASE_NAME
    _assert_no_forbidden_terms(rx_abort)

    rx_active = decode_silicon_register("SLZB-06P10", "CMD_IEEE_RX", "0x0002")
    assert rx_active["healthy"] is True

    csma_busy = decode_silicon_register("CC1352P7", "CMD_IEEE_CSMA", "0x2401")
    assert csma_busy["healthy"] is False
    assert csma_busy["bitfields"]["IEEE_DONE_BUSY (0x2401)"] == 1

    dbell_stripped = decode_silicon_register("CC2652P", "RFC_DBELL", "0x00000001")
    assert dbell_stripped["healthy"] is False
    assert dbell_stripped["bitfields"]["LAST_FG_CMD_DONE (Bit 1)"] == 0

    srcmatch_full = decode_silicon_register("SLZB-06P7", "SRCMATCH", "0xFFFFFFFF")
    assert srcmatch_full["healthy"] is False
    assert srcmatch_full["bitfields"]["OCCUPIED_SLOTS"] == 32
    assert "50% pool cap" in srcmatch_full["diagnosis"]
    _assert_no_forbidden_terms(srcmatch_full)

    vims = decode_silicon_register("CC2674P10", "VIMS", "0x00000001")
    assert vims["healthy"] is True
    assert vims["bitfields"]["CACHE_ENABLED"] == 1

    prcm = decode_silicon_register("CC2652P", "PRCM", "0x00000002")
    assert prcm["healthy"] is True
    assert prcm["bitfields"]["IEEE_802154_ENABLED (Bit 1)"] == 1

    eusart = decode_silicon_register("EFR32MG21", "EUSART0_IF", "0x08")
    assert eusart["healthy"] is False
    assert eusart["bitfields"]["RXOF (Bit 3)"] == 1
    assert "in active development" in eusart.get("zero_stack_remediation", "")
    _assert_no_forbidden_terms(eusart)

    with pytest.raises(ValueError, match="Unsupported chip"):
        decode_silicon_register("UNKNOWN_CHIP", "CMD_IEEE_RX", "0x01")


def test_check_coordinator_capacity_f2_and_efr32() -> None:
    cap_f2 = check_coordinator_capacity(
        device_count=120,
        sleepy_zed_count=36,
        chip_family="SLZB-06P7",
    )
    assert cap_f2["chip_family"] == "F2_CC1352_CC2652"
    assert cap_f2["release"] == ZEROSTACK_RELEASE_NAME
    assert cap_f2["srcmatch_hardware_table"]["max_short_slots"] == 32
    assert cap_f2["srcmatch_hardware_table"]["pend_all_active"] is True
    assert cap_f2["ram_heap_headroom"]["total_sram_kb"] == 144
    assert cap_f2["ram_heap_headroom"].get("indirect_queue_pool_cap_pct") == 50
    assert cap_f2["ram_heap_headroom"].get("max_indirect_frames_per_child") == 2
    assert cap_f2["marketing_url"] == ZEROSTACK_MARKETING_URL
    _assert_no_forbidden_terms(cap_f2)

    cap_p10 = check_coordinator_capacity(
        device_count=180,
        sleepy_zed_count=20,
        chip_family="SLZB-06P10",
    )
    assert cap_p10["ram_heap_headroom"]["total_sram_kb"] == 256
    assert cap_p10["srcmatch_hardware_table"]["pend_all_active"] is False

    cap_efr = check_coordinator_capacity(
        device_count=90,
        sleepy_zed_count=25,
        chip_family="EFR32MG21",
    )
    assert cap_efr["chip_family"] == "SILABS_EFR32"
    assert (
        cap_efr["ram_heap_headroom"]["zerostack_status"] == "EFR32_IN_DEVELOPMENT_TI_F2_AVAILABLE"
    )
    _assert_no_forbidden_terms(cap_efr)

    with pytest.raises(ValueError, match="Unsupported chip"):
        check_coordinator_capacity(device_count=50, sleepy_zed_count=10, chip_family="UNKNOWN_CHIP")


def test_get_zerostack_benchmarks_all_f2_models_and_deduplication() -> None:
    expected_models = (
        "SLZB-06",
        "SLZB-06U",
        "SLZB-06P7",
        "SLZB-06P7U",
        "SLZB-06P7V1",
        "SLZB-07P7",
        "SLZB-06P10",
        "SLZB-07P10",
    )
    for model in expected_models:
        bench = get_zerostack_benchmarks(model)
        assert bench["requested_platform"] != "all"
        assert bench["requested_platform"] == model
        assert bench["release"] == ZEROSTACK_RELEASE_NAME
        assert bench["version"] == ZEROSTACK_FIRMWARE_VERSION
        assert bench["marketing_url"] == ZEROSTACK_MARKETING_URL
        assert "part1_execution_latency" in bench
        assert "part2_resilience_fault_injection" in bench
        assert bench["tclk_miss_speedup_x"] == 4559.0
        assert bench["nwk_encrypt_speedup_x"] == 134.4
        assert bench["nwk_decrypt_speedup_x"] == 139.2
        assert bench["routed_hop_ceiling_pkt_per_sec"] == 6100
        assert bench["malloc_64_holes_cycles"] == 218
        assert bench["malformed_ota_crashes"] == 0
        assert bench["brownout_cut_points_verified"] == 22959
        assert bench["uart_abuse_lost_pings"] == 0
        assert bench["indirect_queue_pool_cap_pct"] == 50
        assert bench["max_indirect_frames_per_child"] == 2
        _assert_no_forbidden_terms(bench)

    all_bench = get_zerostack_benchmarks("all")
    assert all_bench["requested_platform"] == "all"
    assert set(all_bench["platforms"].keys()) == set(expected_models)
    for model_summary in all_bench["platforms"].values():
        assert "part1_execution_latency" not in model_summary
        assert "part2_resilience_fault_injection" not in model_summary
    serialized_all = json.dumps(all_bench)
    assert serialized_all.count('"tclk_lookup_miss_300_entries"') == 1
    assert serialized_all.count('"nor_flash_brownout_power_loss_fuzzing"') == 1
    _assert_no_forbidden_terms(all_bench)

    with pytest.raises(ValueError, match="Unknown platform"):
        get_zerostack_benchmarks("UNKNOWN_PLATFORM")


def test_mcp_resources_bounded_prompt_and_cli_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    summary_json = json.loads(resource_benchmarks_summary())
    assert summary_json["release"] == ZEROSTACK_RELEASE_NAME
    assert summary_json["marketing_url"] == ZEROSTACK_MARKETING_URL
    _assert_no_forbidden_terms(summary_json)

    models_json = json.loads(resource_supported_models())
    assert models_json["release"] == ZEROSTACK_RELEASE_NAME
    assert len(models_json["models"]) == 8
    assert "OpenThread RCP" not in json.dumps(models_json)
    _assert_no_forbidden_terms(models_json)

    catalog_json = json.loads(resource_diagnostics_catalog())
    assert "signatures" in catalog_json
    assert "remediationMeta" in catalog_json
    _assert_no_forbidden_terms(catalog_json)

    prompt_text = diagnose_zigbee_log("Error: SRSP - AF - dataRequest after 6000ms")
    assert ZEROSTACK_MARKETING_URL in prompt_text
    assert ZEROSTACK_RELEASE_NAME in prompt_text
    _assert_no_forbidden_terms(prompt_text)

    huge_prompt_input = "A" * (MAX_PROMPT_LOG_CHARS * 3)
    bounded_prompt = diagnose_zigbee_log(huge_prompt_input)
    assert len(bounded_prompt) < MAX_PROMPT_LOG_CHARS + 1000
    assert "truncated" in bounded_prompt

    captured_run: dict[str, object] = {}

    def fake_run(transport: str = "stdio", **kwargs: object) -> None:
        captured_run["transport"] = transport
        captured_run["kwargs"] = kwargs

    monkeypatch.setattr("zerostack_mcp.server.mcp.run", fake_run)
    main(["--transport", "streamable-http"])
    assert captured_run["transport"] == "streamable-http"
    assert captured_run["kwargs"] == {
        "host": "127.0.0.1",
        "port": 8000,
        "stateless_http": True,
    }


def test_copyright_attribution_and_spdx_headers() -> None:
    license_path = REPO_ROOT / "LICENSE"
    notice_path = REPO_ROOT / "NOTICE"
    assert license_path.is_file()
    assert notice_path.is_file()

    license_text = license_path.read_text(encoding="utf-8")
    notice_text = notice_path.read_text(encoding="utf-8")
    assert "Apache License" in license_text
    assert "Version 2.0, January 2004" in license_text
    assert "Copyright [yyyy] [name of copyright owner]" in license_text
    assert "Copyright (c) 2026 SMLIGHT" in notice_text
    assert "SMLIGHT" in notice_text and "2026" in notice_text

    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["license-files"] == ["LICENSE", "NOTICE"]

    dockerfile_text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY README.md LICENSE NOTICE ./" in dockerfile_text

    typo_pattern = re.compile(r"sml" + r"ght", re.IGNORECASE)
    for file_path in sorted(REPO_ROOT.rglob("*")):
        if any(
            part in {".git", ".venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
            for part in file_path.parts
        ):
            continue
        if file_path.is_file() and file_path.suffix not in {".pyc", ".png", ".pdf", ".whl"}:
            content = file_path.read_text(encoding="utf-8")
            assert typo_pattern.search(content) is None, f"Typo found in {file_path}"

    expected_spdx = ("# Copyright (c) 2026 SMLIGHT", "# SPDX-License-Identifier: Apache-2.0")
    py_files = list((REPO_ROOT / "src" / "zerostack_mcp").rglob("*.py")) + list(
        (REPO_ROOT / "tests").rglob("*.py")
    )
    assert len(py_files) >= 10
    for py_file in sorted(py_files):
        lines = py_file.read_text(encoding="utf-8").splitlines()
        start_idx = 1 if lines and lines[0].startswith("#!") else 0
        assert tuple(lines[start_idx : start_idx + 2]) == expected_spdx, (
            f"Missing 2-line SPDX header in {py_file.relative_to(REPO_ROOT)}"
        )


def test_prefilter_matches_config_mismatch_and_panid_conflict() -> None:
    res_mismatch = analyze_zigbee_thread_log(
        "warn 2026-10-29: adapter-settings-mismatch detected on startup"
    )
    assert res_mismatch["status"] == "fault_signatures_detected"
    assert res_mismatch["matched_count"] >= 1
    mismatch_ids = {m["signature_id"]: m for m in res_mismatch["matches"]}
    assert "ADAPTER_CONFIG_MISMATCH" in mismatch_ids
    assert mismatch_ids["ADAPTER_CONFIG_MISMATCH"]["remediation_key"] == "issue-config-mismatch"
    _assert_no_forbidden_terms(res_mismatch)

    res_panid = analyze_zigbee_thread_log("Found network with the same panId")
    assert res_panid["status"] == "fault_signatures_detected"
    assert res_panid["matched_count"] >= 1
    panid_ids = {m["signature_id"]: m for m in res_panid["matches"]}
    assert "PAN_ID_CONFLICT" in panid_ids
    assert panid_ids["PAN_ID_CONFLICT"]["remediation_key"] == "issue-pan-conflict"
    _assert_no_forbidden_terms(res_panid)
