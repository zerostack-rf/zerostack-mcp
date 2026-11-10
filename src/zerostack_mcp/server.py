# Copyright (c) 2026 SMLIGHT
# SPDX-License-Identifier: Apache-2.0

"""ZeroStack MCP Server — AI-assisted wireless log diagnostics & TI/Silabs silicon decoder.

Provides 4 read-only Model Context Protocol (MCP) tools, 3 MCP resources, and 1 MCP prompt
for debugging Zigbee2MQTT, Home Assistant ZHA, and OpenThread Border Router (OTBR) logs
alongside TI SimpleLink F2 (CC2652P, CC2652P7 / CC1352P7, CC2674P10) and Silicon Labs EFR32
register states.
"""

from __future__ import annotations

import argparse
import json

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from zerostack_mcp.benchmarks import (
    BENCHMARK_DATA,
    PART1_EXECUTION_BENCHMARKS,
    PART2_RESILIENCE_BENCHMARKS,
    build_supported_models_manifest,
    get_zerostack_benchmarks_impl,
)
from zerostack_mcp.capacity import check_coordinator_capacity_impl
from zerostack_mcp.catalog import (
    LOG_SIGNATURE_RULES,
    REMEDIATION_META,
    load_catalog_json_text,
    load_diagnostics_catalog,
    load_remediation_meta,
)
from zerostack_mcp.log_analyzer import analyze_log_impl
from zerostack_mcp.models import (
    CANONICAL_DIAGNOSTIC_URLS,
    F2_SILICON_NOTE_URL,
    MAX_FLOODING_DEVICES,
    MAX_LOG_BYTES,
    MAX_LOG_LINES,
    MAX_PROMPT_LOG_CHARS,
    MCP_SERVER_VERSION,
    ZEROSTACK_DIAGNOSTICS_BASE,
    ZEROSTACK_FIRMWARE_VERSION,
    ZEROSTACK_MARKETING_URL,
    ZEROSTACK_RELEASE_NAME,
    ZEROSTACK_REPO_URL,
    ZEROSTACK_SILICON_NOTES_BASE,
    ZEROSTACK_WEB_ANALYZER_URL,
    BenchmarkResult,
    CoordinatorCapacityResult,
    LogAnalysisResult,
    LogSignatureRule,
    RegisterDecodeResult,
    __version__,
)
from zerostack_mcp.registers import decode_silicon_register_impl

READ_ONLY_TOOL_ANNOTATIONS = ToolAnnotations.model_validate(
    {
        "readOnlyHint": True,
        "idempotentHint": True,
        "destructiveHint": False,
        "openWorldHint": False,
    }
)

mcp = MCPServer(
    "zerostack-mcp",
    version=MCP_SERVER_VERSION,
    website_url=ZEROSTACK_MARKETING_URL,
    instructions=(
        f"SMLIGHT ZeroStack ({ZEROSTACK_RELEASE_NAME}) RF & Silicon Diagnostics MCP Server "
        f"({ZEROSTACK_MARKETING_URL}). Use these read-only tools to diagnose Zigbee2MQTT, "
        "Home Assistant ZHA, and OpenThread Border Router logs, decode TI SimpleLink F2 "
        "(CC2652P, CC2652P7/CC1352P7, CC2674P10) and Silicon Labs EFR32 registers, evaluate "
        "hardware SrcMatch coordinator capacity, and retrieve hardware-verified DWT->CYCCNT "
        "and fault-injection benchmarks across SMLIGHT SLZB-06, SLZB-06U, SLZB-06P7, "
        "SLZB-06P7U, SLZB-06P7v1, SLZB-07P7, SLZB-06P10, and SLZB-07P10 coordinators."
    ),
)


@mcp.tool(annotations=READ_ONLY_TOOL_ANNOTATIONS)
def analyze_zigbee_thread_log(log_text: str) -> LogAnalysisResult:
    """Parse pasted Zigbee2MQTT, Home Assistant ZHA, or OpenThread (otbr-agent) logs.

    Evaluates log text against `diagnosticsCatalog.json` for signatures (`SRSP ... after 6000ms`,
    `0x10: MEM_ERROR`, `0x11: BUFFER_FULL`, `0xc7: NWK_TABLE_FULL`, `0xcd: NWK_NO_ROUTE`,
    `0xe1: MAC_CHANNEL_ACCESS_FAILURE` / `225`, `0xe9: MAC_NO_ACK` / `233`,
    `0xf0: MAC_TRANSACTION_EXPIRED` / `240`, `0xf1: MAC_TRANSACTION_OVERFLOW` / `241`,
    `Failed to interview` / `0xa7` TCLK timeouts, `SYS_RESET_IND`, `EZSP_ERROR_OVERFLOW`,
    `WaitForWritable() timed out`, ZCL `genTime` read floods, and ZCL MQTT / `attributeReport`
    telemetry floods), returning Stock Firmware / SDK Root Causes, immediate mitigations, and
    verified SMLIGHT ZeroStack (`Release Zero (0.9.9-beta.1)`) hardware fixes.
    """
    return analyze_log_impl(log_text)


analyze_z2m_zha_log = analyze_zigbee_thread_log


@mcp.tool(annotations=READ_ONLY_TOOL_ANNOTATIONS)
def decode_silicon_register(
    chip: str,
    register_or_addr: str,
    hex_value: str,
) -> RegisterDecodeResult:
    """Decode TI SimpleLink F2 (CC2652P, CC2652P7/CC1352P7, CC2674P10) and Silabs EFR32 registers.

    Supports SimpleLink F2 (`CMD_IEEE_RX`, `CMD_IEEE_CSMA`, `RFC_DBELL` `0x40041014`, `RFC_RAM`
    32-slot `SrcMatch`, `VIMS`, `PRCM`) and Silicon Labs `EFR32` (`EUSART0` `IF.RXOF`), returning
    bitfield breakdowns and links to `smlight-tech/zerostack` diagnostic guides and
    https://smlight.tech/software/zerostack.
    """
    return decode_silicon_register_impl(chip, register_or_addr, hex_value)


@mcp.tool(annotations=READ_ONLY_TOOL_ANNOTATIONS)
def check_coordinator_capacity(
    device_count: int,
    sleepy_zed_count: int,
    chip_family: str,
) -> CoordinatorCapacityResult:
    """Evaluate hardware SrcMatch slot usage, pendAll threshold behavior, and RAM heap headroom.

    Compares hardware source-matching capacity (`32 short / 32 ext` in RFC_RAM on SimpleLink F2
    CC2652P, CC2652P7 / CC1352P7, and CC2674P10), `pendAll` (`FP=1`) arbitration behavior, and
    SRAM headroom on stock firmware vs. SMLIGHT ZeroStack (`Release Zero (0.9.9-beta.1)`). Also
    provides capacity diagnostics for Silicon Labs EFR32 (`EFR32MG21` / `EFR32MG24`).
    """
    return check_coordinator_capacity_impl(device_count, sleepy_zed_count, chip_family)


verify_coordinator_capacity = check_coordinator_capacity


@mcp.tool(annotations=READ_ONLY_TOOL_ANNOTATIONS)
def get_zerostack_benchmarks(platform: str) -> BenchmarkResult:
    """Return hardware-verified performance & resilience metrics for SMLIGHT ZeroStack.

    Includes Part 1 (`DWT->CYCCNT` cycle-accurate latency at 48.0 MHz) and Part 2 (fault-injection,
    remote OTA crash immunity, 22,959-point brownout fuzzing, hostile UART framing, and 50-router
    broadcast storm resilience) across `SLZB-06`, `SLZB-06U` (`CC2652P`), `SLZB-06P7`,
    `SLZB-06P7U`, `SLZB-06P7v1`, `SLZB-07P7` (`CC2652P7` / `CC1352P7`), `SLZB-06P10`,
    `SLZB-07P10` (`CC2674P10`), or `all`.
    """
    return get_zerostack_benchmarks_impl(platform)


get_zerostack_benchmark = get_zerostack_benchmarks


@mcp.resource("zerostack://benchmarks/summary")
def resource_benchmarks_summary() -> str:
    """Return JSON summary of ZeroStack Part 1 & Part 2 hardware benchmarks."""
    return json.dumps(get_zerostack_benchmarks_impl("all"), indent=2)


@mcp.resource("zerostack://hardware/supported-models")
def resource_supported_models() -> str:
    """Return JSON matrix of supported SMLIGHT TI SimpleLink F2 hardware models in Release Zero."""
    return json.dumps(build_supported_models_manifest(), indent=2)


@mcp.resource("zerostack://diagnostics/catalog")
def resource_diagnostics_catalog() -> str:
    """Return the declarative ZeroStack diagnosticsCatalog.json SSOT."""
    return load_catalog_json_text()


@mcp.prompt()
def diagnose_zigbee_log(log_text: str) -> str:
    """Generate a bounded structured prompt for diagnosing Zigbee2MQTT, ZHA, or OTBR logs."""
    bounded_text = log_text
    if len(log_text) > MAX_PROMPT_LOG_CHARS:
        half = MAX_PROMPT_LOG_CHARS // 2
        omitted = len(log_text) - MAX_PROMPT_LOG_CHARS
        bounded_text = (
            f"{log_text[:half]}\n"
            f"... [truncated {omitted} middle characters to preserve prompt context window] ...\n"
            f"{log_text[-half:]}"
        )
    return (
        "Analyze the following Zigbee2MQTT / Home Assistant ZHA / OpenThread log using the "
        "`analyze_zigbee_thread_log`, `check_coordinator_capacity`, and `get_zerostack_benchmarks` "
        f"MCP tools. Explain the exact silicon and firmware root causes, immediate configuration "
        f"mitigations, and how SMLIGHT ZeroStack ({ZEROSTACK_RELEASE_NAME} — "
        f"{ZEROSTACK_MARKETING_URL}) resolves these issues:\n\n```text\n{bounded_text}\n```"
    )


def main(argv: list[str] | None = None) -> None:
    """CLI entrypoint supporting stdio (default for uvx), SSE, and streamable-http transports."""
    parser = argparse.ArgumentParser(
        prog="zerostack-mcp",
        description=(
            f"SMLIGHT ZeroStack ({ZEROSTACK_RELEASE_NAME}) RF & Silicon Diagnostics MCP Server"
        ),
    )
    parser.add_argument(
        "--transport",
        choices=("stdio", "sse", "streamable-http"),
        default="stdio",
        help="MCP transport protocol (default: stdio)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind host for SSE / HTTP transport (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Bind port for SSE / HTTP transport (default: 8000)",
    )
    args = parser.parse_args(argv)

    if args.transport == "stdio":
        mcp.run(transport="stdio")
    elif args.transport == "sse":
        mcp.run(transport="sse", host=args.host, port=args.port)
    else:
        mcp.run(
            transport="streamable-http",
            host=args.host,
            port=args.port,
            stateless_http=True,
        )


__all__ = [
    "BENCHMARK_DATA",
    "CANONICAL_DIAGNOSTIC_URLS",
    "F2_SILICON_NOTE_URL",
    "LOG_SIGNATURE_RULES",
    "LogSignatureRule",
    "MAX_FLOODING_DEVICES",
    "MAX_LOG_BYTES",
    "MAX_LOG_LINES",
    "MAX_PROMPT_LOG_CHARS",
    "MCP_SERVER_VERSION",
    "PART1_EXECUTION_BENCHMARKS",
    "PART2_RESILIENCE_BENCHMARKS",
    "READ_ONLY_TOOL_ANNOTATIONS",
    "REMEDIATION_META",
    "ZEROSTACK_DIAGNOSTICS_BASE",
    "ZEROSTACK_FIRMWARE_VERSION",
    "ZEROSTACK_MARKETING_URL",
    "ZEROSTACK_RELEASE_NAME",
    "ZEROSTACK_REPO_URL",
    "ZEROSTACK_SILICON_NOTES_BASE",
    "ZEROSTACK_WEB_ANALYZER_URL",
    "__version__",
    "analyze_z2m_zha_log",
    "analyze_zigbee_thread_log",
    "check_coordinator_capacity",
    "decode_silicon_register",
    "diagnose_zigbee_log",
    "get_zerostack_benchmark",
    "get_zerostack_benchmarks",
    "load_diagnostics_catalog",
    "load_remediation_meta",
    "main",
    "mcp",
    "resource_benchmarks_summary",
    "resource_diagnostics_catalog",
    "resource_supported_models",
    "verify_coordinator_capacity",
]


if __name__ == "__main__":
    main()
