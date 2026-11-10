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
from typing import Annotated

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field

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
def analyze_zigbee_thread_log(
    log_text: Annotated[
        str,
        Field(
            description=(
                "Raw multi-line log text from Zigbee2MQTT (`zigbee-herdsman`), Home Assistant ZHA "
                "(`zigpy`/`bellows`/`zigpy-znp`), or OpenThread (`otbr-agent`). Inputs exceeding "
                "2 MB (`MAX_LOG_BYTES`) or 25,000 lines (`MAX_LOG_LINES`) are deterministically "
                "windowed to head + tail slices with `truncated=true`. Empty or whitespace-only "
                "input returns `status='empty_input'`."
            ),
            examples=[
                "error 2026-10-29 12:00:00: SREQ AF_DataRequest failed with 0x10: MEM_ERROR",
                "zh:zstack:unpi: Default response timeout: SRSP - AF - dataRequest after 6000ms",
            ],
        ),
    ],
) -> LogAnalysisResult:
    """Analyze pasted Zigbee2MQTT, Home Assistant ZHA, or OpenThread logs for fault signatures.

    When to use:
    - Use this tool when diagnosing runtime error logs, adapter timeouts (`SRSP ... after 6000ms`),
      MAC/NWK/APS status codes (`0x10`, `0x11`, `0xc7`, `0xcd`, `0xe1`/`225`, `0xe9`/`233`,
      `0xf0`/`240`, `0xf1`/`241`), interview failures (`0xa7`), or ZCL telemetry/`genTime` floods.
    - Do NOT use for decoding raw hexadecimal MCU register words (`decode_silicon_register`),
      sizing network capacity (`check_coordinator_capacity`), or querying hardware benchmark
      tables (`get_zerostack_benchmarks`).

    Behavior:
    - Executes deterministically offline with zero network or serial I/O.
    - Ranks detected faults by severity and root-cause priority (`ZNP_SYS_RESET_IND` > lockstep
      timeouts > memory/buffer exhaustion > RF delivery symptoms) and returns stock SDK root
      causes, immediate workarounds, and SMLIGHT ZeroStack (`Release Zero (0.9.9-beta.1)`) fixes.
    """
    return analyze_log_impl(log_text)


analyze_z2m_zha_log = analyze_zigbee_thread_log


@mcp.tool(annotations=READ_ONLY_TOOL_ANNOTATIONS)
def decode_silicon_register(
    chip: Annotated[
        str,
        Field(
            description=(
                "Target MCU family, SoC part number, or SMLIGHT coordinator SKU "
                "(case-insensitive). Accepted TI SimpleLink F2 tokens: `'F2'`, `'CC2652P'`, "
                "`'CC2652P7'`, `'CC1352P7'`, `'CC2674P10'`, `'P7'`, `'P10'`, `'SLZB-06'`, "
                "`'SLZB-06U'`, `'SLZB-06P7'`, `'SLZB-06P7U'`, `'SLZB-06P7v1'`, `'SLZB-07P7'`, "
                "`'SLZB-06P10'`, `'SLZB-07P10'`. Accepted Silicon Labs EFR32 tokens: `'EFR32'`, "
                "`'EFR32MG21'`, `'EFR32MG24'`, `'MG21'`, `'MG24'`, `'SILABS'`, `'EMBER'`, "
                "`'SLZB-06M'`, `'SLZB-06Mg24'`."
            ),
            examples=["CC2652P7", "SLZB-06P10", "EFR32MG21"],
        ),
    ],
    register_or_addr: Annotated[
        str,
        Field(
            description=(
                "Register symbol, radio command name, or MMIO hex address supported for `chip` "
                "(case-insensitive). Accepted TI SimpleLink F2 values: `'CMD_IEEE_RX'` "
                "(`'IEEERX'`, `'RX_STATUS'`), `'CMD_IEEE_CSMA'` (`'IEEECSMA'`, `'CSMA'`), "
                "`'RFC_DBELL'` (`'RFCPEIEN'`, `'0x40041014'`), `'SRCMATCH'` (`'SRC_MATCH'`, "
                "`'RFC_RAM'`, `'0x20001060'`), `'VIMS'` (`'VIMS_STAT'`, `'0x40034000'`), "
                "`'PRCM'` (`'PRCM_RFCMODEHWOPT'`, `'0x400821D0'`). Accepted Silicon Labs EFR32 "
                "values: `'EUSART0_IF'` (`'EUSART0:IF'`, `'EUSART'`)."
            ),
            examples=["CMD_IEEE_RX", "RFC_DBELL", "0x40041014", "SRCMATCH", "EUSART0_IF"],
        ),
    ],
    hex_value: Annotated[
        str,
        Field(
            description=(
                "Observed 16-bit or 32-bit register or radio command status value as a hexadecimal "
                "string (with or without `'0x'` prefix, e.g. `'0x0807'`, `'0x2401'`, "
                "`'0x00000001'`, `'0xFFFFFFFF'`, `'0x08'`)."
            ),
            examples=["0x0807", "0x2401", "0x00000001", "0xFFFFFFFF", "0x08"],
        ),
    ],
) -> RegisterDecodeResult:
    """Decode a hexadecimal MCU register or radio-core command status word into bitfields.

    When to use:
    - Use this tool when inspecting a specific TI SimpleLink F2 (`CMD_IEEE_RX`, `CMD_IEEE_CSMA`,
      `RFC_DBELL` `0x40041014`, `SRCMATCH`, `VIMS`, `PRCM`) or Silicon Labs EFR32 (`EUSART0_IF`)
      hex register/status value captured from a debugger, crash dump, or telemetry read.
    - Do NOT use for parsing multi-line host application logs (`analyze_zigbee_thread_log`) or
      evaluating mesh node counts (`check_coordinator_capacity`).

    Behavior:
    - Executes deterministically offline with zero hardware or network I/O.
    - Returns decoded bitfield flags, boolean `healthy` status, root-cause diagnosis, and links
      to silicon errata notes; raises `ValueError` on unsupported `chip` or `register_or_addr`
      identifiers or unparseable `hex_value` strings.
    """
    return decode_silicon_register_impl(chip, register_or_addr, hex_value)


@mcp.tool(annotations=READ_ONLY_TOOL_ANNOTATIONS)
def check_coordinator_capacity(
    device_count: Annotated[
        int,
        Field(
            ge=0,
            description=(
                "Total Zigbee nodes joined to the mesh network (mains-powered routers + "
                "battery-powered sleepy end devices, excluding the coordinator itself). "
                "Must be an integer >= 0 and >= `sleepy_zed_count`."
            ),
            examples=[45, 120, 180],
        ),
    ],
    sleepy_zed_count: Annotated[
        int,
        Field(
            ge=0,
            description=(
                "Number of battery-powered / RX-off-when-idle Zigbee End Devices (ZEDs) directly "
                "parented to the coordinator that occupy hardware `SrcMatch` indirect-queue slots. "
                "Must satisfy `0 <= sleepy_zed_count <= device_count`."
            ),
            examples=[20, 36],
        ),
    ],
    chip_family: Annotated[
        str,
        Field(
            description=(
                "Coordinator SoC family or SMLIGHT model identifier (case-insensitive). "
                "Accepted TI SimpleLink F2 values: `'F2_CC1352_CC2652'`, `'F2'`, `'CC2652P'`, "
                "`'CC2652P7'`, `'CC1352P7'`, `'CC2674P10'`, `'P7'`, `'P10'`, `'SLZB-06'`, "
                "`'SLZB-06U'`, `'SLZB-06P7'`, `'SLZB-06P7U'`, `'SLZB-06P7v1'`, `'SLZB-07P7'`, "
                "`'SLZB-06P10'`, `'SLZB-07P10'`. Accepted Silicon Labs EFR32 values: "
                "`'SILABS_EFR32'`, `'EFR32'`, `'EFR32MG21'`, `'EFR32MG24'`, `'MG21'`, `'MG24'`, "
                "`'SILABS'`, `'EMBER'`, `'SLZB-06M'`, `'SLZB-06Mg24'`."
            ),
            examples=["F2_CC1352_CC2652", "SLZB-06P7", "SLZB-06P10", "SILABS_EFR32", "EFR32MG21"],
        ),
    ],
) -> CoordinatorCapacityResult:
    """Calculate hardware SrcMatch slot utilization, pendAll threshold, and SRAM heap headroom.

    When to use:
    - Use this tool for capacity planning and topology sizing given `(device_count,
      sleepy_zed_count, chip_family)` to evaluate 32-slot `RFC_RAM` `SrcMatch` exhaustion,
      `pendAll` (`FP=1`) promotion when `sleepy_zed_count > 32`, indirect queue quota isolation,
      and SRAM headroom (`88 KB` / `144 KB` / `256 KB`).
    - Do NOT use for parsing runtime logs (`analyze_zigbee_thread_log`), decoding register hex
      values (`decode_silicon_register`), or fetching `DWT->CYCCNT` latency benchmarks
      (`get_zerostack_benchmarks`).

    Behavior:
    - Executes deterministically offline; derives `router_count = device_count - sleepy_zed_count`.
    - Raises `ValueError` if `device_count < 0`, `sleepy_zed_count < 0`,
      `sleepy_zed_count > device_count`, or `chip_family` is unrecognized.
    """
    return check_coordinator_capacity_impl(device_count, sleepy_zed_count, chip_family)


verify_coordinator_capacity = check_coordinator_capacity


@mcp.tool(annotations=READ_ONLY_TOOL_ANNOTATIONS)
def get_zerostack_benchmarks(
    platform: Annotated[
        str,
        Field(
            description=(
                "SMLIGHT coordinator SKU to query, or `'all'` for the full cross-platform "
                "comparison matrix (case-insensitive). Accepted values: `'SLZB-06'`, `'SLZB-06U'`, "
                "`'SLZB-06P7'`, `'SLZB-06P7U'`, `'SLZB-06P7v1'`, `'SLZB-07P7'`, `'SLZB-06P10'`, "
                "`'SLZB-07P10'`, or `'all'` (also accepts SoC shorthand `'CC2652P'`, `'CC2652P7'`, "
                "`'CC1352P7'`, `'CC2674P10'`, `'P7'`, `'P10'`, `'*'`)."
            ),
            examples=["SLZB-06P10", "SLZB-06P7", "SLZB-06", "all"],
        ),
    ],
) -> BenchmarkResult:
    """Retrieve hardware-verified DWT->CYCCNT latency and fault-injection benchmarks by SKU.

    When to use:
    - Use this tool to query hardware specifications (CPU, Flash/SRAM, DIO10/DIO11 RTS/CTS wiring,
      supported baud rates) and cycle-accurate Part 1 execution latencies (`TCLK` lookup, `NWK`
      encrypt/decrypt, routed hop ceiling, `O(1)` allocator) plus Part 2 adversarial resilience
      metrics (3,255 MAC vectors, 22,959 brownout cut points, UART framing abuse, 50-router
      broadcast storms) for an SMLIGHT coordinator model or `'all'`.
    - Do NOT use for sizing a user's specific mesh node count (`check_coordinator_capacity`) or
      diagnosing pasted log text (`analyze_zigbee_thread_log`).

    Behavior:
    - Executes deterministically offline with zero network or hardware I/O.
    - Raises `ValueError` if `platform` does not match a supported SMLIGHT SKU or `'all'`.
    """
    return get_zerostack_benchmarks_impl(platform)


get_zerostack_benchmark = get_zerostack_benchmarks


@mcp.resource("zerostack://benchmarks/summary", mime_type="application/json")
def resource_benchmarks_summary() -> str:
    """Return JSON summary of ZeroStack Part 1 & Part 2 hardware benchmarks."""
    return json.dumps(get_zerostack_benchmarks_impl("all"), indent=2)


@mcp.resource("zerostack://hardware/supported-models", mime_type="application/json")
def resource_supported_models() -> str:
    """Return JSON matrix of supported SMLIGHT TI SimpleLink F2 hardware models in Release Zero."""
    return json.dumps(build_supported_models_manifest(), indent=2)


@mcp.resource("zerostack://diagnostics/catalog", mime_type="application/json")
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
