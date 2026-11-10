# Copyright (c) 2026 SMLIGHT
# SPDX-License-Identifier: Apache-2.0

"""ZeroStack MCP Server — AI-assisted wireless diagnostics and silicon decoder."""

from __future__ import annotations

from zerostack_mcp.catalog import load_diagnostics_catalog, load_remediation_meta
from zerostack_mcp.models import (
    CANONICAL_DIAGNOSTIC_URLS,
    MCP_SERVER_VERSION,
    ZEROSTACK_FIRMWARE_VERSION,
    ZEROSTACK_MARKETING_URL,
    ZEROSTACK_RELEASE_NAME,
    ZEROSTACK_REPO_URL,
    ZEROSTACK_WEB_ANALYZER_URL,
    __version__,
)
from zerostack_mcp.server import (
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

__all__ = [
    "CANONICAL_DIAGNOSTIC_URLS",
    "MCP_SERVER_VERSION",
    "ZEROSTACK_FIRMWARE_VERSION",
    "ZEROSTACK_FIRMWARE_VERSION",
    "ZEROSTACK_MARKETING_URL",
    "ZEROSTACK_RELEASE_NAME",
    "ZEROSTACK_REPO_URL",
    "ZEROSTACK_WEB_ANALYZER_URL",
    "__version__",
    "analyze_zigbee_thread_log",
    "check_coordinator_capacity",
    "decode_silicon_register",
    "diagnose_zigbee_log",
    "get_zerostack_benchmarks",
    "load_diagnostics_catalog",
    "load_remediation_meta",
    "main",
    "mcp",
    "resource_benchmarks_summary",
    "resource_diagnostics_catalog",
    "resource_supported_models",
]
