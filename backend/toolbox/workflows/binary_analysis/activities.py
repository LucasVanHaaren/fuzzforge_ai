"""
Binary Analysis Workflow Activities

Activities specific to the Binary Analysis workflow.
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any
import os

import httpx
from temporalio import activity

# Configure logging
logger = logging.getLogger(__name__)

# Add toolbox to path for module imports
sys.path.insert(0, '/app/toolbox')


@activity.defn
async def run_capa(workspace_path: str, config: dict) -> dict:
    """
    Fuzzing activity using the Capa module on specified binary.

    This activity:
    1. Imports the reusable Capa module
    2. Executes capa on specified binary
    3. Returns findings as ModuleResult

    Args:
        workspace_path: Path to the workspace directory (user's uploaded code)
        config: configuration (target_file)

    Returns:
        Fuzzer results dictionary (findings, summary, metadata)
    """
    logger.info(f"Activity: run_capa (workspace={workspace_path})")

    try:
        # Import reusable Capa module
        from modules.reverse import Capa

        workspace = Path(workspace_path)
        if not workspace.exists():
            raise FileNotFoundError(f"Workspace not found: {workspace_path}")

        # Get activity info for real-time stats
        info = activity.info()
        run_id = info.workflow_id

        # Execute the Capa module
        capa = Capa()
        result = await capa.execute(config, workspace)

        logger.info(
            f"✓ Capa completed"
        )

        return result.dict()

    except Exception as e:
        logger.error(f"Capa failed: {e}", exc_info=True)
        raise


# SARIF report generation for binary_analysis module
@activity.defn(name="generate_sarif_report_binary_analysis")
async def generate_sarif_report_activity(
    analysis_results: dict,
    config: dict,
    workspace_path: str
) -> dict:
    """
    Generate SARIF report from binary_analysis results.

    Args:
        analysis_results: Results from binary_analysis run
        config: Reporter configuration
        workspace_path: Path to the workspace

    Returns:
        SARIF report dictionary
    """
    logger.info("Activity: generate_sarif_report (binary_analysis)")

    try:
        from modules.reporter import SARIFReporter

        workspace = Path(workspace_path)
        # Use only findings from binary_analysis
        findings = analysis_results.get("findings", [])

        reporter_config = {
            **config,
            "findings": findings,
            "tool_name": "capa",
            "tool_version": "1.0.0"
        }

        reporter = SARIFReporter()
        result = await reporter.execute(reporter_config, workspace)

        sarif = result.dict().get("sarif", {})

        logger.info(f"\u2713 SARIF report generated with {len(findings)} findings")
        return sarif

    except Exception as e:
        logger.error(f"SARIF report generation failed: {e}", exc_info=True)
        raise
