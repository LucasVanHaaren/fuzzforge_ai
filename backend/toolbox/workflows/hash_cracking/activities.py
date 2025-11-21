"""
Hash Cracking Workflow Activities
"""

# Copyright (c) 2025 FuzzingLabs
#
# Licensed under the Business Source License 1.1 (BSL). See the LICENSE file
# at the root of this repository for details.
#
# After the Change Date (four years from publication), this version of the
# Licensed Work will be made available under the Apache License, Version 2.0.
# See the LICENSE-APACHE file or http://www.apache.org/licenses/LICENSE-2.0
#
# Additional attribution and requirements are provided in the NOTICE file.

import logging
import sys
from pathlib import Path

from temporalio import activity

# Configure logging
logger = logging.getLogger(__name__)

# Add toolbox to path for module imports
sys.path.insert(0, '/app/toolbox')

@activity.defn
async def run_hashid(workspace_path: str, config: dict) -> dict:
    """
    Hash cracking activity using the hashid module on specified hash.

    This activity:
    1. Imports the reusable hashid module
    2. Executes hashid on specified hash
    3. Returns findings as ModuleResult

    Args:
        workspace_path: Path to the workspace directory (user's uploaded code)
        config: configuration (target_file)

    Returns:
        Fuzzer results dictionary (findings, summary, metadata)
    """
    logger.info(f"Activity: run_hashid (workspace={workspace_path})")

    try:
        # Import reusable unblob module
        from modules.cracking import HashIdIdentifier

        workspace = Path(workspace_path)
        if not workspace.exists():
            raise FileNotFoundError(f"Workspace not found: {workspace_path}")

        # Get activity info for real-time stats
        info = activity.info()
        run_id = info.workflow_id

        # Execute the hashid module
        hashid_identifier = HashIdIdentifier()
        result = await hashid_identifier.execute(config, workspace)

        logger.info(
            f"✓ hashid completed"
        )

        return result.dict()

    except Exception as e:
        logger.error(f"hashid failed: {e}", exc_info=True)
        raise

@activity.defn
async def run_hashcat(workspace_path: str, config: dict) -> dict:
    """
    Hash cracking activity using the hashcat module on specified hash.

    This activity:
    1. Imports the reusable hashcat module
    2. Executes hashcat on specified hash
    3. Returns findings as ModuleResult

    Args:
        workspace_path: Path to the workspace directory (user's uploaded code)
        config: configuration (target_file)

    Returns:
        Fuzzer results dictionary (findings, summary, metadata)
    """
    logger.info(f"Activity: run_hashcat (workspace={workspace_path})")

    try:
        # Import reusable unblob module
        from modules.cracking import Hashcat

        workspace = Path(workspace_path)
        if not workspace.exists():
            raise FileNotFoundError(f"Workspace not found: {workspace_path}")

        # Get activity info for real-time stats
        info = activity.info()
        run_id = info.workflow_id

        # Execute the hashcat module
        hashcat = Hashcat()
        result = await hashcat.execute(config, workspace)

        logger.info(
            f"✓ hashcat completed"
        )

        return result.dict()

    except Exception as e:
        logger.error(f"hashcat failed: {e}", exc_info=True)
        raise

@activity.defn
async def generate_sarif_report_activity(
    analysis_results: dict,
    config: dict,
    workspace_path: str
) -> dict:
    """
    Generate SARIF report from hash_cracking results.

    Args:
        analysis_results: Results from hash_cracking run
        config: Reporter configuration
        workspace_path: Path to the workspace

    Returns:
        SARIF report dictionary
    """
    logger.info("Activity: generate_sarif_report (hash_cracking)")

    try:
        from modules.reporter import SARIFReporter

        workspace = Path(workspace_path)
        # Use only findings from hash_cracking
        findings = analysis_results.get("findings", [])

        reporter_config = {
            **config,
            "findings": findings,
            "tool_name": "hash_cracking",
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
