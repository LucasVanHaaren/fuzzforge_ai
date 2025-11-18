"""
Hash Identification Module

Decompiles Android APK files to Java source code using Jadx.
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

import asyncio
import shutil
import logging
from hashid import HashID
from pathlib import Path
from typing import Dict, Any

try:
    from toolbox.modules.base import BaseModule, ModuleMetadata, ModuleResult
except ImportError:
    try:
        from modules.base import BaseModule, ModuleMetadata, ModuleResult
    except ImportError:
        from src.toolbox.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = logging.getLogger(__name__)


class HashIdIdentifier(BaseModule):
    """Module for decompiling APK files to Java source code using Jadx"""

    def get_metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="hashid",
            version="1.0.0",
            description="Identify hash types using hashid library",
            author="FuzzForge Team",
            category="cracking",
            tags=["cracking"],
            input_schema={
                "type": "object",
                "properties": {
                    "hash": {
                        "type": "string",
                        "description": "Hash string to identify",
                    }
                },
                "required": ["hash"],
            },
            output_schema={
                "type": "object",
                "properties": {
                    "output_dir": {
                        "type": "string",
                        "description": "Path to decompiled output directory",
                    },
                },
            },
            requires_workspace=True,
        )

    def validate_config(self, config: Dict[str, Any]) -> bool:
        """Validate module configuration"""
        hash_str = config.get("hash")
        if not hash_str:
            raise ValueError("'hash' must be provided for hash identification")

        return True

    def execute(self, config: Dict[str, Any], workspace: Path) -> ModuleResult:
        """
        Execute Hash Identification on a hash string.

        Args:
            config: Configuration dict with hash, output_dir, etc.
            workspace: Workspace directory path

        Returns:
            ModuleResult with decompilation summary and metadata
        """
        self.start_timer()

        try:
            self.validate_config(config)
            self.validate_workspace(workspace)

            workspace = workspace.resolve()

            # Compute
            hash_str = config["hash"]
            hashid = HashID()
            results = list(hashid.identifyHash(hash_str))
            # returns a list of HashInfo named tuples

            # Create ModuleFinding objects for each identified hash type
            findings = []
            for idx, hash_info in enumerate(results):
                finding = self.create_finding(
                    title=f"Possible Hash Type: {hash_info.name}",
                    description=f"The hash '{hash_str}' may be of type: {hash_info.name}",
                    severity="info",
                    category="hash_identification",
                    metadata={
                        "hash_input": hash_str,
                        "identified_type": hash_info.name,
                        "match_index": idx,
                        "hashcat_mode": hash_info.hashcat,
                        "john_mode": hash_info.john,
                        "extended": hash_info.extended,
                    }
                )
                findings.append(finding)

            # Create summary
            summary = {
                "possible_hash_types": [h.name for h in results],
                "total_matches": len(results),
            }

            logger.info(
                f"✓ Hash identification completed with {len(findings)} possible types"
            )

            return self.create_result(
                findings=findings,
                status="success",
                summary=summary,
                metadata={
                    "hash_length": len(hash_str),
                    "hash_input": hash_str,
                },
            )

        except Exception as exc:
            logger.error(f"Hash identification failed: {exc}", exc_info=True)
            return self.create_result(
                findings=[],
                status="failed",
                error=str(exc),
            )
