"""
Hashcat Module

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


class Hashcat(BaseModule):
    """Module for decompiling APK files to Java source code using Jadx"""

    def get_metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="hashcat",
            version="1.0.0",
            description="Run hashcat to crack hashes",
            author="FuzzForge Team",
            category="cracking",
            tags=["cracking"],
            input_schema={
                "type": "object",
                "properties": {
                    "hash": {
                        "type": "string",
                        "description": "Hash string to crack",
                    }, 
                    "hash_type": {
                        "type": "integer",
                        "description": "Hashcat hash type identifier",
                    },
                },
                "required": ["hash", "hash_type"],
            },
            output_schema={
                "type": "object",
                "properties": {
                    "plaintext": {
                        "type": "string",
                        "description": "Cracked plaintext result",
                    }
                },
            },
            requires_workspace=True,
        )

    def validate_config(self, config: Dict[str, Any]) -> bool:
        """Validate module configuration"""
        hash_str = config.get("hash")
        if not hash_str:
            raise ValueError("'hash' must be provided for hashcat cracking")

        hash_type = config.get("hash_type")
        if hash_type is None:
            raise ValueError("'hash_type' must be provided for hashcat cracking")

        return True

    async def execute(self, config: Dict[str, Any], workspace: Path) -> ModuleResult:
        """
        Execute hashcat to crack a given hash.

        Args:
            config: Configuration dict with hash, hash_type, etc.
            workspace: Workspace directory path

        Returns:
            ModuleResult with decompilation summary and metadata
        """
        self.start_timer()

        try:
            self.validate_config(config)
            self.validate_workspace(workspace)

            workspace = workspace.resolve()

            hash_str = config.get("hash")
            hash_type = str(config.get("hash_type"))

            potfile_path = workspace / "jack.pot"

            cmd = [
                "hashcat",
                "-a", "0",  # Attack mode: Straight
                "-m", hash_type,  # Hash type
                "--potfile-disable",  # Disable potfile
                "--quiet",  # Suppress output
                "--outfile", str(potfile_path),  # Output file
                "--outfile-format", "2",  # Output only cracked hashes
                hash_str,
                "/usr/share/wordlists/SecLists-master/Passwords/Leaked-Databases/rockyou.txt.tar.gz",  # Wordlist
            ]

            logger.info(f"Running Hashcat: {' '.join(cmd)}")

            # Execute Hashcat
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(workspace),
            )

            stdout, stderr = await process.communicate()
            stdout_str = stdout.decode(errors="ignore") if stdout else ""
            stderr_str = stderr.decode(errors="ignore") if stderr else ""

            if stdout_str:
                logger.debug(f"Hashcat stdout: {stdout_str[:200]}...")
            if stderr_str:
                logger.debug(f"Hashcat stderr: {stderr_str[:200]}...")

            if process.returncode != 0:
                error_output = stderr_str or stdout_str or "No error output"
                raise RuntimeError(
                    f"Hashcat failed with exit code {process.returncode}: {error_output[:500]}"
                )

            if not Path(potfile_path).exists():
                logger.warning(
                    f"Hashcat potfile not found at expected path: {potfile_path}"
                )

            # Read cracked result from potfile
            plaintext = ""
            if potfile_path.exists():
                with open(potfile_path, "r", encoding="utf-8", errors="ignore") as f:
                    plaintext = f.readline().strip()

            # Create summary
            summary = {
                "plaintext": plaintext,
            }

            logger.info(
                f"✓ Hashcat cracking completed, plaintext found"
            )

            return self.create_result(
                findings=[self.create_finding(
                    title="Cracked Hash",
                    description=f"The hash '{hash_str}' was cracked to: {plaintext}",
                    severity="critical",
                    category="cracking",
                    metadata={
                        "hash_input": hash_str,
                        "hash_type": hash_type,
                        "plaintext": plaintext,
                    }
                )],
                status="success",
                summary=summary,
                metadata={},
            )

        except Exception as exc:
            logger.error(f"Hashcat cracking failed: {exc}", exc_info=True)
            return self.create_result(
                findings=[],
                status="failed",
                error=str(exc),
                metadata={"module": "hashcat", "hash_input": config.get("hash")},
            )
