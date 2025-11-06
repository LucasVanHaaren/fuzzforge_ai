"""
Capa Capability Detection Module

This module uses capa (FLARE Team) to detect capabilities in executable files.
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
import json
import logging
from pathlib import Path
from typing import Dict, Any, List

try:
    from toolbox.modules.base import BaseModule, ModuleMetadata, ModuleResult
except ImportError:
    try:
        from modules.base import BaseModule, ModuleMetadata, ModuleResult
    except ImportError:
        from ..base import BaseModule, ModuleMetadata, ModuleResult

logger = logging.getLogger(__name__)


class Capa(BaseModule):
    """Capa capability detection module for executable files"""

    def get_metadata(self) -> ModuleMetadata:
        """Get module metadata"""
        return ModuleMetadata(
            name="capa",
            version="1.0.0",
            description="Detects capabilities in executable files using FLARE Team's capa tool",
            author="FuzzForge Team",
            category="reverse",
            tags=["reverse", "capabilities"],
            input_schema={
                "type": "object",
                "properties": {
                    "target_file": {
                        "type": "string",
                        "description": "Path to the executable file to analyze (relative to workspace)"
                    }
                }
            },
            output_schema={
                "type": "object",
                "properties": {
                    "findings": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "capability": {"type": "string"},
                                "category": {"type": "string"},
                                "description": {"type": "string"}
                            }
                        }
                    }
                }
            }
        )

    def validate_config(self, config: Dict[str, Any]) -> bool:
        """Validate configuration"""
        if "target_file" not in config:
            raise ValueError("target_file is required in configuration")
        return True

    async def execute(self, config: Dict[str, Any], workspace: Path) -> ModuleResult:
        """Execute capa capability detection"""
        self.start_timer()

        try:
            # Validate inputs
            self.validate_config(config)
            self.validate_workspace(workspace)

            # Get target file path
            target_file = config.get("target_file")
            target_path = workspace / target_file
            
            # Check if target file exists
            if not target_path.exists():
                error_msg = f"Target file not found: {target_file}"
                logger.error(error_msg)
                return self.create_result(
                    findings=[],
                    status="failed",
                    error=error_msg
                )
            
            if not target_path.is_file():
                error_msg = f"Target path is not a file: {target_file}"
                logger.error(error_msg)
                return self.create_result(
                    findings=[],
                    status="failed",
                    error=error_msg
                )

            logger.info(f"Running capa on {target_file}")

            # Build capa command with JSON output
            cmd = ["capa", str(target_path), "--json"]

            logger.debug(f"Running command: {' '.join(cmd)}")

            # Run capa
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=workspace
            )

            stdout, stderr = await process.communicate()

            # Check if capa execution was successful
            if process.returncode != 0:
                error_msg = stderr.decode() if stderr else "Unknown error"
                logger.error(f"capa failed: {error_msg}")
                return self.create_result(
                    findings=[],
                    status="failed",
                    error=f"capa execution failed: {error_msg}"
                )

            # Parse JSON output
            output = stdout.decode().strip()
            print(output) # debug
            findings = self._parse_capa_output(output, target_file)

            # Create summary
            summary = {
                "target_file": target_file,
                "capabilities_found": len(findings),
                "analysis_completed": True
            }

            logger.info(f"capa analysis completed: found {len(findings)} capabilities")

            return self.create_result(
                findings=findings,
                status="success",
                summary=summary
            )

        except FileNotFoundError:
            error_msg = "capa binary not found"
            logger.error(error_msg)
            return self.create_result(
                findings=[],
                status="failed",
                error=error_msg
            )
        
        except Exception as e:
            logger.error(f"capa module failed: {e}")
            return self.create_result(
                findings=[],
                status="failed",
                error=str(e)
            )

    def _parse_capa_output(self, output: str, target_file: str) -> List:
        """Parse capa JSON output into findings"""
        findings = []

        if not output.strip():
            return findings

        try:
            # Parse JSON output from capa
            results = json.loads(output)
            
            # Capa output has a "rules" section with detected capabilities
            rules = results.get("rules", {})
            
            for rule_name, rule_data in rules.items():
                # Extract metadata
                meta = rule_data.get("meta", {})
                namespace = meta.get("namespace", "unknown")
                #description = meta.get("description", rule_name)
                #attack = meta.get("att&ck", [])
                #mbc = meta.get("mbc", [])
                
                # Determine severity based on namespace
                severity = self._get_capability_severity(namespace)
                
                # Create finding
                finding = self.create_finding(
                    title=f"{rule_name}",
                    description=self._get_capability_recommendation(namespace, rule_name),
                    severity=severity,
                    category="capability"
                    #file_path=target_file,
                    #recommendation=self._get_capability_recommendation(namespace, rule_name),
                    #metadata={
                    #    "rule_name": rule_name,
                    #    "namespace": namespace,
                    #    "attack": attack,
                    #    "mbc": mbc,
                    #    "matches": len(rule_data.get("matches", {}))
                    #}
                )
                
                findings.append(finding)

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse capa output: {e}")
        except Exception as e:
            logger.warning(f"Error processing capa results: {e}")

        return findings

    def _get_capability_severity(self, namespace: str) -> str:
        """Determine severity based on capability namespace"""
        # Critical namespaces
        critical_patterns = [
            "malware", "anti-analysis", "persistence", "defense-evasion",
            "collection", "exfiltration", "command-and-control"
        ]
        
        # High severity namespaces
        high_patterns = [
            "communication", "executable", "host-interaction"
        ]
        
        namespace_lower = namespace.lower()
        
        # Check for critical patterns
        for pattern in critical_patterns:
            if pattern in namespace_lower:
                return "high"
        
        # Check for high patterns
        for pattern in high_patterns:
            if pattern in namespace_lower:
                return "medium"
        
        return "low"

    def _get_capability_recommendation(self, namespace: str, rule_name: str) -> str:
        """Get recommendation based on detected capability"""
        base_rec = f"Capability '{rule_name}' was detected in the analyzed file. "
        
        if "anti-analysis" in namespace.lower():
            base_rec += "This suggests the binary may contain anti-debugging or anti-VM techniques. "
        elif "persistence" in namespace.lower():
            base_rec += "This suggests the binary may establish persistence mechanisms. "
        elif "communication" in namespace.lower():
            base_rec += "This suggests the binary may perform network communication. "
        
        base_rec += "Review the binary's behavior and purpose to determine if this is expected functionality."
        
        return base_rec
