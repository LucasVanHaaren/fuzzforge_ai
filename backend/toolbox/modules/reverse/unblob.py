"""
Unblob Module

This module uses unblob to identify and extract embedded files from a binary blob.
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
from typing import Dict, Any, List, Tuple

try:
    from toolbox.modules.base import BaseModule, ModuleMetadata, ModuleResult
except ImportError:
    try:
        from modules.base import BaseModule, ModuleMetadata, ModuleResult
    except ImportError:
        from ..base import BaseModule, ModuleMetadata, ModuleResult

logger = logging.getLogger(__name__)


class Unblob(BaseModule):
    """Unblob module for extracting embedded files from binary blobs"""

    def get_metadata(self) -> ModuleMetadata:
        """Get module metadata"""
        return ModuleMetadata(
            name="unblob",
            version="1.0.0",
            description="Extracts embedded files from binary blobs using unblob tool",
            author="FuzzForge Team",
            category="reverse",
            tags=["reverse", "carving", "extraction"],
            input_schema={
                "type": "object",
                "properties": {
                    "target_file": {
                        "type": "string",
                        "description": "Path to the binary blob file to carve (relative to workspace)"
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
                                "file_name": {"type": "string"},
                                "file_type": {"type": "string"},
                                "offset": {"type": "integer"},
                                "size": {"type": "integer"}
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
        """Execute unblob extraction"""
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

            logger.info(f"Running unblob on {target_file}")

            # Build unblob command with JSON output
            cmd = ["unblob", "--report", "report.json", str(target_path)]

            logger.debug(f"Running command: {' '.join(cmd)}")

            # Run unblob
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=workspace
            )

            stdout, stderr = await process.communicate()

            # We don't use stdout; unblob writes JSON to report.json when --report is provided.
            if process.returncode != 0:
                error_msg = stderr.decode() if stderr else "Unknown error"
                logger.error(f"unblob failed: {error_msg}")
                return self.create_result(
                    findings=[],
                    status="failed",
                    error=f"unblob execution failed: {error_msg}"
                )

            # Read report.json produced by unblob
            report_path = workspace / "report.json"
            if not report_path.exists():
                error_msg = "unblob did not produce report.json"
                logger.error(error_msg)
                return self.create_result(
                    findings=[],
                    status="failed",
                    error=error_msg
                )

            try:
                report_json = report_path.read_text(encoding="utf-8")
                findings, summary = self._parse_unblob_output(report_json, target_file)
            finally:
                # Always attempt to remove the report file after parsing
                try:
                    if report_path.exists():
                        report_path.unlink()
                except Exception as cleanup_err:
                    logger.debug(f"Failed to remove report.json: {cleanup_err}")

            logger.info(
                f"unblob extraction completed: extracted {summary.get('files_extracted', 0)} files"
            )
            return self.create_result(
                findings=findings,
                status="success",
                summary=summary
            )

        except FileNotFoundError:
            error_msg = "unblob binary not found"
            logger.error(error_msg)
            return self.create_result(
                findings=[],
                status="failed",
                error=error_msg
            )
        
        except Exception as e:
            logger.error(f"unblob module failed: {e}")
            return self.create_result(
                findings=[],
                status="failed",
                error=str(e)
            )

    def _parse_unblob_output(self, output: str, target_file: str) -> Tuple[List, Dict[str, Any]]:
        """Parse unblob JSON output.

        - Findings: only objects with __typename__ == "ChunkReport".
        - files_extracted: count of StatReport objects with is_file == 0.
        """
        findings: List[Dict[str, Any]] = []
        files_extracted = 0

        if not output or not output.strip():
            return findings, {
                "target_file": target_file,
                "files_extracted": 0,
                "analysis_completed": True,
            }

        def iter_reports(root: Any):
            """Yield all report entries regardless of top-level shape."""
            if isinstance(root, dict):
                reports = root.get("reports")
                if isinstance(reports, dict):
                    for _, r in reports.items():
                        yield r
                elif isinstance(reports, list):
                    for r in reports:
                        yield r
            elif isinstance(root, list):
                for item in root:
                    if isinstance(item, dict):
                        rep = item.get("reports")
                        if isinstance(rep, dict):
                            for _, r in rep.items():
                                yield r
                        elif isinstance(rep, list):
                            for r in rep:
                                yield r

        try:
            results = json.loads(output)

            for report in iter_reports(results):
                typename = report.get("__typename__")

                # Count extracted files: StatReport with is_file == 1
                if typename == "StatReport":
                    is_file_val = report.get("is_file")
                    if is_file_val in (1, True):
                        files_extracted += 1

                # Findings only from ChunkReport
                if typename == "ChunkReport":
                    handler_name = report.get("handler_name")
                    is_encrypted = report.get("is_encrypted")
                    start_offset = report.get("start_offset")
                    end_offset = report.get("end_offset")
                    size = report.get("size")

                    finding = self.create_finding(
                        title=f"Found a chunk: {handler_name}",
                        description=f"Chunk carved by handler '{handler_name}' from {start_offset} to {end_offset} (size={size}).",
                        severity="info",
                        category="carved_chunk",
                        metadata={
                            "handler_name": handler_name,
                            "is_encrypted": is_encrypted,
                            "start_offset": start_offset,
                            "end_offset": end_offset,
                            "size": size,
                            "file_path": target_file,
                        },
                    )
                    findings.append(finding)

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse unblob output: {e}")
        except Exception as e:
            logger.warning(f"Error processing unblob results: {e}")

        summary = {
            "target_file": target_file,
            "files_extracted": files_extracted,
            "analysis_completed": True,
        }

        return findings, summary
