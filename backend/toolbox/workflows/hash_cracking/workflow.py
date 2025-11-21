"""
Hash Cracking Workflow - Temporal Version

"""

from datetime import timedelta
from typing import Dict, Any, Optional

from temporalio import workflow
from temporalio.common import RetryPolicy

# Import for type hints (will be executed by worker)
with workflow.unsafe.imports_passed_through():
    import logging

logger = logging.getLogger(__name__)


@workflow.defn
class HashCrackingWorkflow:
    """
    Crack hashes workflow using hashid and other cracking modules.

    User workflow:
    1. User runs: ff workflow run hash_cracking .
    2. CLI uploads project to MinIO
    3. Worker downloads project
    4. Worker runs hashid to identify hash types and attempts to crack them
    5. Worker runs hashcat based on hashid return
    6. Worker returns findings
    """

    @workflow.run
    async def run(
        self,
        target_id: str,  # Required by FuzzForge : MinIO UUID of uploaded user code
        target_hash: str,  # Specific hash to crack
        target_hash_type: Optional[int] = None  # Hashcat mode of the hash (if known)
    ) -> Dict[str, Any]:
        """
        Main workflow execution.

        Args:
            target_id: UUID of the uploaded target in MinIO
            target_hash: The hash string to crack
            target_hash_type: Hashcat mode (if known)
        Returns:
            Dictionary containing findings and summary
        """
        workflow_id = workflow.info().workflow_id

        workflow.logger.info(
            f"Starting Hash Cracking Workflow: "
            f"(workflow_id={workflow_id}, target_id={target_id}, target_hash={target_hash})"
        )

        results = {
            "workflow_id": workflow_id,
            "target_id": target_id,
            "status": "running",
            "steps": []
        }

        try:
            # Get run ID for workspace isolation
            run_id = workflow.info().run_id

            # Step 1: Download user's project from MinIO
            workflow.logger.info("Step 1: Downloading user code from MinIO")
            target_path = await workflow.execute_activity(
                "get_target",
                args=[target_id, run_id, "isolated"],  # target_id, run_id, workspace_isolation
                start_to_close_timeout=timedelta(minutes=5),
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=1),
                    maximum_interval=timedelta(seconds=30),
                    maximum_attempts=3
                )
            )
            results["steps"].append({
                "step": "download_target",
                "status": "success",
                "target_path": target_path
            })
            workflow.logger.info(f"✓ User code downloaded to: {target_path}")

            # Determine hash type - either provided or identified via hashid
            hashcat_mode = target_hash_type
            hashid_results = None

            if target_hash_type is None:
                # Step 2: Run Hashid to identify hash types
                workflow.logger.info("Step 2: Running hashid to identify hash type")
                hashid_config = {
                    "hash": target_hash
                }

                hashid_results = await workflow.execute_activity(
                    "run_hashid",
                    args=[target_path, hashid_config],
                    start_to_close_timeout=timedelta(minutes=5),
                    retry_policy=RetryPolicy(
                        initial_interval=timedelta(seconds=2),
                        maximum_interval=timedelta(seconds=60),
                        maximum_attempts=1
                    )
                )

                print(hashid_results)

                results["steps"].append({
                    "step": "hash_identification",
                    "status": "success",
                    "total_matches": hashid_results.get("summary", {}).get("total_matches", 0)
                })
                workflow.logger.info(
                    f"✓ Hash identification completed: "
                    f"{hashid_results.get('summary', {}).get('total_matches', 0)} possible types found"
                )

                # Extract identified hash types
                findings = hashid_results.get("findings", [])
                total_matches = hashid_results.get("summary", {}).get("total_matches", 0)

                if total_matches == 0:
                    # No matching hash type found - generate SARIF report and abort
                    workflow.logger.warning("No hash type identified - aborting")

                    # Create a finding for no match
                    no_match_findings = [{
                        "title": "No Hash Type Identified",
                        "description": f"The hash '{target_hash}' could not be identified. No matching hash type was found.",
                        "severity": "warning",
                        "category": "hash_identification",
                        "metadata": {
                            "hash_input": target_hash,
                            "status": "no_match"
                        }
                    }]

                    # Generate SARIF report with no match finding
                    sarif = await workflow.execute_activity(
                        "generate_sarif_report_activity",
                        args=[{"findings": no_match_findings}, {}, target_path],
                        start_to_close_timeout=timedelta(minutes=2)
                    )
                    results["sarif"] = sarif
                    results["status"] = "aborted"
                    results["error"] = "No matching hash type found"
                    results["findings"] = no_match_findings

                    # Cleanup
                    await self._cleanup(target_path)

                    return results

                elif total_matches > 1:
                    # Multiple hash types found - generate SARIF report with all possibilities
                    workflow.logger.info(f"Multiple hash types identified ({total_matches}) - returning findings for user selection")

                    # Generate SARIF report with all identified hash types
                    sarif = await workflow.execute_activity(
                        "generate_sarif_report_activity",
                        args=[hashid_results, {}, target_path],
                        start_to_close_timeout=timedelta(minutes=2)
                    )
                    results["sarif"] = sarif
                    results["status"] = "needs_selection"
                    results["message"] = "Multiple hash types identified. Please re-run with a specific hash_type parameter."
                    results["findings"] = findings
                    results["summary"] = hashid_results.get("summary", {})

                    # Cleanup
                    await self._cleanup(target_path)

                    return results

                else:
                    # Exactly one hash type found - extract hashcat mode and proceed
                    hashcat_mode = findings[0].get("metadata", {}).get("hashcat_mode")
                    if hashcat_mode is None:
                        workflow.logger.warning("Hash type identified but no hashcat mode available")

                        no_mode_findings = [{
                            "title": "No Hashcat Mode Available",
                            "description": f"The hash type '{findings[0].get('title', 'Unknown')}' was identified but has no corresponding hashcat mode.",
                            "severity": "warning",
                            "category": "hash_identification",
                            "metadata": findings[0].get("metadata", {})
                        }]

                        sarif = await workflow.execute_activity(
                            "generate_sarif_report_activity",
                            args=[{"findings": no_mode_findings}, {}, target_path],
                            start_to_close_timeout=timedelta(minutes=2)
                        )
                        results["sarif"] = sarif
                        results["status"] = "aborted"
                        results["error"] = "No hashcat mode available for identified hash type"
                        results["findings"] = no_mode_findings

                        await self._cleanup(target_path)

                        return results

                    workflow.logger.info(f"✓ Single hash type identified with hashcat mode: {hashcat_mode}")

            # Step 3: Run hashcat with identified/provided hash type
            workflow.logger.info(f"Step 3: Running hashcat with mode {hashcat_mode}")
            hashcat_config = {
                "hash": target_hash,
                "hash_type": hashcat_mode
            }

            hashcat_results = await workflow.execute_activity(
                "run_hashcat",
                args=[target_path, hashcat_config],
                start_to_close_timeout=timedelta(minutes=30),  # Cracking can take time
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=2),
                    maximum_interval=timedelta(seconds=60),
                    maximum_attempts=1
                )
            )

            results["steps"].append({
                "step": "hash_cracking",
                "status": hashcat_results.get("status", "unknown"),
                "plaintext": hashcat_results.get("summary", {}).get("plaintext", "")
            })
            workflow.logger.info(
                f"✓ Hashcat completed: "
                f"plaintext={'found' if hashcat_results.get('summary', {}).get('plaintext') else 'not found'}"
            )

            # Step 4: Generate SARIF report from hashcat results
            workflow.logger.info("Step 4: Generating SARIF report")
            try:
                sarif = await workflow.execute_activity(
                    "generate_sarif_report_activity",
                    args=[hashcat_results, {}, target_path],
                    start_to_close_timeout=timedelta(minutes=2)
                )
                results["sarif"] = sarif
                workflow.logger.info("✓ SARIF report generated")
            except Exception as e:
                workflow.logger.warning(f"Failed to generate SARIF report: {e}")
                results["sarif"] = {}

            # Step 5: Upload results to MinIO
            workflow.logger.info("Step 5: Uploading results")
            try:
                results_url = await workflow.execute_activity(
                    "upload_results",
                    args=[workflow_id, hashcat_results, "json"],
                    start_to_close_timeout=timedelta(minutes=2)
                )
                results["results_url"] = results_url
                workflow.logger.info(f"✓ Results uploaded to: {results_url}")
            except Exception as e:
                workflow.logger.warning(f"Failed to upload results: {e}")
                results["results_url"] = None

            # Step 6: Cleanup cache
            await self._cleanup(target_path)

            # Mark workflow as successful
            results["status"] = "success"
            results["findings"] = hashcat_results.get("findings", [])
            results["summary"] = hashcat_results.get("summary", {})
            workflow.logger.info(
                f"✓ Workflow completed successfully: {workflow_id} "
                f"(plaintext: {results['summary'].get('plaintext', 'not found')})"
            )

            return results

        except Exception as e:
            workflow.logger.error(f"Workflow failed: {e}")
            results["status"] = "error"
            results["error"] = str(e)
            results["steps"].append({
                "step": "error",
                "status": "failed",
                "error": str(e)
            })
            raise

    async def _cleanup(self, target_path: str) -> None:
        """Helper method to cleanup workspace cache."""
        workflow.logger.info("Cleaning up cache")
        try:
            await workflow.execute_activity(
                "cleanup_cache",
                args=[target_path, "isolated"],
                start_to_close_timeout=timedelta(minutes=1)
            )
            workflow.logger.info("✓ Cache cleaned up")
        except Exception as e:
            workflow.logger.warning(f"Cache cleanup failed: {e}")