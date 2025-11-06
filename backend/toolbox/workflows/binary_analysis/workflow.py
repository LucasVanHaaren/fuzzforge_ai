"""
Binary Analysis Workflow - Temporal Version

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
class BinaryAnalysisWorkflow:
    """
    Analyze binary files using Capa.

    User workflow:
    1. User runs: ff workflow run binary_analysis .
    2. CLI uploads project to MinIO
    3. Worker downloads project
    4. Worker runs Capa analysis
    5. Worker returns findings
    """

    @workflow.run
    async def run(
        self,
        target_id: str,  # Required by FuzzForge : MinIO UUID of uploaded user code
        target_file: str,  # Specific file to analyze
    ) -> Dict[str, Any]:
        """
        Main workflow execution.

        Args:
            target_id: UUID of the uploaded target in MinIO
            target_file: Specific Python file to analyze
        Returns:
            Dictionary containing findings and summary
        """
        workflow_id = workflow.info().workflow_id

        workflow.logger.info(
            f"Starting Binary Analysis Workflow: "
            f"(workflow_id={workflow_id}, target_id={target_id}, target_file={target_file})"
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

            # Step 2: Run Atheris fuzzing
            workflow.logger.info("Step 2: Running Capa analysis")

            fuzz_config = {
                "target_file": target_file
            }

            fuzz_results = await workflow.execute_activity(
                "run_capa",
                args=[target_path, fuzz_config],
                start_to_close_timeout=timedelta(minutes=5),
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=2),
                    maximum_interval=timedelta(seconds=60),
                    maximum_attempts=1
                )
            )

            results["steps"].append({
                "step": "fuzzing",
                "status": "success",
                "capabilities_found": fuzz_results.get("summary", {}).get("capabilities_found", 0),
                "execution_time": fuzz_results.get("summary", {}).get("execution_time", 0)
            })
            workflow.logger.info(
                f"✓ Fuzzing completed: "
                f"{fuzz_results.get('summary', {}).get('capabilities_found', 0)} capabilities found"
            )


            # Step 3: Generate SARIF report from binary_analysis results
            workflow.logger.info("Step 3: Generating SARIF report")
            try:
                sarif = await workflow.execute_activity(
                    "generate_sarif_report_binary_analysis",
                    args=[fuzz_results, {}, target_path],
                    start_to_close_timeout=timedelta(minutes=2)
                )
                results["sarif"] = sarif
                workflow.logger.info("✓ SARIF report generated")
            except Exception as e:
                workflow.logger.warning(f"Failed to generate SARIF report: {e}")
                results["sarif"] = {}

            # Step 4: Upload results to MinIO
            workflow.logger.info("Step 4: Uploading results")
            try:
                results_url = await workflow.execute_activity(
                    "upload_results",
                    args=[workflow_id, fuzz_results, "json"],
                    start_to_close_timeout=timedelta(minutes=2)
                )
                results["results_url"] = results_url
                workflow.logger.info(f"✓ Results uploaded to: {results_url}")
            except Exception as e:
                workflow.logger.warning(f"Failed to upload results: {e}")
                results["results_url"] = None

            # Step 5: Cleanup cache
            workflow.logger.info("Step 5: Cleaning up cache")
            try:
                await workflow.execute_activity(
                    "cleanup_cache",
                    args=[target_path, "isolated"],  # target_path, workspace_isolation
                    start_to_close_timeout=timedelta(minutes=1)
                )
                workflow.logger.info("✓ Cache cleaned up")
            except Exception as e:
                workflow.logger.warning(f"Cache cleanup failed: {e}")

            # Mark workflow as successful
            results["status"] = "success"
            results["findings"] = fuzz_results.get("findings", [])
            results["summary"] = fuzz_results.get("summary", {})
            workflow.logger.info(
                f"✓ Workflow completed successfully: {workflow_id} "
                f"({results['summary'].get('crashes_found', 0)} crashes found)"
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
