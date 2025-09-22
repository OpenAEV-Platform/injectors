import json
import time
from typing import Dict

from contracts_aws import (
    CLOUDTRAIL_ENUM_CONTRACT,
    COGNITO_ENUM_CONTRACT,
    DYNAMODB_ENUM_CONTRACT,
    EBS_ENUM_SNAPSHOTS_CONTRACT,
    EC2_ENUM_INSTANCES_CONTRACT,
    EC2_ENUM_SECURITY_GROUPS_CONTRACT,
    ECR_ENUM_CONTRACT,
    ECS_ENUM_CONTRACT,
    EKS_ENUM_CONTRACT,
    GLUE_ENUM_CONTRACT,
    GUARDDUTY_ENUM_CONTRACT,
    IAM_CREATE_USER_CONTRACT,
    IAM_ENUM_PERMISSIONS_CONTRACT,
    IAM_ENUM_ROLES_CONTRACT,
    IAM_ENUM_USERS_CONTRACT,
    IAM_GET_PASSWORD_POLICY_CONTRACT,
    IAM_PRIVESC_SCAN_CONTRACT,
    LAMBDA_ENUM_FUNCTIONS_CONTRACT,
    ORGANIZATIONS_ENUM_CONTRACT,
    RDS_ENUM_DATABASES_CONTRACT,
    ROUTE53_ENUM_CONTRACT,
    S3_DOWNLOAD_BUCKET_CONTRACT,
    S3_ENUM_BUCKETS_CONTRACT,
    SECRETS_MANAGER_ENUM_CONTRACT,
    SNS_ENUM_CONTRACT,
    SSM_ENUM_PARAMETERS_CONTRACT,
    VPC_ENUM_CONTRACT,
    AWSContracts,
)
from helpers.pacu_executor import PacuExecutor
from pyoaev.helpers import OpenBASConfigHelper, OpenBASInjectorHelper


class OpenBASAWS:
    def __init__(self):
        self.config = OpenBASConfigHelper(
            __file__,
            {
                # API information
                "openbas_url": {"env": "OPENBAS_URL", "file_path": ["openbas", "url"]},
                "openbas_token": {
                    "env": "OPENBAS_TOKEN",
                    "file_path": ["openbas", "token"],
                },
                # Config information
                "injector_id": {"env": "INJECTOR_ID", "file_path": ["injector", "id"]},
                "injector_name": {
                    "env": "INJECTOR_NAME",
                    "file_path": ["injector", "name"],
                },
                "injector_type": {
                    "env": "INJECTOR_TYPE",
                    "file_path": ["injector", "type"],
                    "default": "openbas_aws",
                },
                "injector_log_level": {
                    "env": "INJECTOR_LOG_LEVEL",
                    "file_path": ["injector", "log_level"],
                    "default": "error",
                },
                "injector_contracts": {"data": AWSContracts.build_contract()},
            },
        )

        self.helper = OpenBASInjectorHelper(self.config, open("img/icon-aws.png", "rb"))
        self.pacu_executor = PacuExecutor(logger=self.helper.injector_logger)

    def aws_execution(self, start: float, data: Dict) -> Dict:
        inject_id = data["injection"]["inject_id"]
        contract_id = data["injection"]["inject_injector_contract"]["convertedContent"][
            "contract_id"
        ]
        content = data["injection"]["inject_content"]

        # Log the incoming data structure for debugging
        self.helper.injector_logger.info(
            f"Starting AWS execution for inject {inject_id}"
        )

        # Extract AWS credentials from content
        aws_access_key_id = content.get("aws_access_key_id")
        aws_secret_access_key = content.get("aws_secret_access_key")
        aws_session_token = content.get("aws_session_token")
        aws_region = content.get("aws_region", "us-east-1")

        self.helper.injector_logger.info(f"AWS Region: {aws_region}")
        self.helper.injector_logger.info(
            f"Session token provided: {'Yes' if aws_session_token else 'No'}"
        )

        if not aws_access_key_id or not aws_secret_access_key:
            error_msg = "AWS credentials are required (aws_access_key_id and aws_secret_access_key)"
            self.helper.injector_logger.error(error_msg)
            raise ValueError(error_msg)

        # Set up AWS credentials
        self.helper.injector_logger.info("Setting up AWS credentials...")
        try:
            self.pacu_executor.setup_aws_credentials(
                access_key_id=aws_access_key_id,
                secret_access_key=aws_secret_access_key,
                session_token=aws_session_token,
                region=aws_region,
            )
            self.helper.injector_logger.info("AWS credentials validated successfully")
        except Exception as e:
            self.helper.injector_logger.error(f"Failed to setup AWS credentials: {e}")
            raise

        # Log the module being executed
        module_name = self._get_module_name(contract_id)
        self.helper.injector_logger.info(f"Executing AWS module: {module_name}")

        # Execute the appropriate AWS module based on contract ID
        self.helper.injector_logger.info(
            f"Starting module execution for contract: {contract_id}"
        )
        try:
            results = self._execute_module_by_contract(contract_id, content)
            self.helper.injector_logger.info(
                "Module execution completed, parsing results..."
            )
        except Exception as e:
            error_msg = str(e)
            # Suppress the atexit error which is non-fatal
            if "can't register atexit after shutdown" in error_msg:
                self.helper.injector_logger.debug(f"Ignoring atexit error: {error_msg}")
                # Return a success result since this is a cleanup error that doesn't affect execution
                results = {
                    "success": True,
                    "module": module_name,
                    "data": {"message": "Module executed (cleanup warning ignored)"},
                    "summary": "Execution completed",
                }
            else:
                self.helper.injector_logger.error(
                    f"Module execution failed: {error_msg}"
                )
                raise

        # Parse and return results
        parsed_results = self.pacu_executor.parse_results(results)
        self.helper.injector_logger.info("Results parsed successfully")
        return parsed_results

    def _get_module_name(self, contract_id: str) -> str:
        """Get the module name based on contract ID"""
        module_map = {
            IAM_ENUM_PERMISSIONS_CONTRACT: "iam__enum_permissions",
            IAM_ENUM_USERS_CONTRACT: "iam__enum_users_roles_policies_groups",
            IAM_ENUM_ROLES_CONTRACT: "iam__enum_roles",
            IAM_PRIVESC_SCAN_CONTRACT: "iam__privesc_scan",
            IAM_GET_PASSWORD_POLICY_CONTRACT: "aws_cli_iam_get_password_policy",
            IAM_CREATE_USER_CONTRACT: "aws_cli_iam_create_user",
            EC2_ENUM_INSTANCES_CONTRACT: "ec2__enum",
            EC2_ENUM_SECURITY_GROUPS_CONTRACT: "ec2__enum",
            S3_ENUM_BUCKETS_CONTRACT: "aws_cli_s3_ls",
            S3_DOWNLOAD_BUCKET_CONTRACT: "s3__download_bucket",
            LAMBDA_ENUM_FUNCTIONS_CONTRACT: "lambda__enum",
            CLOUDTRAIL_ENUM_CONTRACT: "cloudtrail__download_event_history",
            VPC_ENUM_CONTRACT: "vpc__enum_lateral_movement",
            RDS_ENUM_DATABASES_CONTRACT: "rds__enum",
            SECRETS_MANAGER_ENUM_CONTRACT: "secrets__enum",
            SSM_ENUM_PARAMETERS_CONTRACT: "systemsmanager__download_parameters",
            ORGANIZATIONS_ENUM_CONTRACT: "organizations__enum",
            EBS_ENUM_SNAPSHOTS_CONTRACT: "ebs__enum_public_snapshots_unauthenticated",
            DYNAMODB_ENUM_CONTRACT: "dynamodb__enum",
            ECR_ENUM_CONTRACT: "ecr__enum",
            ECS_ENUM_CONTRACT: "ecs__enum",
            EKS_ENUM_CONTRACT: "eks__enum",
            GUARDDUTY_ENUM_CONTRACT: "guardduty__list_findings",
            COGNITO_ENUM_CONTRACT: "cognito__enum",
            GLUE_ENUM_CONTRACT: "glue__enum",
            ROUTE53_ENUM_CONTRACT: "route53__enum",
            SNS_ENUM_CONTRACT: "sns__enum",
        }
        return module_map.get(contract_id, "unknown")

    def _execute_module_by_contract(self, contract_id: str, content: Dict) -> Dict:
        """Execute the appropriate AWS module based on contract ID"""

        dispatcher = {
            IAM_ENUM_PERMISSIONS_CONTRACT: self.pacu_executor.execute_iam_enum_permissions,
            IAM_ENUM_USERS_CONTRACT: self.pacu_executor.execute_iam_enum_users,
            IAM_ENUM_ROLES_CONTRACT: self.pacu_executor.execute_iam_enum_roles,
            IAM_PRIVESC_SCAN_CONTRACT: self.pacu_executor.execute_iam_privesc_scan,
            IAM_GET_PASSWORD_POLICY_CONTRACT: self.pacu_executor.execute_iam_get_password_policy,
            IAM_CREATE_USER_CONTRACT: lambda: self.pacu_executor.execute_iam_create_user(
                content.get("username")
            ),
            EC2_ENUM_INSTANCES_CONTRACT: self.pacu_executor.execute_ec2_enum_instances,
            EC2_ENUM_SECURITY_GROUPS_CONTRACT: self.pacu_executor.execute_ec2_enum_security_groups,
            S3_ENUM_BUCKETS_CONTRACT: self.pacu_executor.execute_s3_enum_buckets,
            LAMBDA_ENUM_FUNCTIONS_CONTRACT: self.pacu_executor.execute_lambda_enum_functions,
            CLOUDTRAIL_ENUM_CONTRACT: self.pacu_executor.execute_cloudtrail_enum,
            VPC_ENUM_CONTRACT: self.pacu_executor.execute_vpc_enum,
            RDS_ENUM_DATABASES_CONTRACT: self.pacu_executor.execute_rds_enum_databases,
            SECRETS_MANAGER_ENUM_CONTRACT: self.pacu_executor.execute_secrets_manager_enum,
            SSM_ENUM_PARAMETERS_CONTRACT: self.pacu_executor.execute_ssm_enum_parameters,
            ORGANIZATIONS_ENUM_CONTRACT: self.pacu_executor.execute_organizations_enum,
            EBS_ENUM_SNAPSHOTS_CONTRACT: self.pacu_executor.execute_ebs_enum_snapshots,
            DYNAMODB_ENUM_CONTRACT: self.pacu_executor.execute_dynamodb_enum,
            ECR_ENUM_CONTRACT: self.pacu_executor.execute_ecr_enum,
            ECS_ENUM_CONTRACT: self.pacu_executor.execute_ecs_enum,
            EKS_ENUM_CONTRACT: self.pacu_executor.execute_eks_enum,
            GUARDDUTY_ENUM_CONTRACT: self.pacu_executor.execute_guardduty_enum,
            COGNITO_ENUM_CONTRACT: self.pacu_executor.execute_cognito_enum,
            GLUE_ENUM_CONTRACT: self.pacu_executor.execute_glue_enum,
            ROUTE53_ENUM_CONTRACT: self.pacu_executor.execute_route53_enum,
            SNS_ENUM_CONTRACT: self.pacu_executor.execute_sns_enum,
        }

        if contract_id == S3_DOWNLOAD_BUCKET_CONTRACT:
            bucket_name = content.get("bucket_name")
            if not bucket_name:
                raise ValueError("Bucket name is required for S3 download")
            return self.pacu_executor.execute_s3_download_bucket(bucket_name)

        executor_fn = dispatcher.get(contract_id)
        if not executor_fn:
            raise ValueError(f"Unknown contract ID: {contract_id}")
        return executor_fn()

    def process_message(self, data: Dict) -> None:
        start = time.time()
        inject_id = data["injection"]["inject_id"]

        self.helper.injector_logger.info("=" * 60)
        self.helper.injector_logger.info(f"Processing message for inject: {inject_id}")

        # Notify API of reception and expected number of operations
        reception_data = {"tracking_total_count": 1}

        try:
            self.helper.api.inject.execution_reception(
                inject_id=inject_id, data=reception_data
            )

        except Exception as e:
            self.helper.injector_logger.error(
                f"Failed to send reception notification: {e}"
            )

        # Execute inject
        try:
            self.helper.injector_logger.info("Starting AWS execution...")
            execution_result = self.aws_execution(start, data)

            # Check if execution was successful
            is_success = execution_result.get("success", False)
            outputs = execution_result.get("outputs", {})
            message = execution_result.get("message", "Execution completed")

            if not is_success:
                callback_data = {
                    "execution_message": message,
                    "execution_status": "ERROR",
                    "execution_duration": int(time.time() - start),
                    "execution_action": "complete",
                }
            else:
                outputs_json = json.dumps(outputs)
                callback_data = {
                    "execution_message": message,
                    "execution_output_structured": outputs_json,
                    "execution_status": "SUCCESS",
                    "execution_duration": int(time.time() - start),
                    "execution_action": "complete",
                }

            if is_success:
                self.helper.injector_logger.info(f"Execution succeeded: {message}")
            else:
                self.helper.injector_logger.error(f"Execution failed: {message}")

            try:
                self.helper.api.inject.execution_callback(
                    inject_id=inject_id, data=callback_data
                )
                self.helper.injector_logger.info("Callback sent successfully")
            except Exception as e:
                # Log the actual error message from the exception
                error_str = str(e)
                self.helper.injector_logger.error(
                    f"Failed to send callback: {error_str}"
                )
                # If it's a 500 error, log that we need to check server logs
                if "500" in error_str:
                    self.helper.injector_logger.error(
                        "Server returned 500 - check OpenBAS server logs for details"
                    )
        except Exception as e:
            error_msg = f"Error executing AWS module: {e}"
            self.helper.injector_logger.error(error_msg)
            callback_data = {
                "execution_message": str(e),
                "execution_status": "ERROR",
                "execution_duration": int(time.time() - start),
                "execution_action": "complete",
            }

            try:
                self.helper.api.inject.execution_callback(
                    inject_id=inject_id, data=callback_data
                )
                self.helper.injector_logger.info("Error callback sent successfully")
            except Exception as e:
                # Log the actual error message from the exception
                error_str = str(e)
                self.helper.injector_logger.error(
                    f"Failed to send error callback: {error_str}"
                )

        finally:
            self.helper.injector_logger.info(
                f"Message processing completed in {int(time.time() - start)} seconds"
            )
            self.helper.injector_logger.info("=" * 60)

    # Start the main loop
    def start(self):
        self.helper.injector_logger.info("Starting AWS injector...")
        self.helper.listen(message_callback=self.process_message)


if __name__ == "__main__":
    openBASAWS = OpenBASAWS()
    openBASAWS.start()
