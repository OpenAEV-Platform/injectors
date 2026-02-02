"""
Helper module for executing Pacu modules within OpenAEV injector.
This module handles the execution of Pacu commands and parsing of results.
"""

import json
import os
import platform
import subprocess
from typing import Dict, List, Optional, Tuple


class PacuExecutor:
    """Handles Pacu module execution and result parsing"""

    def __init__(self, logger=None):
        self.logger = logger
        self.pacu_path = None

    def setup_aws_credentials(
        self,
        access_key_id: str,
        secret_access_key: str,
        session_token: Optional[str] = None,
        region: str = "us-east-1",
    ):
        """Set up AWS credentials for Pacu execution"""
        if self.logger:
            self.logger.info(f"Setting up AWS credentials for region: {region}")

        # Set environment variables for AWS SDK
        os.environ["AWS_ACCESS_KEY_ID"] = access_key_id
        os.environ["AWS_SECRET_ACCESS_KEY"] = secret_access_key
        if session_token:
            os.environ["AWS_SESSION_TOKEN"] = session_token
        os.environ["AWS_DEFAULT_REGION"] = region

        return True

    def execute_pacu_module(
        self, module_name: str, module_args: Optional[Dict] = None
    ) -> Dict:
        """Execute a Pacu module via Pacu CLI."""
        if self.logger:
            self.logger.info(f"Executing Pacu module: {module_name}")
        return self._execute_pacu_cli(module_name, module_args)

    def _execute_pacu_cli(
        self, module_name: str, module_args: Optional[Dict] = None
    ) -> Dict:
        """Execute Pacu via CLI (preferred integration per project docs)."""
        if self.logger:
            self.logger.info(f"Executing via Pacu CLI: {module_name}")
        try:
            # First check if session exists, if not create it
            if not self._check_session_exists("openaev_session"):
                if self.logger:
                    self.logger.info("Creating new Pacu session: openaev_session")
                self._create_session("openaev_session")

            cmd = [
                "pacu",
                "--session",
                "openaev_session",
                "--module-name",
                module_name,
                "--exec",
            ]
            # Build module args string if provided
            # According to Pacu docs, module args should be formatted as "key value key value"
            if module_args and isinstance(module_args, dict):
                flat_args: List[str] = []
                for k, v in module_args.items():
                    flat_args.append(f"--{k}")
                    if isinstance(v, list):
                        flat_args.append(",".join(map(str, v)))
                    elif v is not None:
                        flat_args.append(str(v))
                if flat_args:
                    # Pass args as a single string
                    cmd.extend(["--module-args", " ".join(flat_args)])

            # Set environment to be non-interactive
            env = os.environ.copy()
            env["PYTHONUNBUFFERED"] = "1"
            # Set CI environment variable which some tools respect for non-interactive mode
            env["CI"] = "true"
            env["NONINTERACTIVE"] = "1"

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
                env=env,
                stdin=subprocess.DEVNULL,
            )

            if result.returncode == 0:
                return {
                    "success": True,
                    "module": module_name,
                    "data": {"stdout": result.stdout[-50000:]},
                    "summary": "Pacu module executed successfully",
                }

            # Check for signals
            if result.returncode < 0:
                signal_code = -result.returncode
                signal_names = {2: "SIGINT", 9: "SIGKILL", 15: "SIGTERM"}
                signal_name = signal_names.get(signal_code, f"signal {signal_code}")

                # Check stderr/stdout for more context
                error_detail = ""
                if "SIGINT" in (result.stderr or "") or signal_code == 2:
                    error_detail = "Module interrupted - possible interactive prompt or keyboard interrupt"
                elif result.stderr:
                    error_detail = result.stderr.strip()[:200]
                elif result.stdout and "error" in result.stdout.lower():
                    # Extract error from stdout if present
                    lines = result.stdout.split("\n")
                    for line in lines:
                        if "error" in line.lower():
                            error_detail = line.strip()[:200]
                            break

                return {
                    "success": False,
                    "module": module_name,
                    "error": (
                        f"{signal_name}: {error_detail}"
                        if error_detail
                        else f"Pacu terminated by {signal_name}"
                    ),
                }

            # Parse error from stderr or stdout
            error_msg = "Module execution failed"
            if result.stderr:
                error_msg = result.stderr.strip()[:500]
            elif result.stdout:
                # Look for error indicators in stdout
                stdout_lower = result.stdout.lower()
                if (
                    "error" in stdout_lower
                    or "failed" in stdout_lower
                    or "exception" in stdout_lower
                ):
                    # Try to extract the relevant error line
                    lines = result.stdout.split("\n")
                    for line in lines:
                        line_lower = line.lower()
                        if (
                            "error" in line_lower
                            or "failed" in line_lower
                            or "exception" in line_lower
                        ):
                            error_msg = line.strip()[:500]
                            break
                else:
                    # Use last few lines of output as error context
                    lines = result.stdout.strip().split("\n")
                    error_msg = "\n".join(lines[-5:])[:500] if lines else "No output"

            return {
                "success": False,
                "module": module_name,
                "error": error_msg,
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "module": module_name,
                "error": "Module execution timed out after 10 minutes",
            }
        except Exception as e:
            return {"success": False, "module": module_name, "error": str(e)}

    def _check_session_exists(self, session_name: str) -> bool:
        """Check if a Pacu session exists."""
        try:
            # List sessions to check if ours exists
            result = subprocess.run(
                ["pacu", "--list-sessions"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0 and session_name in result.stdout:
                return True
            return False
        except Exception:
            return False

    def _create_session(self, session_name: str) -> None:
        """Create a new Pacu session by using echo to provide input."""
        try:
            # On Windows, we need to use echo to provide input
            # Echo "0" to select "New session", then echo the session name
            if platform.system() == "Windows":
                # Use echo to provide input: 0 for new session, then session name
                cmd = "echo 0 | pacu"
                subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

                # Now set the session name
                cmd = f"echo {session_name} | pacu --session {session_name} --pacu-help"
                subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
            else:
                # On Linux/Mac, we can use stdin
                env = os.environ.copy()
                env["CI"] = "true"

                # Create session by selecting "0" for new session
                process = subprocess.Popen(
                    ["pacu"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=env,
                )
                stdout, stderr = process.communicate(
                    input=f"0\n{session_name}\nexit\n", timeout=10
                )

            if self.logger:
                self.logger.info(f"Session '{session_name}' created")
        except Exception as e:
            if self.logger:
                self.logger.info(f"Session creation failed: {str(e)[:100]}")

    def _ensure_session(self, session_name: str) -> None:
        """Deprecated - use _check_session_exists and _create_session instead."""
        if not self._check_session_exists(session_name):
            self._create_session(session_name)

    def execute_iam_enum_permissions(self) -> Dict:
        """Execute IAM permission enumeration"""
        return self.execute_pacu_module("iam__enum_permissions")

    def execute_iam_enum_users(self) -> Dict:
        """Execute IAM user enumeration"""
        return self.execute_pacu_module("iam__enum_users_roles_policies_groups")

    def execute_iam_enum_roles(self) -> Dict:
        """Execute IAM role enumeration"""
        return self.execute_pacu_module("iam__enum_roles")

    def execute_iam_privesc_scan(self) -> Dict:
        """Execute IAM privilege escalation scan"""
        return self.execute_pacu_module("iam__privesc_scan")

    def execute_iam_get_password_policy(self) -> Dict:
        """Execute IAM get account password policy using AWS CLI"""
        if self.logger:
            self.logger.info("Executing IAM get account password policy")

        # Use AWS CLI for getting password policy
        return self.execute_aws_cli_command("iam get-account-password-policy")

    def execute_iam_create_user(self, username: str) -> Dict:
        """Execute IAM create user attack using AWS CLI

        Args:
            username: The username to create in IAM

        Returns:
            Command execution results
        """
        if not username:
            return {
                "success": False,
                "module": "aws_cli_iam_create_user",
                "error": "Username is required for IAM create user",
            }

        if self.logger:
            self.logger.info(
                f"Executing IAM create user attack for username: {username}"
            )

        # Use AWS CLI to create the user
        return self.execute_aws_cli_command(f"iam create-user --user-name {username}")

    def execute_ec2_enum_instances(self) -> Dict:
        """Execute EC2 instance enumeration"""
        return self.execute_pacu_module("ec2__enum")

    def execute_ec2_enum_security_groups(self) -> Dict:
        """Execute EC2 security group enumeration"""
        # EC2 enum includes security groups
        return self.execute_pacu_module("ec2__enum")

    def execute_s3_enum_buckets(self) -> Dict:
        """Execute S3 bucket enumeration using AWS CLI"""
        if self.logger:
            self.logger.info("Executing S3 bucket enumeration")

        # Use AWS CLI for S3 enumeration
        return self.execute_aws_cli_command("s3 ls")

    def execute_s3_download_bucket(self, bucket_name: str) -> Dict:
        """Download S3 bucket contents"""
        return self.execute_pacu_module(
            "s3__download_bucket", {"bucket_names": [bucket_name]}
        )

    def execute_lambda_enum_functions(self) -> Dict:
        """Execute Lambda function enumeration"""
        return self.execute_pacu_module("lambda__enum")

    def execute_cloudtrail_enum(self) -> Dict:
        """Execute CloudTrail enumeration"""
        # CloudTrail enum not available, use download_event_history
        return self.execute_pacu_module("cloudtrail__download_event_history")

    def execute_vpc_enum(self) -> Dict:
        """Execute VPC enumeration"""
        # VPC enum not directly available, use lateral movement enum
        return self.execute_pacu_module("vpc__enum_lateral_movement")

    def execute_rds_enum_databases(self) -> Dict:
        """Execute RDS database enumeration"""
        return self.execute_pacu_module("rds__enum")

    def execute_secrets_manager_enum(self) -> Dict:
        """Execute Secrets Manager enumeration"""
        return self.execute_pacu_module("secrets__enum")

    def execute_ssm_enum_parameters(self) -> Dict:
        """Execute SSM parameter enumeration"""
        return self.execute_pacu_module("systemsmanager__download_parameters")

    def execute_organizations_enum(self) -> Dict:
        """Execute Organizations enumeration"""
        return self.execute_pacu_module("organizations__enum")

    # Additional Pacu modules
    def execute_ebs_enum_snapshots(self) -> Dict:
        """Execute EBS snapshots enumeration"""
        return self.execute_pacu_module("ebs__enum_public_snapshots_unauthenticated")

    def execute_dynamodb_enum(self) -> Dict:
        """Execute DynamoDB enumeration"""
        return self.execute_pacu_module("dynamodb__enum")

    def execute_ecr_enum(self) -> Dict:
        """Execute ECR enumeration"""
        return self.execute_pacu_module("ecr__enum")

    def execute_ecs_enum(self) -> Dict:
        """Execute ECS enumeration"""
        return self.execute_pacu_module("ecs__enum")

    def execute_eks_enum(self) -> Dict:
        """Execute EKS enumeration"""
        return self.execute_pacu_module("eks__enum")

    def execute_guardduty_enum(self) -> Dict:
        """Execute GuardDuty findings enumeration"""
        return self.execute_pacu_module("guardduty__list_findings")

    def execute_cognito_enum(self) -> Dict:
        """Execute Cognito enumeration"""
        return self.execute_pacu_module("cognito__enum")

    def execute_glue_enum(self) -> Dict:
        """Execute Glue enumeration"""
        return self.execute_pacu_module("glue__enum")

    def execute_route53_enum(self) -> Dict:
        """Execute Route53 enumeration"""
        return self.execute_pacu_module("route53__enum")

    def execute_sns_enum(self) -> Dict:
        """Execute SNS enumeration"""
        return self.execute_pacu_module("sns__enum")

    def execute_aws_cli_command(self, command: str = "s3 ls") -> Dict:
        """Execute AWS CLI command for S3 operations

        Since Pacu doesn't have an s3__enum module, we use AWS CLI directly.
        This is an internal method used by execute_s3_enum_buckets.

        Args:
            command: AWS CLI command to execute (without 'aws' prefix)

        Returns:
            Command execution results
        """
        if self.logger:
            self.logger.info(f"Executing AWS CLI command: aws {command}")

        try:
            # Try to execute AWS CLI command directly
            env = os.environ.copy()
            env["CI"] = "true"

            # On Windows, we need to use shell=True for .cmd files
            use_shell = platform.system() == "Windows"

            if use_shell:
                # For Windows, construct command as a string
                cmd = f"aws {command}"
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=60,
                    env=env,
                    shell=True,
                )
            else:
                # For Unix-like systems, use list of arguments
                result = subprocess.run(
                    ["aws"] + command.split(),
                    capture_output=True,
                    text=True,
                    timeout=60,
                    env=env,
                )

            # Determine module name based on command
            if "s3 ls" in command:
                module_name = "aws_cli_s3"
                summary = "S3 buckets listed successfully"
            elif "iam get-account-password-policy" in command:
                module_name = "aws_cli_iam_get_password_policy"
                summary = "Password policy retrieved successfully"
            elif "iam create-user" in command:
                module_name = "aws_cli_iam_create_user"
                # Extract username from command for summary
                username = (
                    command.split("--user-name")[-1].strip()
                    if "--user-name" in command
                    else "unknown"
                )
                summary = f"User '{username}' created successfully"
            else:
                module_name = f"aws_cli_{command.replace(' ', '_')}"
                summary = "AWS CLI command executed successfully"

            if result.returncode == 0:
                return {
                    "success": True,
                    "module": module_name,
                    "data": {"output": result.stdout},
                    "summary": summary,
                }
            else:
                # Return error if AWS CLI fails
                error_msg = result.stderr or f"Failed to execute: aws {command}"
                if "Unable to locate credentials" in error_msg:
                    error_msg = "AWS credentials not configured"
                elif "AccessDenied" in error_msg:
                    error_msg = "Access denied - check IAM permissions"

                return {
                    "success": False,
                    "module": module_name,
                    "error": error_msg,
                }

        except FileNotFoundError:
            return {
                "success": False,
                "module": f"aws_cli_{command.replace(' ', '_')}",
                "error": "AWS CLI not installed. Please install AWS CLI.",
            }
        except subprocess.CalledProcessError as e:
            # This shouldn't happen since we're not using check=True
            return {
                "success": False,
                "module": f"aws_cli_{command.replace(' ', '_')}",
                "error": f"AWS CLI execution failed: {str(e)}",
            }
        except Exception as e:
            return {
                "success": False,
                "module": f"aws_cli_{command.replace(' ', '_')}",
                "error": f"Unexpected error executing AWS CLI: {str(e)}",
            }

    def parse_results(self, results: Dict) -> Dict:
        """
        Parse Pacu execution results into OpenAEV format

        Args:
            results: Raw results from Pacu module execution

        Returns:
            Formatted results for OpenAEV with structured outputs
        """

        if not results.get("success"):
            error_msg = results.get("error", "Unknown error")
            if self.logger:
                self.logger.error(f"Module execution failed: {error_msg}")

            # Simplify error message for outputs
            if "ImportError" in error_msg or "cannot import" in error_msg:
                simple_error = "Pacu not properly installed"
            elif "SIGINT" in error_msg or "interrupted" in error_msg:
                simple_error = "Module execution interrupted"
            else:
                # Clean and truncate error message
                simple_error = (
                    error_msg.replace("\\", "/").replace("\n", " ").strip()[:100]
                )

            return {
                "success": False,
                "message": f"Module execution failed: {simple_error}",
                "outputs": {"error": simple_error},
            }

        module_name = results.get("module", "unknown")
        data = results.get("data", {})
        summary = results.get("summary", "")

        if self.logger:
            self.logger.info(f"Processing successful results for module: {module_name}")

        # Parse S3 bucket enumeration (AWS CLI)
        if "aws_cli_s3" in module_name:
            output = data.get("output", "")
            buckets = []

            # Parse AWS CLI S3 ls output
            # Format: "2025-07-29 06:15:56 bucket-name"
            for line in output.strip().split("\n"):
                if line.strip():
                    parts = line.strip().split(None, 2)
                    if len(parts) >= 3:
                        # Extract bucket name (third part)
                        buckets.append(parts[2])

            message = f"Found {len(buckets)} S3 buckets"
            if self.logger:
                self.logger.info(message)

            return {
                "success": True,
                "message": message,
                "outputs": {
                    "buckets": buckets,
                },
            }

        # Parse IAM password policy (AWS CLI)
        elif "aws_cli_iam_get_password_policy" in module_name:
            output = data.get("output", "")

            # Parse JSON output from AWS CLI
            try:
                policy_data = json.loads(output)
                password_policy = policy_data.get("PasswordPolicy", {})

                # Format the policy into a readable string
                policy_items = []
                if "MinimumPasswordLength" in password_policy:
                    policy_items.append(
                        f"Minimum Length: {password_policy['MinimumPasswordLength']}"
                    )
                if "RequireSymbols" in password_policy:
                    policy_items.append(
                        f"Require Symbols: {password_policy['RequireSymbols']}"
                    )
                if "RequireNumbers" in password_policy:
                    policy_items.append(
                        f"Require Numbers: {password_policy['RequireNumbers']}"
                    )
                if "RequireUppercaseCharacters" in password_policy:
                    policy_items.append(
                        f"Require Uppercase: {password_policy['RequireUppercaseCharacters']}"
                    )
                if "RequireLowercaseCharacters" in password_policy:
                    policy_items.append(
                        f"Require Lowercase: {password_policy['RequireLowercaseCharacters']}"
                    )
                if "AllowUsersToChangePassword" in password_policy:
                    policy_items.append(
                        f"Allow Users to Change Password: {password_policy['AllowUsersToChangePassword']}"
                    )
                if "ExpirePasswords" in password_policy:
                    policy_items.append(
                        f"Password Expiration: {password_policy['ExpirePasswords']}"
                    )
                if "MaxPasswordAge" in password_policy:
                    policy_items.append(
                        f"Max Password Age: {password_policy['MaxPasswordAge']} days"
                    )
                if "PasswordReusePrevention" in password_policy:
                    policy_items.append(
                        f"Password Reuse Prevention: {password_policy['PasswordReusePrevention']} passwords"
                    )
                if "HardExpiry" in password_policy:
                    policy_items.append(f"Hard Expiry: {password_policy['HardExpiry']}")

                policy_summary = " | ".join(policy_items)

                message = f"Retrieved password policy: {len(policy_items)} settings"
                if self.logger:
                    self.logger.info(message)

                return {
                    "success": True,
                    "message": message,
                    "outputs": {
                        "password_policy": policy_summary,
                    },
                }
            except (json.JSONDecodeError, KeyError) as e:
                # Handle parsing error
                if self.logger:
                    self.logger.error(f"Failed to parse password policy: {e}")

                return {
                    "success": False,
                    "message": f"Failed to parse password policy: {str(e)}",
                    "outputs": {"error": str(e)},
                }

        # Parse IAM create user (AWS CLI)
        elif "aws_cli_iam_create_user" in module_name:
            output = data.get("output", "")

            # Parse JSON output from AWS CLI
            try:
                user_data = json.loads(output) if output else {}
                user = user_data.get("User", {})

                # Extract user details
                username = user.get("UserName", "unknown")

                message = f"Successfully created IAM user: {username}"
                if self.logger:
                    self.logger.info(message)

                # For attack actions, we return minimal output
                return {
                    "success": True,
                    "message": message,
                    "outputs": {},  # No outputs for attack actions
                }
            except (json.JSONDecodeError, KeyError) as e:
                # If we can't parse JSON, it might be an error
                if (
                    "EntityAlreadyExists" in output
                    or "already exists" in output.lower()
                ):
                    message = "User already exists"
                elif "AccessDenied" in output:
                    message = "Access denied - insufficient permissions to create user"
                else:
                    message = (
                        f"Failed to create user: {str(e) if e else 'Unknown error'}"
                    )

                if self.logger:
                    self.logger.error(message)

                return {
                    "success": False,
                    "message": message,
                    "outputs": {},
                }

        # Parse IAM permissions enumeration
        elif "iam__enum_permissions" in module_name:
            # Parse stdout for permissions
            stdout = data.get("stdout", "")
            permissions = self._parse_iam_permissions(stdout)

            message = f"Found {len(permissions)} IAM permissions"
            if self.logger:
                self.logger.info(message)

            return {
                "success": True,
                "message": message,
                "outputs": {
                    "permissions": permissions,
                },
            }

        # Parse IAM users, roles, policies, groups enumeration
        elif "iam__enum_users" in module_name:
            stdout = data.get("stdout", "")
            users, roles, policies, groups = self._parse_iam_entities(stdout)

            message = f"Found {len(users)} users, {len(roles)} roles, {len(policies)} policies, {len(groups)} groups"
            if self.logger:
                self.logger.info(message)

            return {
                "success": True,
                "message": message,
                "outputs": {
                    "users": users,
                    "roles": roles,
                    "policies": policies,
                    "groups": groups,
                },
            }

        # Parse IAM roles enumeration
        elif "iam__enum_roles" in module_name:
            stdout = data.get("stdout", "")
            roles = self._parse_iam_roles(stdout)

            message = f"Found {len(roles)} IAM roles"
            if self.logger:
                self.logger.info(message)

            return {
                "success": True,
                "message": message,
                "outputs": {
                    "roles": roles,
                },
            }

        # Parse IAM privilege escalation scan
        elif "privesc" in module_name:
            stdout = data.get("stdout", "")
            privesc_paths = self._parse_privesc_paths(stdout)

            message = f"Found {len(privesc_paths)} potential privilege escalation paths"
            if self.logger:
                self.logger.info(message)

            return {
                "success": True,
                "message": message,
                "outputs": {
                    "privesc_paths": privesc_paths,
                },
            }

        # Parse EC2 enumeration
        elif "ec2__enum" in module_name:
            stdout = data.get("stdout", "")
            instances, security_groups = self._parse_ec2_data(stdout)

            message = f"Found {len(instances)} EC2 instances, {len(security_groups)} security groups"
            if self.logger:
                self.logger.info(message)

            return {
                "success": True,
                "message": message,
                "outputs": {
                    "instances": instances,
                    "security_groups": security_groups,
                },
            }

        # Parse Lambda enumeration
        elif "lambda__enum" in module_name:
            stdout = data.get("stdout", "")
            functions = self._parse_lambda_functions(stdout)

            message = f"Found {len(functions)} Lambda functions"
            if self.logger:
                self.logger.info(message)

            return {
                "success": True,
                "message": message,
                "outputs": {
                    "functions": functions,
                },
            }

        # Generic parsing for other modules - extract key entities
        else:
            stdout = data.get("stdout", "") or data.get("output", "")
            parsed_data = self._generic_parse(module_name, stdout)

            if self.logger:
                self.logger.info(f"Module {module_name} completed")

            return {
                "success": True,
                "message": summary or f"Module {module_name} completed",
                "outputs": parsed_data,
            }

    def _parse_iam_permissions(self, stdout: str) -> List[str]:
        """Parse IAM permissions from Pacu output"""
        permissions = []
        for line in stdout.split("\n"):
            # Look for permission patterns like "Action: s3:GetObject"
            if "Action:" in line or "Permission:" in line:
                perm = line.split(":", 1)[1].strip() if ":" in line else line.strip()
                if perm and perm not in permissions:
                    permissions.append(perm)
        return permissions

    def _parse_iam_entities(
        self, stdout: str
    ) -> Tuple[List[str], List[str], List[str], List[str]]:
        """Parse IAM users, roles, policies, and groups from Pacu output"""
        users = []
        roles = []
        policies = []
        groups = []

        current_section = None
        for line in stdout.split("\n"):
            line = line.strip()

            # Detect sections
            if "Users:" in line or "IAM Users" in line:
                current_section = "users"
            elif "Roles:" in line or "IAM Roles" in line:
                current_section = "roles"
            elif "Policies:" in line or "IAM Policies" in line:
                current_section = "policies"
            elif "Groups:" in line or "IAM Groups" in line:
                current_section = "groups"
            elif line and not line.startswith("[") and not line.startswith("{"):
                # Parse entity names
                if current_section == "users" and line not in users:
                    users.append(line)
                elif current_section == "roles" and line not in roles:
                    roles.append(line)
                elif current_section == "policies" and line not in policies:
                    policies.append(line)
                elif current_section == "groups" and line not in groups:
                    groups.append(line)

        return users, roles, policies, groups

    def _parse_iam_roles(self, stdout: str) -> List[str]:
        """Parse IAM roles from Pacu output"""
        roles = []
        for line in stdout.split("\n"):
            line = line.strip()
            # Look for role ARNs or role names
            if "arn:aws:iam::" in line and "role/" in line:
                # Extract role name from ARN
                role_name = (
                    line.split("role/")[1].split()[0] if "role/" in line else line
                )
                if role_name not in roles:
                    roles.append(role_name)
            elif "Role:" in line:
                role_name = line.split(":", 1)[1].strip()
                if role_name and role_name not in roles:
                    roles.append(role_name)
        return roles

    def _parse_privesc_paths(self, stdout: str) -> List[str]:
        """Parse privilege escalation paths from Pacu output"""
        privesc_paths = []
        for line in stdout.split("\n"):
            line = line.strip()
            # Look for privilege escalation indicators
            if any(
                keyword in line.lower()
                for keyword in ["escalation", "privesc", "vulnerable", "exploit"]
            ):
                if line not in privesc_paths:
                    privesc_paths.append(line)
        return privesc_paths

    def _parse_ec2_data(self, stdout: str) -> Tuple[List[str], List[str]]:
        """Parse EC2 instances and security groups from Pacu output"""
        instances = []
        security_groups = []

        for line in stdout.split("\n"):
            line = line.strip()
            # Look for instance IDs
            if "i-" in line and len(line.split("i-")[1]) >= 8:
                instance_id = "i-" + line.split("i-")[1].split()[0]
                if instance_id not in instances:
                    instances.append(instance_id)
            # Look for security group IDs
            elif "sg-" in line:
                sg_id = "sg-" + line.split("sg-")[1].split()[0]
                if sg_id not in security_groups:
                    security_groups.append(sg_id)

        return instances, security_groups

    def _parse_lambda_functions(self, stdout: str) -> List[str]:
        """Parse Lambda function names from Pacu output"""
        functions = []
        for line in stdout.split("\n"):
            line = line.strip()
            # Look for function names or ARNs
            if "arn:aws:lambda:" in line:
                # Extract function name from ARN
                func_name = (
                    line.split("function:")[1].split()[0]
                    if "function:" in line
                    else line
                )
                if func_name not in functions:
                    functions.append(func_name)
            elif "Function:" in line or "FunctionName:" in line:
                func_name = line.split(":", 1)[1].strip()
                if func_name and func_name not in functions:
                    functions.append(func_name)
        return functions

    def _generic_parse(self, module_name: str, stdout: str) -> Dict:
        """Generic parser for other module types"""
        outputs = {}

        # Module-specific parsing
        if "rds" in module_name:
            outputs["databases"] = self._extract_items(
                stdout, ["DBInstanceIdentifier", "Database:", "RDS:"]
            )
        elif "secrets" in module_name:
            outputs["secrets"] = self._extract_items(
                stdout, ["SecretName:", "Secret:", "ARN:"]
            )
        elif "ssm" in module_name or "parameter" in module_name:
            outputs["parameters"] = self._extract_items(
                stdout, ["Parameter:", "Name:", "SSM:"]
            )
        elif "vpc" in module_name:
            outputs["vpcs"] = self._extract_items(stdout, ["vpc-", "VPC:", "VpcId:"])
        elif "cloudtrail" in module_name:
            outputs["events"] = self._extract_items(
                stdout, ["Event:", "EventName:", "Trail:"]
            )
        elif "organizations" in module_name:
            outputs["organizations"] = self._extract_items(
                stdout, ["Account:", "Organization:", "OrgId:"]
            )
        elif "ebs" in module_name:
            outputs["snapshots"] = self._extract_items(
                stdout, ["snap-", "Snapshot:", "SnapshotId:"]
            )
        elif "dynamodb" in module_name:
            outputs["tables"] = self._extract_items(
                stdout, ["Table:", "TableName:", "DynamoDB:"]
            )
        elif "ecr" in module_name:
            outputs["repositories"] = self._extract_items(
                stdout, ["Repository:", "RepositoryName:", "ECR:"]
            )
        elif "ecs" in module_name:
            outputs["clusters"] = self._extract_items(
                stdout, ["Cluster:", "ClusterArn:", "ECS:"]
            )
        elif "eks" in module_name:
            outputs["clusters"] = self._extract_items(
                stdout, ["Cluster:", "ClusterName:", "EKS:"]
            )
        elif "guardduty" in module_name:
            outputs["findings"] = self._extract_items(
                stdout, ["Finding:", "FindingId:", "GuardDuty:"]
            )
        elif "cognito" in module_name:
            outputs["user_pools"] = self._extract_items(
                stdout, ["UserPool:", "PoolId:", "Cognito:"]
            )
        elif "glue" in module_name:
            outputs["databases"] = self._extract_items(
                stdout, ["Database:", "DatabaseName:", "Glue:"]
            )
        elif "route53" in module_name:
            outputs["hosted_zones"] = self._extract_items(
                stdout, ["HostedZone:", "Zone:", "Route53:"]
            )
        elif "sns" in module_name:
            outputs["topics"] = self._extract_items(
                stdout, ["Topic:", "TopicArn:", "SNS:"]
            )
        else:
            # Default: try to extract any identifiable items
            outputs["items"] = self._extract_items(
                stdout, ["Name:", "Id:", "ARN:", "Identifier:"]
            )

        # Remove empty lists
        outputs = {k: v for k, v in outputs.items() if v}

        return outputs

    def _extract_items(self, text: str, patterns: List[str]) -> List[str]:
        """Extract items matching any of the given patterns"""
        items = []
        for line in text.split("\n"):
            line = line.strip()
            for pattern in patterns:
                if pattern in line:
                    # Extract the value after the pattern
                    if ":" in pattern:
                        value = (
                            line.split(pattern, 1)[1].strip() if pattern in line else ""
                        )
                    else:
                        # For ID patterns like "vpc-", "snap-", extract the ID
                        value = line

                    if value and value not in items:
                        items.append(value)
                    break
        return items
