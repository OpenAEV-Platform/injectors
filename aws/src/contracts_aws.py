from typing import List

from pyoaev.contracts import ContractBuilder
from pyoaev.contracts.contract_config import (
    Contract,
    ContractCardinality,
    ContractConfig,
    ContractElement,
    ContractExpectations,
    ContractOutputElement,
    ContractOutputType,
    ContractSelect,
    ContractText,
    Expectation,
    ExpectationType,
    SupportedLanguage,
    prepare_contracts,
)
from pyoaev.security_domain.types import SecurityDomains

TYPE = "openaev_aws"

# Contract IDs for different AWS modules
IAM_ENUM_PERMISSIONS_CONTRACT = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
IAM_ENUM_USERS_CONTRACT = "b2c3d4e5-f6a7-8901-bcde-f12345678901"
IAM_ENUM_ROLES_CONTRACT = "c3d4e5f6-a7b8-9012-cdef-123456789012"
IAM_PRIVESC_SCAN_CONTRACT = "d4e5f6a7-b8c9-0123-defa-234567890123"
IAM_GET_PASSWORD_POLICY_CONTRACT = "b6c7d8e9-f0a1-2345-bcde-345678901234"
IAM_CREATE_USER_CONTRACT = "c7d8e9f0-a1b2-3456-cdef-456789012345"
EC2_ENUM_INSTANCES_CONTRACT = "e5f6a7b8-c9d0-1234-efab-345678901234"
EC2_ENUM_SECURITY_GROUPS_CONTRACT = "f6a7b8c9-d0e1-2345-fabc-456789012345"
S3_ENUM_BUCKETS_CONTRACT = "a7b8c9d0-e1f2-3456-abcd-567890123456"
S3_DOWNLOAD_BUCKET_CONTRACT = "b8c9d0e1-f2a3-4567-bcde-678901234567"
LAMBDA_ENUM_FUNCTIONS_CONTRACT = "c9d0e1f2-a3b4-5678-cdef-789012345678"
CLOUDTRAIL_ENUM_CONTRACT = "d0e1f2a3-b4c5-6789-defa-890123456789"
VPC_ENUM_CONTRACT = "e1f2a3b4-c5d6-7890-efab-901234567890"
RDS_ENUM_DATABASES_CONTRACT = "f2a3b4c5-d6e7-8901-fabc-012345678901"
SECRETS_MANAGER_ENUM_CONTRACT = "a3b4c5d6-e7f8-9012-abcd-123456789012"
SSM_ENUM_PARAMETERS_CONTRACT = "b4c5d6e7-f8a9-0123-bcde-234567890123"
ORGANIZATIONS_ENUM_CONTRACT = "c5d6e7f8-a9b0-1234-cdef-345678901234"
EBS_ENUM_SNAPSHOTS_CONTRACT = "d6e7f8a9-b0c1-2345-defa-456789012345"
DYNAMODB_ENUM_CONTRACT = "e7f8a9b0-c1d2-3456-efab-567890123456"
ECR_ENUM_CONTRACT = "f8a9b0c1-d2e3-4567-fabc-678901234567"
ECS_ENUM_CONTRACT = "a9b0c1d2-e3f4-5678-abcd-789012345678"
EKS_ENUM_CONTRACT = "b0c1d2e3-f4a5-6789-bcde-890123456789"
GUARDDUTY_ENUM_CONTRACT = "c1d2e3f4-a5b6-7890-cdef-901234567890"
COGNITO_ENUM_CONTRACT = "d2e3f4a5-b6c7-8901-defa-012345678901"
GLUE_ENUM_CONTRACT = "e3f4a5b6-c7d8-9012-efab-123456789012"
ROUTE53_ENUM_CONTRACT = "f4a5b6c7-d8e9-0123-fabc-234567890123"
SNS_ENUM_CONTRACT = "a5b6c7d8-e9f0-1234-abcd-345678901234"


class AWSContracts:
    @staticmethod
    def build_contract():
        # Config
        contract_config = ContractConfig(
            type=TYPE,
            label={
                SupportedLanguage.en: "AWS Exploitation",
                SupportedLanguage.fr: "Exploitation AWS",
            },
            color_dark="#ff9800",
            color_light="#ff9800",
            expose=True,
        )

        # Common fields for AWS credentials
        aws_access_key = ContractText(
            key="aws_access_key_id",
            label="AWS Access Key ID",
            mandatory=True,
        )

        aws_secret_key = ContractText(
            key="aws_secret_access_key",
            label="AWS Secret Access Key",
            mandatory=True,
        )

        aws_session_token = ContractText(
            key="aws_session_token",
            label="AWS Session Token (optional for temporary credentials)",
            mandatory=False,
        )

        aws_region = ContractSelect(
            key="aws_region",
            label="AWS Region",
            defaultValue=["us-east-1"],
            mandatory=True,
            choices={
                # North America
                "us-east-1": "US East (N. Virginia)",
                "us-east-2": "US East (Ohio)",
                "us-west-1": "US West (N. California)",
                "us-west-2": "US West (Oregon)",
                "ca-central-1": "Canada (Central)",
                "ca-west-1": "Canada West (Calgary)",
                # South America
                "sa-east-1": "South America (São Paulo)",
                # Europe
                "eu-west-1": "EU (Ireland)",
                "eu-west-2": "EU (London)",
                "eu-west-3": "EU (Paris)",
                "eu-central-1": "EU (Frankfurt)",
                "eu-central-2": "EU (Zurich)",
                "eu-north-1": "EU (Stockholm)",
                "eu-south-1": "EU (Milan)",
                "eu-south-2": "EU (Spain)",
                # Middle East
                "me-south-1": "Middle East (Bahrain)",
                "me-central-1": "Middle East (UAE)",
                "il-central-1": "Israel (Tel Aviv)",
                # Africa
                "af-south-1": "Africa (Cape Town)",
                # Asia Pacific
                "ap-east-1": "Asia Pacific (Hong Kong)",
                "ap-south-1": "Asia Pacific (Mumbai)",
                "ap-south-2": "Asia Pacific (Hyderabad)",
                "ap-northeast-1": "Asia Pacific (Tokyo)",
                "ap-northeast-2": "Asia Pacific (Seoul)",
                "ap-northeast-3": "Asia Pacific (Osaka)",
                "ap-southeast-1": "Asia Pacific (Singapore)",
                "ap-southeast-2": "Asia Pacific (Sydney)",
                "ap-southeast-3": "Asia Pacific (Jakarta)",
                "ap-southeast-4": "Asia Pacific (Melbourne)",
                "ap-southeast-5": "Asia Pacific (Kuala Lumpur)",
                "ap-southeast-6": "Asia Pacific (Bangkok)",
                # China
                "cn-north-1": "China (Beijing)",
                "cn-northwest-1": "China (Ningxia)",
                # AWS GovCloud
                "us-gov-east-1": "AWS GovCloud (US-East)",
                "us-gov-west-1": "AWS GovCloud (US-West)",
            },
        )

        # Common expectations
        expectations = ContractExpectations(
            key="expectations",
            label="Expectations",
            mandatory=False,
            cardinality=ContractCardinality.Multiple,
            predefinedExpectations=[
                Expectation(
                    expectation_type=ExpectationType.detection,
                    expectation_name="Detection",
                    expectation_description="",
                    expectation_score=100,
                    expectation_expectation_group=False,
                )
            ],
        )

        # Output types for different modules

        # Generic JSON output (fallback)
        output_json = ContractOutputElement(
            type=ContractOutputType.Text,
            field="results",
            isMultiple=False,
            isFindingCompatible=False,
            labels=["aws", "raw"],
        )

        # S3 Outputs
        output_s3_buckets = ContractOutputElement(
            type=ContractOutputType.Text,
            field="buckets",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["aws", "s3", "bucket"],
        )

        # IAM Outputs
        output_iam_permissions = ContractOutputElement(
            type=ContractOutputType.Text,
            field="permissions",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["aws", "iam", "permission"],
        )

        output_iam_users = ContractOutputElement(
            type=ContractOutputType.Text,
            field="users",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["aws", "iam", "user"],
        )

        output_iam_roles = ContractOutputElement(
            type=ContractOutputType.Text,
            field="roles",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["aws", "iam", "role"],
        )

        output_iam_policies = ContractOutputElement(
            type=ContractOutputType.Text,
            field="policies",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["aws", "iam", "policy"],
        )

        output_iam_groups = ContractOutputElement(
            type=ContractOutputType.Text,
            field="groups",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["aws", "iam", "group"],
        )

        output_iam_privesc_paths = ContractOutputElement(
            type=ContractOutputType.Text,
            field="privesc_paths",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["aws", "iam", "vulnerability", "privesc"],
        )

        # IAM Password Policy Output
        output_iam_password_policy = ContractOutputElement(
            type=ContractOutputType.Text,
            field="password_policy",
            isMultiple=False,
            isFindingCompatible=True,
            labels=["aws", "iam", "password_policy"],
        )

        # EC2 Outputs
        output_ec2_instances = ContractOutputElement(
            type=ContractOutputType.Text,
            field="instances",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["aws", "ec2", "instance"],
        )

        output_ec2_security_groups = ContractOutputElement(
            type=ContractOutputType.Text,
            field="security_groups",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["aws", "ec2", "security_group"],
        )

        # Lambda Outputs
        output_lambda_functions = ContractOutputElement(
            type=ContractOutputType.Text,
            field="functions",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["aws", "lambda", "function"],
        )

        # RDS Outputs
        output_rds_databases = ContractOutputElement(
            type=ContractOutputType.Text,
            field="databases",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["aws", "rds", "database"],
        )

        # Secrets Manager Outputs
        output_secrets = ContractOutputElement(
            type=ContractOutputType.Text,
            field="secrets",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["aws", "secretsmanager", "secret"],
        )

        # SSM Outputs
        output_ssm_parameters = ContractOutputElement(
            type=ContractOutputType.Text,
            field="parameters",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["aws", "ssm", "parameter"],
        )

        # VPC Outputs
        output_vpc_networks = ContractOutputElement(
            type=ContractOutputType.Text,
            field="vpcs",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["aws", "vpc", "network"],
        )

        # CloudTrail Outputs
        output_cloudtrail_events = ContractOutputElement(
            type=ContractOutputType.Text,
            field="events",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["aws", "cloudtrail", "event"],
        )

        # Organizations Outputs
        output_organizations = ContractOutputElement(
            type=ContractOutputType.Text,
            field="organizations",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["aws", "organizations", "account"],
        )

        # EBS Outputs
        output_ebs_snapshots = ContractOutputElement(
            type=ContractOutputType.Text,
            field="snapshots",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["aws", "ebs", "snapshot"],
        )

        # DynamoDB Outputs
        output_dynamodb_tables = ContractOutputElement(
            type=ContractOutputType.Text,
            field="tables",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["aws", "dynamodb", "table"],
        )

        # ECR Outputs
        output_ecr_repositories = ContractOutputElement(
            type=ContractOutputType.Text,
            field="repositories",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["aws", "ecr", "repository"],
        )

        # ECS Outputs
        output_ecs_clusters = ContractOutputElement(
            type=ContractOutputType.Text,
            field="clusters",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["aws", "ecs", "cluster"],
        )

        # EKS Outputs
        output_eks_clusters = ContractOutputElement(
            type=ContractOutputType.Text,
            field="clusters",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["aws", "eks", "cluster"],
        )

        # GuardDuty Outputs
        output_guardduty_findings = ContractOutputElement(
            type=ContractOutputType.Text,
            field="findings",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["aws", "guardduty", "finding"],
        )

        # Cognito Outputs
        output_cognito_pools = ContractOutputElement(
            type=ContractOutputType.Text,
            field="user_pools",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["aws", "cognito", "pool"],
        )

        # Glue Outputs
        output_glue_databases = ContractOutputElement(
            type=ContractOutputType.Text,
            field="databases",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["aws", "glue", "database"],
        )

        # Route53 Outputs
        output_route53_zones = ContractOutputElement(
            type=ContractOutputType.Text,
            field="hosted_zones",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["aws", "route53", "zone"],
        )

        # SNS Outputs
        output_sns_topics = ContractOutputElement(
            type=ContractOutputType.Text,
            field="topics",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["aws", "sns", "topic"],
        )

        # Base fields for all contracts
        base_fields: List[ContractElement] = (
            ContractBuilder()
            .add_fields(
                [
                    aws_access_key,
                    aws_secret_key,
                    aws_session_token,
                    aws_region,
                    expectations,
                ]
            )
            .build_fields()
        )

        def make_contract(
            contract_id: str,
            en: str,
            fr: str,
            outputs: List[ContractOutputElement],
            fields: List[ContractElement] = None,
        ) -> Contract:
            return Contract(
                contract_id=contract_id,
                config=contract_config,
                label={
                    SupportedLanguage.en: en,
                    SupportedLanguage.fr: fr,
                },
                fields=fields or base_fields,
                outputs=(ContractBuilder().add_outputs(outputs).build_outputs()),
                manual=False,
                domains=[SecurityDomains.CLOUD.value],
            )

        # IAM Enumeration contracts
        iam_enum_permissions_contract = make_contract(
            IAM_ENUM_PERMISSIONS_CONTRACT,
            "AWS - IAM Enumerate Permissions",
            "AWS - Énumération des permissions IAM",
            [output_iam_permissions],
        )

        iam_enum_users_contract = make_contract(
            IAM_ENUM_USERS_CONTRACT,
            "AWS - IAM Enumerate Users, Roles, Policies and Groups",
            "AWS - Énumération des utilisateurs, rôles, politiques et groupes IAM",
            [
                output_iam_users,
                output_iam_roles,
                output_iam_policies,
                output_iam_groups,
            ],
        )

        iam_enum_roles_contract = make_contract(
            IAM_ENUM_ROLES_CONTRACT,
            "AWS - IAM Enumerate Roles",
            "AWS - Énumération des rôles IAM",
            [output_iam_roles],
        )

        # IAM Privilege Escalation Scan
        iam_privesc_scan_contract = make_contract(
            IAM_PRIVESC_SCAN_CONTRACT,
            "AWS - IAM Privilege Escalation Scan",
            "AWS - Scan d'escalade de privilèges IAM",
            [output_iam_privesc_paths],
        )

        # IAM Get Account Password Policy
        iam_get_password_policy_contract = make_contract(
            IAM_GET_PASSWORD_POLICY_CONTRACT,
            "AWS - IAM Get Account Password Policy",
            "AWS - Obtenir la politique de mot de passe IAM",
            [output_iam_password_policy],
        )

        # IAM Create User (Attack)
        iam_username = ContractText(
            key="username",
            label="Username to create",
            mandatory=True,
        )

        iam_create_user_fields = (
            ContractBuilder()
            .add_fields(
                [
                    aws_access_key,
                    aws_secret_key,
                    aws_session_token,
                    aws_region,
                    iam_username,
                    expectations,
                ]
            )
            .build_fields()
        )

        # No output for this attack action - it either succeeds or fails
        iam_create_user_contract = make_contract(
            IAM_CREATE_USER_CONTRACT,
            "AWS - IAM Create User (Attack)",
            "AWS - Créer un utilisateur IAM (Attaque)",
            [],  # No outputs - this is an attack action
            fields=iam_create_user_fields,
        )

        # EC2 Enumeration contracts
        ec2_enum_instances_contract = make_contract(
            EC2_ENUM_INSTANCES_CONTRACT,
            "AWS - EC2 Enumerate Instances",
            "AWS - Énumération des instances EC2",
            [output_ec2_instances, output_ec2_security_groups],
        )

        ec2_enum_security_groups_contract = make_contract(
            EC2_ENUM_SECURITY_GROUPS_CONTRACT,
            "AWS - EC2 Enumerate Security Groups",
            "AWS - Énumération des groupes de sécurité EC2",
            [output_ec2_security_groups],
        )

        # S3 contracts
        # S3 Enumeration (via AWS CLI since Pacu s3__enum module doesn't exist)
        s3_enum_buckets_contract = make_contract(
            S3_ENUM_BUCKETS_CONTRACT,
            "AWS - S3 List Buckets",
            "AWS - Lister les buckets S3",
            [output_s3_buckets],
        )

        # S3 Download specific bucket
        s3_bucket_name = ContractText(
            key="bucket_name",
            label="S3 Bucket Name",
            mandatory=True,
        )

        s3_download_fields = (
            ContractBuilder()
            .add_fields(
                [
                    aws_access_key,
                    aws_secret_key,
                    aws_session_token,
                    aws_region,
                    s3_bucket_name,
                    expectations,
                ]
            )
            .build_fields()
        )

        s3_download_bucket_contract = make_contract(
            S3_DOWNLOAD_BUCKET_CONTRACT,
            "AWS - S3 Download Bucket",
            "AWS - Télécharger le bucket S3",
            [output_json],
            fields=s3_download_fields,
        )

        # Lambda Enumeration
        lambda_enum_functions_contract = make_contract(
            LAMBDA_ENUM_FUNCTIONS_CONTRACT,
            "AWS - Lambda Enumerate Functions",
            "AWS - Énumération des fonctions Lambda",
            [output_lambda_functions],
        )

        # CloudTrail Enumeration
        cloudtrail_enum_contract = make_contract(
            CLOUDTRAIL_ENUM_CONTRACT,
            "AWS - CloudTrail Enumerate Trails",
            "AWS - Énumération CloudTrail",
            [output_cloudtrail_events],
        )

        # VPC Enumeration
        vpc_enum_contract = make_contract(
            VPC_ENUM_CONTRACT,
            "AWS - VPC Enumerate Networks",
            "AWS - Énumération des VPC",
            [output_vpc_networks],
        )

        # RDS Enumeration
        rds_enum_databases_contract = make_contract(
            RDS_ENUM_DATABASES_CONTRACT,
            "AWS - RDS Enumerate Databases",
            "AWS - Énumération des bases RDS",
            [output_rds_databases],
        )

        # Secrets Manager Enumeration
        secrets_manager_enum_contract = make_contract(
            SECRETS_MANAGER_ENUM_CONTRACT,
            "AWS - Secrets Manager Enumerate",
            "AWS - Énumération Secrets Manager",
            [output_secrets],
        )

        # SSM Parameters Enumeration
        ssm_enum_parameters_contract = make_contract(
            SSM_ENUM_PARAMETERS_CONTRACT,
            "AWS - SSM Enumerate Parameters",
            "AWS - Énumération des paramètres SSM",
            [output_ssm_parameters],
        )

        # Organizations Enumeration
        organizations_enum_contract = make_contract(
            ORGANIZATIONS_ENUM_CONTRACT,
            "AWS - Organizations Enumerate",
            "AWS - Énumération des organisations",
            [output_organizations],
        )

        # EBS Snapshots Enumeration
        ebs_enum_snapshots_contract = make_contract(
            EBS_ENUM_SNAPSHOTS_CONTRACT,
            "AWS - EBS Enumerate Snapshots",
            "AWS - Énumération des snapshots EBS",
            [output_ebs_snapshots],
        )

        # DynamoDB Enumeration
        dynamodb_enum_contract = make_contract(
            DYNAMODB_ENUM_CONTRACT,
            "AWS - DynamoDB Enumerate Tables",
            "AWS - Énumération des tables DynamoDB",
            [output_dynamodb_tables],
        )

        # ECR Enumeration
        ecr_enum_contract = make_contract(
            ECR_ENUM_CONTRACT,
            "AWS - ECR Enumerate Repositories",
            "AWS - Énumération des dépôts ECR",
            [output_ecr_repositories],
        )

        # ECS Enumeration
        ecs_enum_contract = make_contract(
            ECS_ENUM_CONTRACT,
            "AWS - ECS Enumerate Clusters",
            "AWS - Énumération des clusters ECS",
            [output_ecs_clusters],
        )

        # EKS Enumeration
        eks_enum_contract = make_contract(
            EKS_ENUM_CONTRACT,
            "AWS - EKS Enumerate Clusters",
            "AWS - Énumération des clusters EKS",
            [output_eks_clusters],
        )

        # GuardDuty Enumeration
        guardduty_enum_contract = make_contract(
            GUARDDUTY_ENUM_CONTRACT,
            "AWS - GuardDuty List Findings",
            "AWS - Liste des découvertes GuardDuty",
            [output_guardduty_findings],
        )

        # Cognito Enumeration
        cognito_enum_contract = make_contract(
            COGNITO_ENUM_CONTRACT,
            "AWS - Cognito Enumerate User Pools",
            "AWS - Énumération des pools Cognito",
            [output_cognito_pools],
        )

        # Glue Enumeration
        glue_enum_contract = make_contract(
            GLUE_ENUM_CONTRACT,
            "AWS - Glue Enumerate Databases",
            "AWS - Énumération des bases Glue",
            [output_glue_databases],
        )

        # Route53 Enumeration
        route53_enum_contract = make_contract(
            ROUTE53_ENUM_CONTRACT,
            "AWS - Route53 Enumerate Zones",
            "AWS - Énumération des zones Route53",
            [output_route53_zones],
        )

        # SNS Enumeration
        sns_enum_contract = make_contract(
            SNS_ENUM_CONTRACT,
            "AWS - SNS Enumerate Topics",
            "AWS - Énumération des topics SNS",
            [output_sns_topics],
        )

        return prepare_contracts(
            [
                iam_enum_permissions_contract,
                iam_enum_users_contract,
                iam_enum_roles_contract,
                iam_privesc_scan_contract,
                iam_get_password_policy_contract,
                iam_create_user_contract,
                ec2_enum_instances_contract,
                ec2_enum_security_groups_contract,
                s3_enum_buckets_contract,
                s3_download_bucket_contract,
                lambda_enum_functions_contract,
                cloudtrail_enum_contract,
                vpc_enum_contract,
                rds_enum_databases_contract,
                secrets_manager_enum_contract,
                ssm_enum_parameters_contract,
                organizations_enum_contract,
                ebs_enum_snapshots_contract,
                dynamodb_enum_contract,
                ecr_enum_contract,
                ecs_enum_contract,
                eks_enum_contract,
                guardduty_enum_contract,
                cognito_enum_contract,
                glue_enum_contract,
                route53_enum_contract,
                sns_enum_contract,
            ]
        )
