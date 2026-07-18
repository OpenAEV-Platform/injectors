"""Stratus Red Team technique catalog.

Auto-generated from the Stratus Red Team source
(github.com/DataDog/stratus-red-team, internal/attacktechniques). Each entry
mirrors one registered AttackTechnique: its id, platform, friendly name and
MITRE ATT&CK technique ids where Stratus declares them. Regenerate when the
pinned Stratus release changes.
"""

from dataclasses import dataclass
from typing import List, Tuple


@dataclass(frozen=True)
class Technique:
    id: str
    platform: str
    name: str
    attack_patterns: Tuple[str, ...] = ()


TECHNIQUES: List[Technique] = [
    Technique(
        "aws.credential-access.ec2-get-password-data",
        "aws",
        "Retrieve EC2 Password Data",
    ),
    Technique(
        "aws.credential-access.ec2-steal-instance-credentials",
        "aws",
        "Steal EC2 Instance Credentials",
        ("T1552.005",),
    ),
    Technique(
        "aws.credential-access.secretsmanager-batch-retrieve-secrets",
        "aws",
        "Retrieve a High Number of Secrets Manager secrets (Batch)",
    ),
    Technique(
        "aws.credential-access.secretsmanager-retrieve-secrets",
        "aws",
        "Retrieve a High Number of Secrets Manager secrets",
    ),
    Technique(
        "aws.credential-access.ssm-retrieve-securestring-parameters",
        "aws",
        "Retrieve And Decrypt SSM Parameters",
    ),
    Technique(
        "aws.defense-evasion.cloudtrail-delete",
        "aws",
        "Delete CloudTrail Trail",
        ("T1562.008",),
    ),
    Technique(
        "aws.defense-evasion.cloudtrail-event-selectors",
        "aws",
        "Disable CloudTrail Logging Through Event Selectors",
        ("T1562.008",),
    ),
    Technique(
        "aws.defense-evasion.cloudtrail-lifecycle-rule",
        "aws",
        "CloudTrail Logs Impairment Through S3 Lifecycle Rule",
        ("T1562.008",),
    ),
    Technique(
        "aws.defense-evasion.cloudtrail-stop",
        "aws",
        "Stop CloudTrail Trail",
        ("T1562.008",),
    ),
    Technique("aws.defense-evasion.dns-delete-logs", "aws", "Delete DNS query logs"),
    Technique(
        "aws.defense-evasion.organizations-leave",
        "aws",
        "Attempt to Leave the AWS Organization",
    ),
    Technique(
        "aws.defense-evasion.vpc-remove-flow-logs", "aws", "Remove VPC Flow Logs"
    ),
    Technique(
        "aws.discovery.ec2-download-user-data", "aws", "Download EC2 Instance User Data"
    ),
    Technique(
        "aws.discovery.ec2-enumerate-from-instance",
        "aws",
        "Execute Discovery Commands on an EC2 Instance",
    ),
    Technique("aws.discovery.ses-enumerate", "aws", "Enumerate SES"),
    Technique(
        "aws.execution.ec2-launch-unusual-instances",
        "aws",
        "Launch Unusual EC2 instances",
        ("T1578.002",),
    ),
    Technique(
        "aws.execution.ec2-user-data",
        "aws",
        "Execute Commands on EC2 Instance via User Data",
    ),
    Technique(
        "aws.execution.sagemaker-update-lifecycle-config",
        "aws",
        "Execute Commands on SageMaker Notebook Instance via Lifecycle Configuration",
    ),
    Technique(
        "aws.execution.ssm-send-command",
        "aws",
        "Usage of ssm:SendCommand on multiple instances",
    ),
    Technique(
        "aws.execution.ssm-start-session",
        "aws",
        "Usage of ssm:StartSession on multiple instances",
    ),
    Technique(
        "aws.exfiltration.ec2-security-group-open-port-22-ingress",
        "aws",
        "Open Ingress Port 22 on a Security Group",
        ("T1562.007",),
    ),
    Technique(
        "aws.exfiltration.ec2-share-ami", "aws", "Exfiltrate an AMI by Sharing It"
    ),
    Technique(
        "aws.exfiltration.ec2-share-ebs-snapshot",
        "aws",
        "Exfiltrate EBS Snapshot by Sharing It",
        ("T1578.001",),
    ),
    Technique(
        "aws.exfiltration.rds-share-snapshot",
        "aws",
        "Exfiltrate RDS Snapshot by Sharing",
    ),
    Technique(
        "aws.exfiltration.s3-backdoor-bucket-policy",
        "aws",
        "Backdoor an S3 Bucket via its Bucket Policy",
    ),
    Technique("aws.impact.bedrock-invoke-model", "aws", "Invoke Bedrock Model"),
    Technique(
        "aws.impact.s3-ransomware-batch-deletion",
        "aws",
        "S3 Ransomware through batch file deletion",
    ),
    Technique(
        "aws.impact.s3-ransomware-client-side-encryption",
        "aws",
        "S3 Ransomware through client-side encryption",
    ),
    Technique(
        "aws.impact.s3-ransomware-individual-deletion",
        "aws",
        "S3 Ransomware through individual file deletion",
    ),
    Technique(
        "aws.initial-access.console-login-without-mfa",
        "aws",
        "Console Login without MFA",
    ),
    Technique(
        "aws.lateral-movement.ec2-instance-connect",
        "aws",
        "Usage of EC2 Instance Connect on multiple instances",
    ),
    Technique(
        "aws.lateral-movement.ec2-serial-console-send-ssh-public-key",
        "aws",
        "Usage of EC2 Serial Console to push SSH public key",
    ),
    Technique("aws.persistence.iam-backdoor-role", "aws", "Backdoor an IAM Role"),
    Technique(
        "aws.persistence.iam-backdoor-user",
        "aws",
        "Create an Access Key on an IAM User",
        ("T1098.001",),
    ),
    Technique(
        "aws.persistence.iam-create-admin-user",
        "aws",
        "Create an administrative IAM User",
        ("T1136.003",),
    ),
    Technique(
        "aws.persistence.iam-create-backdoor-role",
        "aws",
        "Create a backdoored IAM Role",
        ("T1098.003",),
    ),
    Technique(
        "aws.persistence.iam-create-user-login-profile",
        "aws",
        "Create a Login Profile on an IAM User",
        ("T1098.001",),
    ),
    Technique(
        "aws.persistence.lambda-backdoor-function",
        "aws",
        "Backdoor Lambda Function Through Resource-Based Policy",
    ),
    Technique(
        "aws.persistence.lambda-layer-extension",
        "aws",
        "Add a Malicious Lambda Extension",
    ),
    Technique(
        "aws.persistence.lambda-overwrite-code", "aws", "Overwrite Lambda Function Code"
    ),
    Technique(
        "aws.persistence.rolesanywhere-create-trust-anchor",
        "aws",
        "Create an IAM Roles Anywhere trust anchor",
    ),
    Technique(
        "aws.persistence.sts-federation-token",
        "aws",
        "Generate temporary AWS credentials using GetFederationToken",
        ("T1098.001",),
    ),
    Technique(
        "aws.privilege-escalation.iam-update-user-login-profile",
        "aws",
        "Change IAM user password",
    ),
    Technique(
        "azure.credential-access.app-service-publishing-credentials",
        "azure",
        "Retrieve App Service Publishing Credentials",
    ),
    Technique(
        "azure.execution.vm-custom-script-extension",
        "azure",
        "Execute Command on Virtual Machine using Custom Script Extension",
    ),
    Technique(
        "azure.execution.vm-run-command",
        "azure",
        "Execute Commands on Virtual Machine using Run Command",
    ),
    Technique("azure.exfiltration.disk-export", "azure", "Export Disk Through SAS URL"),
    Technique(
        "azure.exfiltration.storage-public-access",
        "azure",
        "Exfiltrate Azure Storage via public access",
    ),
    Technique(
        "azure.exfiltration.storage-sas-export",
        "azure",
        "Exfiltrate Azure Storage through SAS URL",
    ),
    Technique(
        "azure.impact.blob-ransomware-client-encryption-scope",
        "azure",
        "Azure Blob Storage ransomware through Encryption Scope using client-managed Key Vault key",
    ),
    Technique(
        "azure.impact.blob-ransomware-cpek",
        "azure",
        "Azure Blob Storage ransomware through Customer-Provided Encryption Keys",
    ),
    Technique(
        "azure.impact.blob-ransomware-individual-file-deletion",
        "azure",
        "Azure ransomware via Storage Account Blob deletion",
    ),
    Technique(
        "azure.impact.blob-ransomware-service-storage-cmk",
        "azure",
        "Azure Blob Storage ransomware through Customer-Managed Key Vault key and vault deletion",
    ),
    Technique("azure.impact.resource-lock", "azure", "Delete Azure resource lock"),
    Technique(
        "azure.persistence.backdoor-managed-identity-fic",
        "azure",
        "Backdoor Azure Managed Identity with Federated Identity Credential (FIC)",
    ),
    Technique(
        "azure.persistence.create-bastion-shareable-link",
        "azure",
        "Create Azure VM Bastion shareable link",
    ),
    Technique(
        "azure.privilege-escalation.root-user-access-administrator",
        "azure",
        "Elevate to User Access Administrator at Root Scope",
    ),
    Technique(
        "entra-id.persistence.backdoor-application",
        "entra-id",
        "Backdoor Entra ID application",
    ),
    Technique(
        "entra-id.persistence.backdoor-application-fic",
        "entra-id",
        "Backdoor Entra ID application with Federated Identity Credential (FIC)",
    ),
    Technique(
        "entra-id.persistence.backdoor-application-sp",
        "entra-id",
        "Backdoor Entra ID application through service principal",
    ),
    Technique("entra-id.persistence.guest-user", "entra-id", "Create Guest User"),
    Technique(
        "entra-id.persistence.hidden-au",
        "entra-id",
        "Create Hidden Scoped Role Assignment Through HiddenMembership AU",
    ),
    Technique("entra-id.persistence.new-application", "entra-id", "Create Application"),
    Technique(
        "entra-id.persistence.restricted-au",
        "entra-id",
        "Create Sticky Backdoor User Through Restricted Management AU",
    ),
    Technique(
        "gcp.credential-access.secretmanager-retrieve-secrets",
        "gcp",
        "Retrieve a High Number of Secret Manager secrets",
    ),
    Technique(
        "gcp.defense-evasion.delete-dns-logs",
        "gcp",
        "Delete a Cloud DNS Logging Policy",
    ),
    Technique(
        "gcp.defense-evasion.delete-logging-sink", "gcp", "Delete a GCP Log Sink"
    ),
    Technique(
        "gcp.defense-evasion.disable-audit-logs",
        "gcp",
        "Disable Data Access Audit Logs for a GCP Service",
    ),
    Technique(
        "gcp.defense-evasion.disable-logging-sink", "gcp", "Disable a GCP Log Sink"
    ),
    Technique(
        "gcp.defense-evasion.reduce-sink-log-retention",
        "gcp",
        "Reduce Log Retention Period on a Cloud Logging Sink Bucket",
    ),
    Technique(
        "gcp.defense-evasion.remove-project-from-organization",
        "gcp",
        "Attempt to Remove a GCP Project from its Organization",
    ),
    Technique(
        "gcp.defense-evasion.remove-vpc-flow-logs",
        "gcp",
        "Disable VPC Flow Logs on a Subnet",
    ),
    Technique(
        "gcp.discovery.download-instance-metadata",
        "gcp",
        "Read GCE Instance Metadata via the Compute API",
    ),
    Technique(
        "gcp.discovery.enumerate-permissions",
        "gcp",
        "Enumerate Permissions of a GCP Service Account",
    ),
    Technique(
        "gcp.execution.modify-vertex-notebook-startup",
        "gcp",
        "Inject a Malicious Startup Script into a Vertex AI Workbench Instance",
    ),
    Technique(
        "gcp.exfiltration.share-compute-disk",
        "gcp",
        "Exfiltrate Compute Disk by sharing it",
    ),
    Technique(
        "gcp.exfiltration.share-compute-image",
        "gcp",
        "Exfiltrate Compute Image by sharing it",
    ),
    Technique(
        "gcp.exfiltration.share-compute-snapshot",
        "gcp",
        "Exfiltrate Compute Disk by sharing a snapshot",
    ),
    Technique("gcp.impact.create-gpu-vm", "gcp", "Create a GCE GPU Virtual Machine"),
    Technique(
        "gcp.impact.create-instances-in-multiple-zones",
        "gcp",
        "Create GCE Instances in Multiple Zones",
    ),
    Technique(
        "gcp.impact.gcs-ransomware-client-side-encryption",
        "gcp",
        "GCS Ransomware through client-side encryption",
    ),
    Technique(
        "gcp.impact.gcs-ransomware-individual-deletion",
        "gcp",
        "GCS Ransomware through individual file deletion",
    ),
    Technique(
        "gcp.initial-access.use-compute-sa-outside-gcp",
        "gcp",
        "Steal and Use the GCE Default Service Account Token from Outside Google Cloud",
    ),
    Technique(
        "gcp.lateral-movement.add-sshkey-instance-metadata",
        "gcp",
        "Register SSH public key to instance metadata",
    ),
    Technique(
        "gcp.persistence.backdoor-service-account-policy",
        "gcp",
        "Backdoor a GCP Service Account through its IAM Policy",
    ),
    Technique(
        "gcp.persistence.create-admin-service-account",
        "gcp",
        "Create an Admin GCP Service Account",
    ),
    Technique(
        "gcp.persistence.create-service-account-key",
        "gcp",
        "Create a GCP Service Account Key",
    ),
    Technique(
        "gcp.persistence.invite-external-user",
        "gcp",
        "Invite an External User to a GCP Project",
    ),
    Technique(
        "gcp.privilege-escalation.impersonate-service-accounts",
        "gcp",
        "Impersonate GCP Service Accounts",
    ),
    Technique("k8s.credential-access.dump-secrets", "k8s", "Dump All Secrets"),
    Technique(
        "k8s.credential-access.steal-serviceaccount-token",
        "k8s",
        "Steal Pod Service Account Token",
    ),
    Technique(
        "k8s.persistence.create-admin-clusterrole", "k8s", "Create Admin ClusterRole"
    ),
    Technique(
        "k8s.persistence.create-client-certificate",
        "k8s",
        "Create Client Certificate Credential",
    ),
    Technique("k8s.persistence.create-token", "k8s", "Create Long-Lived Token"),
    Technique(
        "k8s.privilege-escalation.hostpath-volume",
        "k8s",
        "Container breakout via hostPath volume mount",
    ),
    Technique(
        "k8s.privilege-escalation.nodes-proxy",
        "k8s",
        "Privilege escalation through node/proxy permissions",
    ),
    Technique("k8s.privilege-escalation.privileged-pod", "k8s", "Run a Privileged Pod"),
    Technique(
        "eks.lateral-movement.create-access-entry",
        "eks",
        "Create Admin EKS Access Entry",
    ),
    Technique(
        "eks.persistence.backdoor-aws-auth-configmap",
        "eks",
        "Backdoor aws-auth EKS ConfigMap",
    ),
]
