"""Stratus Red Team technique catalogs, grouped by platform.

Each mapping mirrors ``stratus list --platform <platform>`` for the pinned
Stratus release (see ``STRATUS_VERSION`` in the Dockerfile). The dictionaries
are consumed by the platform contracts to populate the technique selector, and
any technique id can still be supplied through the "custom technique id" field.
"""

from typing import Dict

AWS_TECHNIQUES: Dict[str, str] = {
    "aws.credential-access.ec2-get-password-data": "Credential Access - EC2 Get Password Data",
    "aws.credential-access.ec2-steal-instance-credentials": "Credential Access - EC2 Steal Instance Credentials",
    "aws.credential-access.secretsmanager-batch-retrieve-secrets": "Credential Access - SecretsManager Batch Retrieve Secrets",
    "aws.credential-access.secretsmanager-retrieve-secrets": "Credential Access - SecretsManager Retrieve Secrets",
    "aws.credential-access.ssm-retrieve-securestring-parameters": "Credential Access - SSM Retrieve Securestring Parameters",
    "aws.defense-evasion.cloudtrail-delete": "Defense Evasion - CloudTrail Delete",
    "aws.defense-evasion.cloudtrail-event-selectors": "Defense Evasion - CloudTrail Event Selectors",
    "aws.defense-evasion.cloudtrail-lifecycle-rule": "Defense Evasion - CloudTrail Lifecycle Rule",
    "aws.defense-evasion.cloudtrail-stop": "Defense Evasion - CloudTrail Stop",
    "aws.defense-evasion.dns-delete-logs": "Defense Evasion - DNS Delete Logs",
    "aws.defense-evasion.organizations-leave": "Defense Evasion - Organizations Leave",
    "aws.defense-evasion.vpc-remove-flow-logs": "Defense Evasion - VPC Remove Flow Logs",
    "aws.discovery.ec2-enumerate-from-instance": "Discovery - EC2 Enumerate From Instance",
    "aws.discovery.ec2-get-user-data": "Discovery - EC2 Get User Data",
    "aws.discovery.ses-enumerate": "Discovery - SES Enumerate",
    "aws.execution.ec2-launch-unusual-instances": "Execution - EC2 Launch Unusual Instances",
    "aws.execution.ec2-user-data": "Execution - EC2 User Data",
    "aws.execution.sagemaker-lifecycle-config": "Execution - SageMaker Lifecycle Config",
    "aws.execution.ssm-send-command": "Execution - SSM Send Command",
    "aws.execution.ssm-start-session": "Execution - SSM Start Session",
    "aws.exfiltration.ec2-security-group-open-port-22-ingress": "Exfiltration - EC2 Security Group Open Port 22 Ingress",
    "aws.exfiltration.ec2-share-ami": "Exfiltration - EC2 Share AMI",
    "aws.exfiltration.ec2-share-ebs-snapshot": "Exfiltration - EC2 Share EBS Snapshot",
    "aws.exfiltration.rds-share-snapshot": "Exfiltration - RDS Share Snapshot",
    "aws.exfiltration.s3-backdoor-bucket-policy": "Exfiltration - S3 Backdoor Bucket Policy",
    "aws.impact.bedrock-invoke-model": "Impact - Bedrock Invoke Model",
    "aws.impact.s3-ransomware-batch-deletion": "Impact - S3 Ransomware Batch Deletion",
    "aws.impact.s3-ransomware-client-side-encryption": "Impact - S3 Ransomware Client Side Encryption",
    "aws.impact.s3-ransomware-individual-deletion": "Impact - S3 Ransomware Individual Deletion",
    "aws.initial-access.console-login-without-mfa": "Initial Access - Console Login Without MFA",
    "aws.lateral-movement.ec2-send-serial-console-send-ssh-public-key": "Lateral Movement - EC2 Send Serial Console Send SSH Public Key",
    "aws.lateral-movement.ec2-send-ssh-public-key": "Lateral Movement - EC2 Send SSH Public Key",
    "aws.persistence.iam-backdoor-role": "Persistence - IAM Backdoor Role",
    "aws.persistence.iam-backdoor-user": "Persistence - IAM Backdoor User",
    "aws.persistence.iam-create-admin-user": "Persistence - IAM Create Admin User",
    "aws.persistence.iam-create-backdoor-role": "Persistence - IAM Create Backdoor Role",
    "aws.persistence.iam-create-user-login-profile": "Persistence - IAM Create User Login Profile",
    "aws.persistence.lambda-backdoor-function": "Persistence - Lambda Backdoor Function",
    "aws.persistence.lambda-layer-extension": "Persistence - Lambda Layer Extension",
    "aws.persistence.lambda-overwrite-code": "Persistence - Lambda Overwrite Code",
    "aws.persistence.rolesanywhere-create-trust-anchor": "Persistence - RolesAnywhere Create Trust Anchor",
    "aws.persistence.sts-federation-token": "Persistence - STS Federation Token",
    "aws.privilege-escalation.change-iam-user-password": "Privilege Escalation - Change IAM User Password",
}

AZURE_TECHNIQUES: Dict[str, str] = {
    "azure.credential-access.app-service-publishing-credentials": "Credential Access - App Service Publishing Credentials",
    "azure.execution.vm-custom-script-extension": "Execution - VM Custom Script Extension",
    "azure.execution.vm-run-command": "Execution - VM Run Command",
    "azure.exfiltration.disk-export": "Exfiltration - Disk Export",
    "azure.exfiltration.storage-public-access": "Exfiltration - Storage Public Access",
    "azure.exfiltration.storage-sas-export": "Exfiltration - Storage SAS Export",
    "azure.impact.blob-ransomware-client-encryption-scope": "Impact - Blob Ransomware Client Encryption Scope",
    "azure.impact.blob-ransomware-cpek": "Impact - Blob Ransomware CPEK",
    "azure.impact.blob-ransomware-individual-file-deletion": "Impact - Blob Ransomware Individual File Deletion",
    "azure.impact.blob-ransomware-service-storage-cmk": "Impact - Blob Ransomware Service Storage CMK",
    "azure.impact.resource-lock": "Impact - Resource Lock",
    "azure.persistence.backdoor-managed-identity-fic": "Persistence - Backdoor Managed Identity FIC",
    "azure.persistence.create-bastion-shareable-link": "Persistence - Create Bastion Shareable Link",
    "azure.privilege-escalation.root-user-access-administrator": "Privilege Escalation - Root User Access Administrator",
}

ENTRA_TECHNIQUES: Dict[str, str] = {
    "entra-id.persistence.backdoor-application": "Persistence - Backdoor Application",
    "entra-id.persistence.backdoor-application-fic": "Persistence - Backdoor Application FIC",
    "entra-id.persistence.backdoor-application-sp": "Persistence - Backdoor Application SP",
    "entra-id.persistence.guest-user": "Persistence - Guest User",
    "entra-id.persistence.hidden-au": "Persistence - Hidden AU",
    "entra-id.persistence.new-application": "Persistence - New Application",
    "entra-id.persistence.restricted-au": "Persistence - Restricted AU",
}

GCP_TECHNIQUES: Dict[str, str] = {
    "gcp.credential-access.secretmanager-retrieve-secrets": "Credential Access - SecretManager Retrieve Secrets",
    "gcp.defense-evasion.delete-dns-logs": "Defense Evasion - Delete DNS Logs",
    "gcp.defense-evasion.delete-logging-sink": "Defense Evasion - Delete Logging Sink",
    "gcp.defense-evasion.disable-audit-logs": "Defense Evasion - Disable Audit Logs",
    "gcp.defense-evasion.disable-logging-sink": "Defense Evasion - Disable Logging Sink",
    "gcp.defense-evasion.reduce-sink-log-retention": "Defense Evasion - Reduce Sink Log Retention",
    "gcp.defense-evasion.remove-project-from-organization": "Defense Evasion - Remove Project From Organization",
    "gcp.defense-evasion.remove-vpc-flow-logs": "Defense Evasion - Remove VPC Flow Logs",
    "gcp.discovery.download-instance-metadata": "Discovery - Download Instance Metadata",
    "gcp.discovery.enumerate-permissions": "Discovery - Enumerate Permissions",
    "gcp.execution.modify-vertex-notebook-startup": "Execution - Modify Vertex Notebook Startup",
    "gcp.exfiltration.share-compute-disk": "Exfiltration - Share Compute Disk",
    "gcp.exfiltration.share-compute-image": "Exfiltration - Share Compute Image",
    "gcp.exfiltration.share-compute-snapshot": "Exfiltration - Share Compute Snapshot",
    "gcp.impact.create-gpu-vm": "Impact - Create GPU VM",
    "gcp.impact.create-instances-in-multiple-zones": "Impact - Create Instances In Multiple Zones",
    "gcp.impact.gcs-ransomware-client-side-encryption": "Impact - GCS Ransomware Client Side Encryption",
    "gcp.impact.gcs-ransomware-individual-deletion": "Impact - GCS Ransomware Individual Deletion",
    "gcp.initial-access.use-compute-sa-outside-gcp": "Initial Access - Use Compute SA Outside GCP",
    "gcp.lateral-movement.add-sshkey-instance-metadata": "Lateral Movement - Add SSHKey Instance Metadata",
    "gcp.persistence.backdoor-service-account-policy": "Persistence - Backdoor Service Account Policy",
    "gcp.persistence.create-admin-service-account": "Persistence - Create Admin Service Account",
    "gcp.persistence.create-service-account-key": "Persistence - Create Service Account Key",
    "gcp.persistence.invite-external-user": "Persistence - Invite External User",
    "gcp.privilege-escalation.impersonate-service-accounts": "Privilege Escalation - Impersonate Service Accounts",
}

K8S_TECHNIQUES: Dict[str, str] = {
    "k8s.credential-access.dump-secrets": "Credential Access - Dump Secrets",
    "k8s.credential-access.steal-serviceaccount-token": "Credential Access - Steal ServiceAccount Token",
    "k8s.persistence.create-admin-clusterrole": "Persistence - Create Admin ClusterRole",
    "k8s.persistence.create-client-certificate": "Persistence - Create Client Certificate",
    "k8s.persistence.create-token": "Persistence - Create Token",
    "k8s.privilege-escalation.hostpath-volume": "Privilege Escalation - HostPath Volume",
    "k8s.privilege-escalation.nodes-proxy": "Privilege Escalation - Nodes Proxy",
    "k8s.privilege-escalation.privileged-pod": "Privilege Escalation - Privileged Pod",
}

EKS_TECHNIQUES: Dict[str, str] = {
    "eks.lateral-movement.create-access-entry": "Lateral Movement - Create Access Entry",
    "eks.persistence.backdoor-aws-auth-configmap": "Persistence - Backdoor AWS Auth ConfigMap",
}
