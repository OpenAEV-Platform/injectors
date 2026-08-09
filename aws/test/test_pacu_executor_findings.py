"""Unit tests for the AWS Pacu result parser semantic finding shapes.

Covers the P2 semantic typing: Secrets Manager / SSM -> Credentials, IAM privesc
-> Vulnerability, and EC2 / VPC -> IPv4 (public IPs) + Port (open SG ports). The
parser imports only the standard library, so these tests need neither pacu nor
awscli installed.
"""

from aws.helpers.pacu_executor import PacuExecutor


def _executor():
    return PacuExecutor(logger=None)


def test_privesc_paths_emit_vulnerability_findings():
    results = {
        "success": True,
        "module": "iam__privesc_scan",
        "data": {
            "stdout": (
                "Potential privilege escalation found: CreateAccessKey\n"
                "Vulnerable path via iam:PassRole to admin role\n"
                "just an informational line with no signal\n"
            )
        },
    }

    outputs = _executor().parse_results(results)["outputs"]
    paths = outputs["privesc_paths"]

    assert len(paths) == 2
    for path in paths:
        assert path["status"] == "VULNERABLE"
        assert path["name"]
        assert path["details"]


def test_secrets_manager_emits_credentials():
    results = {
        "success": True,
        "module": "secrets__enum",
        "data": {"stdout": "SecretName: prod/db/password\nSecret: staging/api-key\n"},
    }

    creds = _executor().parse_results(results)["outputs"]["secrets"]

    assert {c["username"] for c in creds} == {
        "prod/db/password",
        "staging/api-key",
    }
    for cred in creds:
        assert cred["hash"] == cred["username"]


def test_ssm_parameters_emit_credentials():
    results = {
        "success": True,
        "module": "systemsmanager__download_parameters",
        "data": {"stdout": "Parameter: /prod/token\nName: /prod/other\n"},
    }

    params = _executor().parse_results(results)["outputs"]["parameters"]

    assert params
    for cred in params:
        assert cred["username"]
        assert cred["hash"]


def test_ec2_enum_emits_public_ips_and_open_ports():
    stdout = (
        "Instance i-0123456789abcdef0 in sg-0abc1234\n"
        "PublicIpAddress: 51.38.220.153\n"
        "PrivateIpAddress: 10.0.0.5\n"
        "SecurityGroup rule FromPort: 22 ToPort: 22\n"
        "Open port 443 to 0.0.0.0/0\n"
    )
    results = {
        "success": True,
        "module": "ec2__enum",
        "data": {"stdout": stdout},
    }

    outputs = _executor().parse_results(results)["outputs"]

    assert "51.38.220.153" in outputs["public_ips"]
    assert "10.0.0.5" not in outputs["public_ips"]
    assert 22 in outputs["open_ports"]
    assert 443 in outputs["open_ports"]
    assert outputs["instances"] == ["i-0123456789abcdef0"]


def test_extract_public_ipv4s_excludes_private_ranges():
    executor = _executor()
    ips = executor._extract_public_ipv4s(
        "8.8.8.8 10.1.2.3 192.168.1.1 172.16.0.1 1.1.1.1 not.an.ip"
    )
    assert set(ips) == {"8.8.8.8", "1.1.1.1"}
