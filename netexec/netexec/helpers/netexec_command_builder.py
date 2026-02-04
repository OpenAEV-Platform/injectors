from typing import Dict, List, Optional


def build_command_smb(
    targets: List[str],
    credentials: Optional[Dict[str, str]] = None,
    options: Optional[List[str]] = None,
) -> List[str]:
    if not targets:
        raise ValueError("At least one target is required for SMB command")

    cmd = ["netexec", "smb"]

    for target in targets:
        cmd.append(target)

    if credentials is not None:
        cmd += ["-u", credentials["username"], "-p", credentials["password"]]

    if options:
        if isinstance(options, str):
            cmd.append(options)
        else:
            cmd.extend(options)

    return cmd


def build_command_version() -> List[str]:
    return ["netexec", "--version"]


def extract_data(content: Dict) -> Optional[Dict[str, str]]:
    username = content.get("username")
    password = content.get("password")
    options = content.get("options")

    data: Dict = {}

    if username and password:
        data["credentials"] = {
            "username": username,
            "password": password,
        }

    if options:
        if isinstance(options, list):
            data["options"] = options
        else:
            data["options"] = [options]

    return data or None
