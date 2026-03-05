import subprocess
from typing import Optional


def execute_netexec(cmd: list[str], input_data: Optional[str] = None):
    kwargs = {
        "capture_output": True,
        "check": False,
        "text": True,
    }

    if input_data is not None:
        kwargs["input"] = input_data

    result = subprocess.run(cmd, **kwargs)

    return result.stdout, result.stderr, result.returncode
