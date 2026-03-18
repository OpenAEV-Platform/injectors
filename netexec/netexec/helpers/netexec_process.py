import subprocess
from typing import Optional, Tuple

DEFAULT_TIMEOUT = 300  # 5 minutes


def execute_netexec(
    cmd: list[str],
    input_data: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> Tuple[str, str, int]:
    kwargs = {
        "capture_output": True,
        "check": False,
        "text": True,
        "timeout": timeout,
    }

    if input_data is not None:
        kwargs["input"] = input_data

    try:
        result = subprocess.run(cmd, **kwargs)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"NetExec timed out after {timeout}s", -1
