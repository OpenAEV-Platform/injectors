"""Private temporary-directory preparation shared by client resources."""

import os
from pathlib import Path


def make_private_directory(path: Path, *, platform_name: str) -> None:
    """Apply the portable owner-only directory mode where supported."""
    if platform_name != "nt":
        os.chmod(path, 0o700)
