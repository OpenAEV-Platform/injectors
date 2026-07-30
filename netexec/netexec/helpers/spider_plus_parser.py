"""Parser for the NetExec ``spider_plus`` module metadata.

Unlike every other NetExec output, ``spider_plus`` does not print the files it
finds on stdout -- stdout only carries aggregate stats. The per-file list is
written to a JSON metadata file per target (``<ip>.json``) in the module's
output folder. This helper reads that folder and turns each file into a
structured ``file`` finding.

Metadata shape (one JSON per target)::

    {
      "SYSVOL": {
        "north.sevenkingdoms.local/scripts/secret.ps1": {
          "atime_epoch": "...", "ctime_epoch": "...",
          "mtime_epoch": "...", "size": "869 B"
        }
      }
    }

The top-level key is the SMB share; the nested key is the file path relative to
that share. The finding keeps ``file_name`` (basename) separate from ``path``
(directory) and ``share`` so the platform can render the basename while still
carrying the full location -- and so a share-hosted file links back to its
``share`` finding.
"""

import json
import os


def _split_path(relative_path: str) -> tuple[str, str]:
    """Return (directory, file_name) for a share-relative path.

    ``north.sevenkingdoms.local/scripts/secret.ps1`` -> ("north.sevenkingdoms.local/scripts", "secret.ps1").
    A top-level file yields an empty directory.
    """
    normalized = relative_path.replace("\\", "/").strip("/")
    if "/" not in normalized:
        return "", normalized
    directory, _, file_name = normalized.rpartition("/")
    return directory, file_name


def extract_files_from_metadata(
    spider_json: dict,
    ip: str,
    ip_to_asset_id_map: dict,
) -> list[dict]:
    """Flatten a single target's spider_plus metadata into file findings."""
    results: list[dict] = []
    asset_id = ip_to_asset_id_map.get(ip, "")
    for share, files in (spider_json or {}).items():
        if not isinstance(files, dict):
            continue
        for relative_path in files:
            directory, file_name = _split_path(str(relative_path))
            if not file_name:
                continue
            finding: dict = {
                "file_name": file_name,
                "path": directory,
                "share": share,
                "host": ip,
            }
            if asset_id:
                finding["asset_id"] = asset_id
            results.append(finding)
    return results


def parse_spider_output_dir(
    output_dir: str,
    ip_to_asset_id_map: dict,
) -> list[dict]:
    """Read every ``<ip>.json`` in *output_dir* and return all file findings.

    The target IP is recovered from the JSON file name (netexec writes one file
    per target named ``<ip>.json``). Missing or malformed files are skipped --
    a spider run that reached no readable share simply yields no findings.
    """
    results: list[dict] = []
    if not output_dir or not os.path.isdir(output_dir):
        return results
    for entry in sorted(os.listdir(output_dir)):
        if not entry.endswith(".json"):
            continue
        ip = entry[: -len(".json")]
        full_path = os.path.join(output_dir, entry)
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                spider_json = json.load(f)
        except (OSError, ValueError):
            continue
        results.extend(extract_files_from_metadata(spider_json, ip, ip_to_asset_id_map))
    return results
