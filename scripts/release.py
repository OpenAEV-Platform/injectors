import argparse
import logging
import os

import requests
from OAEV_utils.release_utils import closeRelease

logging.basicConfig(encoding="utf-8", level=logging.INFO)

parser = argparse.ArgumentParser("release")
parser.add_argument(
    "branch_injectors", help="The new version number of the release.", type=str
)
parser.add_argument(
    "previous_version", help="The previous version number of the release.", type=str
)
parser.add_argument(
    "new_version", help="The new version number of the release.", type=str
)
parser.add_argument(
    "github_token", help="The github token to use for the release note.", type=str
)
parser.add_argument(
    "--dev", help="Flag to prevent pushing the release.", action="store_false"
)
args = parser.parse_args()

previous_version = args.previous_version
new_version = args.new_version
branch_injectors = args.branch_injectors
github_token = args.github_token

os.environ["DRONE_COMMIT_AUTHOR"] = "Filigran-Automation"
os.environ["GIT_AUTHOR_NAME"] = "Filigran Automation"
os.environ["GIT_AUTHOR_EMAIL"] = "automation@filigran.io"
os.environ["GIT_COMMITTER_NAME"] = "Filigran Automation"
os.environ["GIT_COMMITTER_EMAIL"] = "automation@filigran.io"

# Injectors Python

logging.info("[injectors] Starting the release")
logging.info("[injectors] Searching and replacing all version numbers everywhere")

# __version__ -> mwdb.py & __init__.py
os.system(
    "grep -rli '__version__ = "
    + previous_version
    + "' * | xargs -i@ sed -i 's/__version__ = "
    + previous_version.replace(".", "\\.")
    + "/__version__ = "
    + new_version.replace(".", "\\.")
    + "/g' @"
)

# -> README.md
os.system(
    "grep -rli 'OpenAEV Platform >= "
    + previous_version
    + "' * | xargs -i@ sed -i 's/OpenAEV Platform >= "
    + previous_version.replace(".", "\\.")
    + "/OpenAEV Platform >= "
    + new_version.replace(".", "\\.")
    + "/g' @"
)

# image: openaev/****:x.x.x -> docker-compose.yml
os.system(
    r"grep -rli '"
    + previous_version
    + "' * | xargs -i@ sed -i -E 's/openaev\\/(.*)\\:"
    + previous_version.replace(".", "\\.")
    + "/openaev\\/\\1:"
    + new_version.replace(".", "\\.")
    + "/g' @"
)

# pyoaev==x.x.x -> requirements.txt
os.system(
    "grep -rli 'pyoaev=="
    + previous_version
    + "' * | xargs -i@ sed -i 's/pyoaev=="
    + previous_version.replace(".", "\\.")
    + "/pyoaev=="
    + new_version.replace(".", "\\.")
    + "/g' @"
)

logging.info("[injectors] Pushing to " + branch_injectors)
os.system(
    'git commit -a -m "[all] Release '
    + new_version
    + '" > /dev/null 2>&1 && git push origin '
    + branch_injectors
    + " > /dev/null 2>&1"
)

logging.info("[injectors] Tagging")
os.system("git tag -f " + new_version + " && git push -f --tags > /dev/null 2>&1")

logging.info("[injectors] Generating release")
os.system("gren release > /dev/null 2>&1")

# Modify the release note
logging.info("[injectors] Getting the current release note")
release = requests.get(
    "https://api.github.com/repos/OpenAEV-Platform/injectors/releases/latest",
    headers={
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + github_token,
        "X-GitHub-Api-Version": "2022-11-28",
    },
)
release_data = release.json()
release_body = release_data["body"]

logging.info("[injectors] Generating the new release note")
github_release_note = requests.post(
    "https://api.github.com/repos/OpenAEV-Platform/injectors/releases/generate-notes",
    headers={
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + github_token,
        "X-GitHub-Api-Version": "2022-11-28",
    },
    json={"tag_name": new_version, "previous_tag_name": previous_version},
)
github_release_note_data = github_release_note.json()
github_release_note_data_body = github_release_note_data["body"]
if "Full Changelog" not in release_body:
    new_release_note = (
        release_body
        + "\n"
        + github_release_note_data_body.replace(
            "## What's Changed", "#### Pull Requests:\n"
        ).replace("## New Contributors", "#### New Contributors:\n")
    )
else:
    new_release_note = release_body

logging.info("[injectors] Updating the release")
requests.patch(
    "https://api.github.com/repos/OpenAEV-Platform/injectors/releases/"
    + str(release_data["id"]),
    headers={
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + github_token,
        "X-GitHub-Api-Version": "2022-11-28",
    },
    json={"body": new_release_note},
)

closeRelease(
    "https://api.github.com/repos/OpenAEV-Platform/injectors", new_version, github_token
)
logging.info("[injectors] Release done!")
