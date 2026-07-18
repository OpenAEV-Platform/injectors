"""In-memory campaign / recipient tracking store.

Maps opaque per-recipient tokens to their campaign and records the human
response events (open, click, submit). MVP is process-local; a persistent
backing store can be added later for restart safety.
"""

import threading
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class Recipient:
    token: str
    inject_id: str
    email: str
    opened: bool = False
    clicked: bool = False
    submitted: bool = False


@dataclass
class CampaignStats:
    total: int = 0
    opened: int = 0
    clicked: int = 0
    submitted: int = 0


@dataclass
class Campaign:
    inject_id: str
    recipients: List[Recipient] = field(default_factory=list)


class CampaignStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._by_token: Dict[str, Recipient] = {}
        self._by_inject: Dict[str, Campaign] = {}

    def register(self, token: str, inject_id: str, email: str) -> None:
        recipient = Recipient(token=token, inject_id=inject_id, email=email)
        with self._lock:
            self._by_token[token] = recipient
            campaign = self._by_inject.setdefault(inject_id, Campaign(inject_id))
            campaign.recipients.append(recipient)

    def record_open(self, token: str) -> bool:
        with self._lock:
            recipient = self._by_token.get(token)
            if recipient is None:
                return False
            recipient.opened = True
            return True

    def record_click(self, token: str) -> bool:
        with self._lock:
            recipient = self._by_token.get(token)
            if recipient is None:
                return False
            recipient.opened = True
            recipient.clicked = True
            return True

    def record_submit(self, token: str) -> bool:
        with self._lock:
            recipient = self._by_token.get(token)
            if recipient is None:
                return False
            recipient.opened = True
            recipient.clicked = True
            recipient.submitted = True
            return True

    def stats(self, inject_id: str) -> CampaignStats:
        with self._lock:
            campaign = self._by_inject.get(inject_id)
            if campaign is None:
                return CampaignStats()
            return CampaignStats(
                total=len(campaign.recipients),
                opened=sum(1 for r in campaign.recipients if r.opened),
                clicked=sum(1 for r in campaign.recipients if r.clicked),
                submitted=sum(1 for r in campaign.recipients if r.submitted),
            )
