"""Thin client over the Gophish REST API."""

from dataclasses import dataclass, field
from typing import Dict

import requests


@dataclass
class CampaignResult:
    success: bool
    message: str
    campaign_id: int = 0
    stats: Dict[str, int] = field(default_factory=dict)


class GophishClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        verify_tls: bool = False,
        timeout: int = 60,
        logger=None,
    ):
        self.base_url = base_url.rstrip("/")
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.logger = logger
        self._headers = {"Authorization": api_key}

    def create_campaign(
        self,
        name: str,
        template_name: str,
        page_name: str,
        smtp_name: str,
        group_name: str,
        url: str,
    ) -> CampaignResult:
        """Create and launch a campaign referencing existing Gophish objects.

        Gophish resolves the template, landing page, sending profile and target
        group by name, so those objects must already exist on the server.
        """
        payload = {
            "name": name,
            "template": {"name": template_name},
            "page": {"name": page_name},
            "smtp": {"name": smtp_name},
            "url": url,
            "groups": [{"name": group_name}],
        }
        try:
            response = requests.post(
                f"{self.base_url}/api/campaigns/",
                json=payload,
                headers=self._headers,
                verify=self.verify_tls,
                timeout=self.timeout,
            )
            response.raise_for_status()
            body = response.json()
        except requests.HTTPError as exc:
            return CampaignResult(False, f"Gophish campaign creation failed: {exc}")
        except requests.RequestException as exc:
            return CampaignResult(False, f"Gophish request error: {exc}")

        return CampaignResult(
            success=True,
            message=f"Launched Gophish campaign '{name}' (id {body.get('id')})",
            campaign_id=int(body.get("id", 0)),
            stats=self._extract_stats(body),
        )

    def get_campaign_stats(self, campaign_id: int) -> CampaignResult:
        try:
            response = requests.get(
                f"{self.base_url}/api/campaigns/{campaign_id}",
                headers=self._headers,
                verify=self.verify_tls,
                timeout=self.timeout,
            )
            response.raise_for_status()
            body = response.json()
        except requests.HTTPError as exc:
            return CampaignResult(False, f"Gophish stats fetch failed: {exc}")
        except requests.RequestException as exc:
            return CampaignResult(False, f"Gophish request error: {exc}")

        return CampaignResult(
            success=True,
            message=f"Fetched stats for campaign {campaign_id}",
            campaign_id=campaign_id,
            stats=self._extract_stats(body),
        )

    @staticmethod
    def _extract_stats(body: Dict) -> Dict[str, int]:
        stats = body.get("stats") or {}
        return {
            "total": int(stats.get("total", 0)),
            "sent": int(stats.get("sent", 0)),
            "opened": int(stats.get("opened", 0)),
            "clicked": int(stats.get("clicked", 0)),
            "submitted_data": int(stats.get("submitted_data", 0)),
        }
