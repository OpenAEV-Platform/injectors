"""Emulates C2 beaconing traffic toward a listener (Sliver / Mythic style).

Rather than deploying a full C2 framework, this generates the network beaconing
pattern - periodic callbacks with configurable interval, jitter and a malware
like user agent - which is what NDR / network C2 detections key on. Point it at
a Sliver or Mythic HTTP listener (or any sink) to validate detection.
"""

import random
import time
from dataclasses import dataclass, field
from typing import Dict, List

import requests

# Guard rails so a misconfigured inject cannot run unbounded.
MAX_BEACONS = 240
MAX_INTERVAL_SECONDS = 300
MAX_JITTER_PERCENT = 100

BEACON_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


@dataclass
class C2Result:
    success: bool
    message: str
    outputs: Dict[str, List[str]] = field(default_factory=dict)


class C2Executor:
    def __init__(self, logger=None, per_beacon_timeout: int = 10, sleeper=time.sleep):
        self.logger = logger
        self.per_beacon_timeout = per_beacon_timeout
        # Injected for testability so unit tests do not actually sleep.
        self._sleep = sleeper

    @staticmethod
    def _jittered(interval: float, jitter_percent: float) -> float:
        bounded_jitter = max(0.0, min(jitter_percent, MAX_JITTER_PERCENT))
        delta = interval * (bounded_jitter / 100.0)
        return min(
            MAX_INTERVAL_SECONDS,
            max(0.0, interval + random.uniform(-delta, delta)),
        )

    def beacon(
        self,
        listener_url: str,
        beacon_count: int,
        interval_seconds: float,
        jitter_percent: float,
    ) -> C2Result:
        count = max(1, min(int(beacon_count), MAX_BEACONS))
        interval = max(0.0, min(float(interval_seconds), MAX_INTERVAL_SECONDS))
        sent = 0
        reached = 0
        for index in range(count):
            try:
                response = requests.get(
                    listener_url,
                    headers={"User-Agent": BEACON_USER_AGENT},
                    timeout=self.per_beacon_timeout,
                )
                reached += 1 if response.status_code < 500 else 0
            except requests.RequestException:
                # A blocked beacon still generated observable network traffic.
                pass
            sent += 1
            if index < count - 1:
                self._sleep(self._jittered(interval, jitter_percent))

        return C2Result(
            success=True,
            message=(
                f"Emulated {sent} C2 beacons to {listener_url} "
                f"({reached} reached the listener)"
            ),
            outputs={
                "beacons_sent": [str(sent)],
                "beacons_reached": [str(reached)],
                "listener": [listener_url],
            },
        )
