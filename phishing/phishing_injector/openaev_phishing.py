import json
import re
import secrets
import time
from pathlib import Path
from typing import Dict, List

from phishing_injector.configuration.config_loader import ConfigLoader
from phishing_injector.helpers import templates
from phishing_injector.helpers.phishing_sender import PhishingSender
from phishing_injector.tracking.server import TrackingServer
from phishing_injector.tracking.store import CampaignStore
from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper

from injector_common.data_helpers import DataHelpers
from injector_common.dump_config import intercept_dump_argument

ICON_PATH = Path(__file__).parent / "img" / "icon-phishing.png"


class OpenAEVPhishing:
    def __init__(self, start_server: bool = True):
        self.config_loader = ConfigLoader()
        self.config = OpenAEVConfigHelper.from_configuration_object(
            self.config_loader.to_daemon_config()
        )
        intercept_dump_argument(self.config.get_config_obj())
        with open(ICON_PATH, "rb") as icon_file:
            icon_bytes = icon_file.read()
        self.helper = OpenAEVInjectorHelper(self.config, icon_bytes)

        phishing_conf = self.config_loader.phishing
        self.public_url = phishing_conf.public_url
        self.store = CampaignStore()
        smtp_password = (
            phishing_conf.smtp_password.get_secret_value()
            if phishing_conf.smtp_password
            else None
        )
        self.sender = PhishingSender(
            host=phishing_conf.smtp_host,
            port=phishing_conf.smtp_port,
            mail_from=phishing_conf.mail_from,
            username=phishing_conf.smtp_username,
            password=smtp_password,
            use_tls=phishing_conf.smtp_use_tls,
            logger=self.helper.injector_logger,
        )
        self.server = TrackingServer(
            self.store,
            host=phishing_conf.listen_host,
            port=phishing_conf.listen_port,
            redirect_url=phishing_conf.redirect_url,
        )
        if start_server:
            self.server.start()

    @staticmethod
    def parse_recipients(raw: str) -> List[str]:
        if not raw:
            return []
        parts = re.split(r"[,\n;]+", raw)
        return [p.strip() for p in parts if p.strip()]

    def process_message(self, data: Dict) -> None:
        start = time.time()
        inject_id = DataHelpers.get_inject_id(data)

        content = DataHelpers.get_content(data)
        recipients = self.parse_recipients(content.get("recipients", ""))
        self.helper.api.inject.execution_reception(
            inject_id=inject_id,
            data={"tracking_total_count": max(len(recipients), 1)},
        )

        try:
            if not recipients:
                raise ValueError("No recipients provided")

            template_key = content.get("template")
            if isinstance(template_key, list):
                template_key = template_key[0] if template_key else None
            custom_html = content.get("custom_html", "")
            subject_override = content.get("subject")
            if isinstance(subject_override, list):
                subject_override = subject_override[0] if subject_override else None

            sent = 0
            errors = []
            for email in recipients:
                token = secrets.token_urlsafe(16)
                self.store.register(token, inject_id, email)
                rendered = templates.render(
                    template_key or "password_reset",
                    self.public_url,
                    token,
                    custom_html=custom_html,
                )
                subject = subject_override or rendered["subject"] or "Notification"
                message = self.sender.build_message(email, subject, rendered["html"])
                result = self.sender.send(message)
                if result.success:
                    sent += 1
                else:
                    errors.append(f"{email}: {result.message}")

            summary = (
                f"Phishing campaign launched: {sent}/{len(recipients)} emails sent. "
                f"Tracking at {self.public_url}"
            )
            # Surface per-recipient failures even on a partial success: a
            # launched campaign stays SUCCESS (delivered recipients remain
            # trackable), but the failed recipients are appended to the message
            # so delivery issues are diagnosable instead of silently dropped.
            if errors:
                failure_detail = "Failed recipients: " + "; ".join(errors)
                execution_message = (
                    f"{summary}. {failure_detail}" if sent else failure_detail
                )
            else:
                execution_message = summary
            status = "SUCCESS" if sent > 0 else "ERROR"
            callback_data = {
                "execution_message": execution_message,
                "execution_status": status,
                "execution_duration": int(time.time() - start),
                "execution_action": "complete",
            }
            if sent:
                # The launch callback reports the send-time facts only. Open /
                # click / submit events land later on the embedded tracking
                # server; they are recorded in-memory per campaign and scored
                # through the contract's manual "Human Response" expectation.
                callback_data["execution_output_structured"] = json.dumps(
                    {
                        "sent": sent,
                        "total": len(recipients),
                        "tracking_url": self.public_url,
                    }
                )
            self.helper.api.inject.execution_callback(
                inject_id=inject_id, data=callback_data
            )
        except Exception as e:
            self.helper.api.inject.execution_callback(
                inject_id=inject_id,
                data={
                    "execution_message": str(e),
                    "execution_status": "ERROR",
                    "execution_duration": int(time.time() - start),
                    "execution_action": "complete",
                },
            )

    def start(self):
        self.helper.injector_logger.info("Starting native Phishing injector...")
        self.helper.listen(message_callback=self.process_message)


if __name__ == "__main__":
    OpenAEVPhishing().start()
