import time
from typing import Dict

from email_seg.configuration.config_loader import ConfigLoader
from email_seg.helpers.email_sender import EmailSender
from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper

from injector_common.data_helpers import DataHelpers
from injector_common.dump_config import intercept_dump_argument

ICON_PATH = "email_seg/img/icon-email-seg.png"


class OpenAEVEmailSeg:
    def __init__(self):
        self.config = OpenAEVConfigHelper.from_configuration_object(
            ConfigLoader().to_daemon_config()
        )
        intercept_dump_argument(self.config.get_config_obj())
        with open(ICON_PATH, "rb") as icon_file:
            icon_bytes = icon_file.read()
        self.helper = OpenAEVInjectorHelper(self.config, icon_bytes)
        self.sender = EmailSender(logger=self.helper.injector_logger)

    @staticmethod
    def _first(value):
        if isinstance(value, list):
            return value[0] if value else None
        return value

    @classmethod
    def _as_bool(cls, value, default: bool = True) -> bool:
        value = cls._first(value)
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("true", "1", "yes", "on")

    def process_message(self, data: Dict) -> None:
        start = time.time()
        inject_id = DataHelpers.get_inject_id(data)
        self.helper.api.inject.execution_reception(
            inject_id=inject_id, data={"tracking_total_count": 1}
        )

        try:
            content = DataHelpers.get_content(data)
            payload = self._first(content.get("payload"))
            message = self.sender.build_message(
                payload=payload,
                mail_from=self._first(content.get("mail_from")),
                mail_to=self._first(content.get("mail_to")),
                subject=self._first(content.get("subject"))
                or "OpenAEV email gateway assessment",
                malicious_url=self._first(content.get("malicious_url")),
            )
            result = self.sender.send(
                message,
                host=self._first(content.get("smtp_host")),
                port=int(self._first(content.get("smtp_port")) or 587),
                username=self._first(content.get("smtp_username")),
                password=self._first(content.get("smtp_password")),
                use_tls=self._as_bool(content.get("smtp_use_tls", True)),
            )

            self.helper.api.inject.execution_callback(
                inject_id=inject_id,
                data={
                    "execution_message": result.message,
                    "execution_status": "SUCCESS" if result.success else "ERROR",
                    "execution_duration": int(time.time() - start),
                    "execution_action": "complete",
                },
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
        self.helper.injector_logger.info("Starting Email Gateway (SEG) injector...")
        self.helper.listen(message_callback=self.process_message)


if __name__ == "__main__":
    OpenAEVEmailSeg().start()
