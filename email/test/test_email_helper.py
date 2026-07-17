from email_injector.helpers.email_helper import EmailPayloadBuilder


def test_email_payload_builder():
    content = {
        "smtp_hostname": "smtp.example.com",
        "smtp_port": "587",
        "smtp_use_tls": True,
        "smtp_username": "user",
        "smtp_password": "pass",
        "from": "sender@example.com",
        "mail_from": "bounce@example.com",
        "reply_to": "reply@example.com",
        "to": "recipient@example.com",
        "cc": "cc1@example.com, cc2@example.com",
        "bcc": "bcc@example.com",
        "subject": "Hello",
        "body": "World",
    }

    payload = EmailPayloadBuilder.build(content)

    assert payload["smtp_hostname"] == "smtp.example.com"
    assert payload["smtp_port"] == 587
    assert payload["smtp_use_tls"] is True
    assert payload["smtp_username"] == "user"
    assert payload["smtp_password"] == "pass"
    assert payload["from"] == "sender@example.com"
    assert payload["mail_from"] == "bounce@example.com"
    assert payload["reply_to"] == "reply@example.com"
    assert payload["to"] == "recipient@example.com"
    assert payload["cc"] == ["cc1@example.com", "cc2@example.com"]
    assert payload["bcc"] == ["bcc@example.com"]
    assert payload["subject"] == "Hello"
    assert payload["body"] == "World"


def test_email_payload_builder_defaults():
    content = {
        "smtp_hostname": "smtp.example.com",
        "smtp_port": "25",
        "from": "sender@example.com",
        "to": "recipient@example.com",
        "subject": "Hello",
        "body": "World",
    }

    payload = EmailPayloadBuilder.build(content)

    assert payload["smtp_hostname"] == "smtp.example.com"
    assert payload["smtp_port"] == 25
    assert payload["smtp_use_tls"] is False
    assert payload["smtp_username"] is None
    assert payload["smtp_password"] is None
    assert payload["mail_from"] == "sender@example.com"
    assert payload["reply_to"] is None
    assert payload["cc"] == []
    assert payload["bcc"] == []


def test_email_payload_builder_empty_mail_from_falls_back_to_from():
    content = {
        "smtp_hostname": "smtp.example.com",
        "smtp_port": "25",
        "from": "sender@example.com",
        "mail_from": "",
        "to": "recipient@example.com",
        "subject": "Hello",
        "body": "World",
    }

    payload = EmailPayloadBuilder.build(content)

    assert payload["mail_from"] == "sender@example.com"


def test_email_payload_builder_parse_bool_from_string():
    content = {
        "smtp_hostname": "smtp.example.com",
        "smtp_port": "25",
        "smtp_use_tls": "yes",
        "from": "sender@example.com",
        "to": "recipient@example.com",
        "subject": "Hello",
        "body": "World",
    }

    payload = EmailPayloadBuilder.build(content)

    assert payload["smtp_use_tls"] is True


def test_email_payload_builder_parse_bool_from_empty_string():
    content = {
        "smtp_hostname": "smtp.example.com",
        "smtp_port": "25",
        "smtp_use_tls": "",
        "from": "sender@example.com",
        "to": "recipient@example.com",
        "subject": "Hello",
        "body": "World",
    }

    payload = EmailPayloadBuilder.build(content)

    assert payload["smtp_use_tls"] is False
