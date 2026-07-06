from email_injector.helpers.email_helper import EmailPayloadBuilder


def test_email_payload_builder():
    content = {
        "from": "sender@example.com",
        "to": "recipient@example.com",
        "subject": "Hello",
        "body": "World",
    }

    payload = EmailPayloadBuilder.build(content)

    assert payload["from"] == "sender@example.com"
    assert payload["to"] == "recipient@example.com"
    assert payload["subject"] == "Hello"
    assert payload["body"] == "World"
    assert "smtp_hostname" not in payload
