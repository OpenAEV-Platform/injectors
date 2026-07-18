"""Built-in phishing email templates rendered with per-recipient tracking."""

from typing import Dict

TEMPLATES: Dict[str, Dict[str, str]] = {
    "password_reset": {
        "subject": "Action required: reset your password",
        "html": (
            "<html><body>"
            "<p>Hello,</p>"
            "<p>We detected unusual activity on your account. Please "
            '<a href="{link}">reset your password</a> to keep it secure.</p>'
            '<img src="{pixel}" width="1" height="1" alt="" />'
            "</body></html>"
        ),
    },
    "mfa_reenrollment": {
        "subject": "Re-enroll your multi-factor authentication",
        "html": (
            "<html><body>"
            "<p>Hello,</p>"
            "<p>Your MFA method expires soon. Please "
            '<a href="{link}">re-enroll now</a>.</p>'
            '<img src="{pixel}" width="1" height="1" alt="" />'
            "</body></html>"
        ),
    },
    "shared_document": {
        "subject": "A document was shared with you",
        "html": (
            "<html><body>"
            "<p>Hello,</p>"
            '<p>A colleague shared a document with you. <a href="{link}">'
            "Open document</a>.</p>"
            '<img src="{pixel}" width="1" height="1" alt="" />'
            "</body></html>"
        ),
    },
}


def render(
    template_key: str, base_url: str, token: str, custom_html: str = ""
) -> Dict[str, str]:
    """Return {subject, html} for a recipient token.

    The link points at the click endpoint and the pixel at the open endpoint of
    the embedded tracking server.
    """
    link = f"{base_url.rstrip('/')}/c/{token}"
    pixel = f"{base_url.rstrip('/')}/o/{token}"

    if custom_html:
        html = custom_html.replace("{link}", link).replace("{pixel}", pixel)
        return {"subject": "", "html": html}

    template = TEMPLATES.get(template_key)
    if template is None:
        raise ValueError(f"Unknown template: {template_key}")
    return {
        "subject": template["subject"],
        "html": template["html"].format(link=link, pixel=pixel),
    }
