# Injector icon

The injector icon is committed here as `icon-email-seg.png`.

This injector wraps no single vendor; it uses a clean, generic email/security
mark (confirmed with the product team). Per OpenAEV-Platform/injectors#305 the
icon must be:

- Square 1:1, 512x512 PNG
- Solid opaque background (no transparency)
- Centered mark with ~14% padding

When replacing the icon, keep the same filename and these constraints so the
container startup read in `openaev_email_seg.py` continues to work.
