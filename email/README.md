# Email Injector

This injector allows sending emails via SMTP.

## Configuration

`config.yml` only contains OpenAEV and injector runtime settings:

```yaml
injector:
  id: 'changeme'
  name: 'Email'
  log_level: 'info'
```

Injects carry the message-specific fields: `from`, `to`, `subject`, `body`,
optional `cc` and `bcc` (comma-separated email lists), and SMTP fields:
`smtp_hostname`, `smtp_port`, `smtp_use_tls`, `smtp_username`,
`smtp_password`. They can also carry one optional attachment through the
contract attachment field.
