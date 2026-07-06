# Email Injector

This injector allows sending emails via SMTP.

## Configuration

SMTP settings are provided through the injector configuration (`config.yml`),
under the `injector` section, and are shared by every inject:

```yaml
injector:
  id: 'changeme'
  name: 'Email'
  log_level: 'info'
  smtp_hostname: 'smtp.example.com'
  smtp_port: 587
  smtp_use_tls: true
  smtp_username: 'changeme'
  smtp_password: 'changeme'
```

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `smtp_hostname` | yes | — | Hostname of the SMTP server |
| `smtp_port` | no | `587` | Port of the SMTP server |
| `smtp_use_tls` | no | `false` | Use STARTTLS when connecting |
| `smtp_username` | no | `null` | SMTP authentication username |
| `smtp_password` | no | `null` | SMTP authentication password |

Injects only carry the message-specific fields: `from`, `to`, `subject` and
`body`.
