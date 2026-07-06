# Email Injector - Research Findings

---

## Ce que ce n'est PAS

- ❌ Un outil de mailing externe (campagnes client, newsletters, etc.)
- ❌ Un outil de phishing
    - Conséquence : l'utilisateur **ne pourra pas modifier le contenu** de l'email, ou on force le **full text** (pas de liens, pas d'images, pas de JS, pas de HTML arbitraire)

---

## MVP1 — 101 Emails (SMTP)

### Périmètre

- Envoi d'emails via **SMTP** (Python `smtplib`)
- **Signature en PJ** ou en lien dans le corps (donc pas de raw text pur)
- Configurable via le **catalog**
- Configuration **iso** des autres injectors (même pattern `config.yml`)
- **Configuration du header** (custom headers)

### Implémentation technique

#### SMTP avec `smtplib`

```python
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

def send_email(smtp_config: dict, to: str, subject: str, body: str, signature_file: str = None):
    msg = MIMEMultipart()
    msg["From"] = smtp_config["from"]
    msg["To"] = to
    msg["Subject"] = subject

    # Custom OpenAEV headers
    msg["X-OpenAEV-Signature"] = smtp_config["signature_uuid"]
    msg["X-OpenAEV-FallbackMail-Signature-Name"] = smtp_config["fallback_email"]

    msg.attach(MIMEText(body, "plain"))  # Force plain text — no HTML

    # Signature as attachment
    if signature_file:
        with open(signature_file, "rb") as f:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", f"attachment; filename={signature_file}")
            msg.attach(part)

    with smtplib.SMTP(smtp_config["host"], smtp_config["port"], timeout=30) as server:
        server.starttls()
        server.login(smtp_config["username"], smtp_config["password"])
        server.send_message(msg)
```

**Ref:** [Python smtplib docs](https://docs.python.org/3/library/smtplib.html)

#### Configuration (iso injector pattern)

```yaml
# config.yml.sample
openaev:
  url: "https://openaev.example.com"
  token: "${OPENAEV_TOKEN}"

injector:
  id: "email-injector-001"
  name: "Email Injector"
  log_level: "INFO"

email:
  smtp:
    host: "smtp.example.com"
    port: 587
    tls: true
    username: "${SMTP_USER}"
    password: "${SMTP_PASSWORD}"
  from: "openaev-injector@company.com"
  headers:
    X-OpenAEV-Signature: "${SIGNATURE_UUID}"
    X-OpenAEV-FallbackMail-Signature-Name: "${FALLBACK_EMAIL}"
```

### Tests locaux avec Mailpit

Pour les tests d'intégration SMTP, **Mailpit** est recommandé :

- serveur SMTP local pour capturer les emails sans envoi réel
- UI web pour inspecter headers, body, pièces jointes
- API HTTP pour automatiser les assertions en test

Exemple de lancement :

```bash
docker run --rm -p 1025:1025 -p 8025:8025 axllent/mailpit
```

Configuration injector en environnement de test :

```yaml
email:
  smtp:
    host: "localhost"
    port: 1025
    tls: false
    username: ""
    password: ""
```

Workflow de test conseillé :

1. L'injector envoie via SMTP vers Mailpit
2. Vérifier dans l'UI (`http://localhost:8025`) la présence des headers OpenAEV
3. Vérifier les PJ/signatures et les contraintes de contenu (plain text, pas de HTML actif)

---

## MVP2 — O365

### Signatures

| Signature | Description |
|-----------|-------------|
| `inject.source.email` | Email source de l'injection |
| `inject.player.email` | Email du player ciblé |
| `inject_mail_fallback_email` | Email de fallback |
| `inject.mail.url_hash` | Hash pour chaque URL présente dans le body |
| `inject.mail.attachment.hash` | Hash des pièces jointes |

### Headers

```
X-OpenAEV-Signature: {uuid}
X-OpenAEV-FallbackMail-Signature-Name: {email}
```

### Contrat

- **1 seul contrat global** pour MVP2

---

## Future

- **IMAP** — réception/lecture des réponses
- **PGP** — chiffrement des emails
- **Templates d'email** (Jinja2)
- **Plusieurs contrats** (un par type d'email/scénario)

### Templates (Future)

Quand les templates seront implémentés, Jinja2 est le standard :

```python
from jinja2 import Environment, FileSystemLoader

env = Environment(loader=FileSystemLoader("templates/"))
template = env.get_template("inject_email.txt")

body = template.render(
    player_name="John Doe",
    scenario="Credential Theft",
    inject_id="INJ-2026-042",
)
```

---

## Problèmes : SaaS tiers (django-anymail)

### Pourquoi ne PAS utiliser django-anymail / SaaS providers

Django's `django-anymail` permet de brancher des providers SaaS (SendGrid, Mailgun, SES, etc.) via une abstraction. **Ce n'est pas adapté pour l'email injector** car :

| Problème | Impact pour OpenAEV |
|----------|---------------------|
| **Vendor lock-in** | Dépendance à un provider externe pour un composant critique |
| **Pas de contrôle des headers** | Les providers modifient/ajoutent leurs propres headers (tracking pixels, etc.) — incompatible avec nos signatures |
| **Data residency** | Le contenu des injects transite par une infra tierce — problème GDPR/SOC2 |
| **Anti-phishing filters** | Les SaaS ont des politiques anti-phishing qui pourraient bloquer nos injects légitimes |
| **Rate limits opaques** | Throttling imprévisible, pas acceptable pour des exercices planifiés |
| **Coût** | Inutile quand on a un SMTP dédié |
| **Dépendance Django** | L'injector est standalone Python, pas un projet Django |

### Conclusion

→ **SMTP direct** est le bon choix : contrôle total des headers, pas de dépendance externe, données restent internes.

---

## Plan d'exécution

### Ordre de développement

```
expectation → inject → o365
```

### Déploiement

1. **1ère étape** : 2 injectors en parallèle (ancien Java + nouveau Python)
2. **Dépréciation** : une fois le nouvel injector Python iso-feature de l'actuel
    - Iso-feature = ? Juste l'envoi multiple ?
    - Définir le backport nécessaire

### Référence : injector Java actuel

[EmailService.java](https://github.com/OpenAEV-Platform/openaev/blob/main/openaev-api/src/main/java/io/openaev/injectors/email/service/EmailService.java)

---

## Questions ouvertes

| # | Question | Options / Notes |
|---|----------|-----------------|
| 1 | Donner la possibilité d'avoir son propre serveur SMTP ? (pour les devs) | Oui via config.yml ? Env de dev uniquement ? |
| 2 | PGP : est-ce qu'on l'utilise par défaut ? L'utilisateur peut en uploader un ? | Utiliser le store Java ? PostgreSQL ? Key server ? |
| 3 | Fallback email : `Reply-To` ou `Return-Path` ? | `Reply-To` = visible par l'utilisateur, `Return-Path` = bounces uniquement |
| 4 | Iso-feature : que faut-il backporter exactement ? | Envoi multiple ? Templates ? Headers ? |

---

## Ressources

- [Python smtplib](https://docs.python.org/3/library/smtplib.html)
- [EmailService.java (injector actuel)](https://github.com/OpenAEV-Platform/openaev/blob/main/openaev-api/src/main/java/io/openaev/injectors/email/service/EmailService.java)
