# PasteGuard

**En bref.** Petit outil PHP, zéro dépendance, pour la minute d’avant le collage : *est-ce que ce log contient une clé ?* Tu lui donnes un log, un `.env` ou une sortie de commande. Il retire les secrets et te laisse une version collable. Rien n’est envoyé nulle part.

---

People paste production logs into chatbots, tickets and Slack. The log is useful. The Stripe key, the JWT and the database password inside it are not. PasteGuard is the local pass you run first.

On the bundled sample (`examples/leaky.txt`):

```text
pasteguard: examples/leaky.txt
6 secret(s) redacted
  assignment       3
  aws_access_key   1
  jwt              1
  url_userinfo     1
stdout is the paste-safe copy. nothing was uploaded.
```

```text
Authorization: Bearer [REDACTED:jwt:5a31]

DB_PASSWORD=changeme
APP_KEY=[REDACTED:assignment:f96a]
DATABASE_URL=mysql://[REDACTED:url_userinfo:7b91]@10.0.0.8:3306/billing
AWS_ACCESS_KEY_ID=[REDACTED:aws_access_key:fe62]
MAIL_PASSWORD=[REDACTED:assignment:4ebd]
APP_KEY=[REDACTED:assignment:f96a]

note: the user token expired after logout.
customer support@client.example asked for a receipt.
password=secret
```

The four hex digits are a fingerprint, so the same `APP_KEY` is recognizable twice. They are not a prefix of the secret. `changeme`, `password=secret`, the host and the sentence stay: a paste that is only `[REDACTED]` is not debuggable.

## Run it

Requires PHP 8.1+ with PCRE (the default build). No Composer install.

```bash
git clone https://github.com/Nguemoue/project2026_20261015_pasteguard.git
cd project2026_20261015_pasteguard

php bin/pasteguard examples/leaky.txt
php bin/pasteguard storage/logs/laravel.log -o safe.log
php bin/pasteguard --check storage/logs/laravel.log
```

`--check` prints `file:line:kind:fingerprint` and exits `1` when it finds something. It does not print the secret. Use that in CI. Exit `0` means the file is clean. Exit `2` is a usage or IO error.

Local page, still no upload:

```bash
php -S 127.0.0.1:8765 -t public
```

Open the site, choose **Charger l’exemple**, then **Rendre collable**. Do not put this page on a public server: the text would pass through that server.

## CI gate

```yaml
- name: Logs are safe to paste
  run: php bin/pasteguard --check storage/logs/laravel.log
```

`--json` prints counts and locations. Combined with `--check`, the JSON does not include the log text.

## What it redacts

High-confidence shapes, not a dump of every vendor on earth:

- private keys (PEM, including a one-line `\n` form)
- GitHub `ghp_` / `gho_` / `ghu_` / `ghs_` / `ghr_` and `github_pat_`
- GitLab `glpat-`, Slack tokens and incoming webhooks
- Stripe secret keys and `whsec_` (publishable `pk_` keys are left alone)
- OpenAI, Anthropic and `xai-` keys
- Google API keys, SendGrid, npm, Shopify, Hugging Face, PyPI, DigitalOcean
- AWS access key ids (`AKIA…`)
- JWTs and other `Bearer` tokens, plus `Authorization: Basic`
- userinfo in `mysql://`, `postgres://`, `mongodb://`, `redis://`, `amqp://`
- assignments whose name looks like a password, secret, api key or token

`--pii` also redacts email addresses. `user@example.com` stays, because that one is documentation.

## What it will not do

- It will not catch a secret with a boring name (`KEY=`) or a value split across lines.
- It will not scan git history. Use a real history scanner for that. This is for the paste in front of you.
- A placeholder (`changeme`, `secret`, `xxx`, `your-token`, `${VAR}`, a filesystem path) is not treated as a live credential.
- The fingerprint is 16 bits. It correlates repeats inside one file. It does not recover the value.
- Finding a hit means rotate the real credential if it was already shared. Redaction does not undo a paste.

The sample JWT is the public jwt.io fixture. The sample AWS id is `AKIAIOSFODNN7EXAMPLE`, AWS’s documented example. Tests build other shapes at runtime so the repository does not contain live credentials.

## Tests

```bash
php tests/run.php
```

GitHub Actions runs the same file on PHP 8.1, 8.2, 8.3 and 8.4.

## Layout

```text
bin/pasteguard     CLI
public/index.php   local paste page
src/               rules, redactor, CLI, page
examples/leaky.txt synthetic log (public fixtures only)
tests/run.php      assertions, no PHPUnit
```

## License

MIT. Copyright 2026 Luc (Nguemoue).
