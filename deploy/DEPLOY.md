# Hosting ASTRA for a shared test

This puts ASTRA on one server with Docker: the database, the API and the studio, with demo data for **AI agents and AI models** and a login for each tester. About 15 minutes.

**What you need on the server:** Docker Engine with Compose v2.20 or later, about 4 GB of RAM and 5 GB of disk, and the GitHub repository (`https://github.com/khidawi/ATRA-Design-Studio.git`). No GPU, and no language model: this setup leaves out Ollama, so the two chat-style assistants that call a local model are not available. Everything else works, including the design review in the model designer, production monitoring, assurance packs and attestations.

## 1. Get the code and configure it

```bash
git clone https://github.com/khidawi/ATRA-Design-Studio.git
cd ATRA-Design-Studio/deploy
cp .env.example .env
```

Edit `.env`:

- `POSTGRES_PASSWORD`: any long random string.
- `ASTRA_SECRET_KEY`: a Fernet key. Generate one with
  ```bash
  docker run --rm python:3.13-slim sh -c "pip install -q cryptography && python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
  ```
  Keep it with your backups: without it, stored tokens and alert webhook addresses cannot be read again.
- `ASTRA_PORT`: the port the studio listens on (default 8080).

## 2. Start it and claim the administrator account straight away

```bash
docker compose -f docker-compose.demo.yml up --build -d
```

**Do the next step immediately, before the server is reachable by anyone else.** A new ASTRA server offers the *first person who opens it* the chance to create the administrator. The seed script below is how you make sure that is you.

```bash
export ASTRA_ADMIN_PASSWORD='choose-a-long-password'      # at least 10 characters
python3 seed_demo.py --url http://localhost:8080 \
    --admin-email you@example.org --admin-name "Your Name" \
    --tester "Ada Lovelace <ada@example.org>" \
    --tester "Alan Turing <alan@example.org>"
```

This creates the administrator, loads the **Helix Logistics** demo organisation (five AI agents and an AI model), gives the model a production monitor with a normal period followed by a drifted one, and creates an `engineer` account per tester. Testers can design, monitor and edit; they cannot sign off or administer. Use `--tester-role auditor` for read-only accounts. Each tester's password is printed once at the end: pass it on privately; they can change it under their account.

It is safe to run again; what exists is skipped. `--no-traffic` skips the demo monitors. To load a second organisation (the Lamad LLC example, with three models), add `--company ../examples/company-lamad-llc.json` on a separate server: importing a second company into the same server renames the organisation.

## 3. Make it reachable, with HTTPS: the production file

For anything beyond a try-out on your own machine, use `docker-compose.prod.yml` instead of the demo file. It is the same three parts with HTTPS in front and the containers locked down, and nothing to add by hand:

- **Caddy** is the only container with published ports (80 and 443). It gets the certificate, renews it, redirects HTTP to HTTPS (a sign-in sent over plain HTTP is redirected and never reaches the application) and adds the security headers (HSTS for a year, no content sniffing, no framing, no referrer, a minimal permissions policy).
- The **studio, the API and the database are not published**. The API and the database are on a private network the proxy cannot see.
- The **API runs as an unprivileged user** (uid 10001) on a **read-only filesystem**, with no extra Linux capabilities and no way to gain any. Its code is owned by root and read-only to it; its only writable place is a memory-only `/tmp` (the throwaway checkouts of connected repositories). The studio's nginx is read-only too.
- The session cookie is marked **Secure** because the API is told the scheme the browser used (`--proxy-headers`, trusted only on the private network).

```bash
cd ATRA-Design-Studio/deploy
cp .env.example .env          # set POSTGRES_PASSWORD, ASTRA_SECRET_KEY and ASTRA_DOMAIN (the production variables are at the bottom)
docker compose -f docker-compose.prod.yml up --build -d
python3 seed_demo.py --url https://astra.example.org --admin-email you@example.org ...      # claim the administrator first, as in step 2
python3 verify_https.py https://astra.example.org --email you@example.org --password '...'   # then check it from the outside
```

**Before you start:** the name in `ASTRA_DOMAIN` must be a DNS record that points at this server, and ports 80 and 443 must be open to the internet for the certificate to be issued (Caddy answers the certificate authority's challenge on port 80). Open nothing else.

**A private name with no public DNS** (an internal server): set `ASTRA_TLS=internal`. Caddy then issues the certificate from its own authority, and the people using it must trust that authority (its root certificate is in the `caddy_data` volume, under `pki/authorities/local/root.crt`), or put your organisation's own certificate authority in front instead. A name like `localhost` works the same way for a local check.

**`verify_https.py`** is the check an auditor or a security questionnaire would make, from outside: HTTP redirects to HTTPS, the certificate is valid and has more than 14 days left, TLS 1.2 or 1.3 only, the headers are there, the application and its database answer, the API refuses a request with no sign-in, the session cookie is HttpOnly, Secure and SameSite, and the API, the database and the development port are not reachable. It changes nothing. Run it after every update. (It will flag ports 8765 and 5173 on a machine that also runs the development compose file: that is what it is for.)

**Not covered here:** single sign-on and multi-factor sign-in for staff (put the site behind your organisation's identity-aware proxy or a VPN until it is built), a Content-Security-Policy that restricts scripts (the studio is one page with inline script, which would have to be moved to files first; the policy here closes framing, form targets, base URLs and plugins), and encryption inside the private network between the studio and the API (acceptable on one host).

### The demo file and your own proxy

`docker-compose.demo.yml` publishes the studio on one port and leaves HTTPS to you. If you use it, put a reverse proxy with a certificate in front, and never expose the port directly:


Do not expose the studio over plain HTTP outside a trusted network: passwords would cross the network in clear and the session cookie is only marked secure over HTTPS. Put a reverse proxy with a certificate in front of it. With Caddy, for example:

```
astra.example.org {
    reverse_proxy localhost:8080
}
```

Open only ports 80 and 443 on the firewall. The database and the API are not published by this compose file; only the studio is.

## Day to day

The commands below use the demo file; with the production file, use `-f docker-compose.prod.yml` instead (`up --build -d` rebuilds the API and the studio and leaves the certificates, which are in the `caddy_data` volume, alone).

| | |
|---|---|
| See what is running | `docker compose -f docker-compose.demo.yml ps` |
| Logs | `docker compose -f docker-compose.demo.yml logs -f backend` |
| Update to the latest version | `git pull && docker compose -f docker-compose.demo.yml up --build -d` (database changes apply on their own and only add) |
| Back up | `docker compose -f docker-compose.demo.yml exec -T db pg_dump -U stai stai > astra-backup.sql`, and keep `.env` |
| Start again with empty data | `docker compose -f docker-compose.demo.yml down -v`, then step 2 |
| A tester forgot a password | an administrator can reset it under Users |

## Good to know

- The demo data is synthetic. Do not put a company's real data on a shared test server until you have decided who may see it.
- Testers can try the production-monitoring side from their own machine with the example in `sdk/python/examples/demo_models.py`: create a **collector** API key under Users, set `ASTRA_URL` and `ASTRA_KEY`, and run it. It needs only Python.
- If something does not start, `docker compose ... logs backend` usually says why. A missing `POSTGRES_PASSWORD` or `ASTRA_SECRET_KEY` is refused with a message naming it.
