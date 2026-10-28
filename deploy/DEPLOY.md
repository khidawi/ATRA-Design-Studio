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
- The **studio (nginx, unprivileged, port 8080), the API and the database are not published**. The API and the database are on a private network the proxy cannot see.
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

### The database: encrypted, three identities, an audit log that cannot be rewritten

The production file sets the database up so that a flaw in the application cannot read the network, change the structure of the data or rewrite history:

- **Every connection is encrypted.** The `certs` service makes a certificate for the database (the authority's private key is thrown away after signing it). The database accepts only TLS 1.2 or later with scram-sha-256 passwords, and refuses a connection that is not encrypted (it is rejected, not retried in clear). The API checks the database's certificate and name (`sslmode=verify-full`). The private key never leaves the database container; the API gets only the authority's public certificate, read-only.
- **Three identities.** `astra_admin` is the database superuser and is used only to create the database and by backups. `stai_owner` owns the tables and is used by the API only at start-up, to apply migrations. `stai_app` is what the running API connects as: it can read and write data and use sequences, and nothing else: no creating, altering or dropping tables, no roles, and time limits on statements and idle transactions.
- **The audit log is append-only in the database itself.** At each start-up the API (as the owner) removes UPDATE, DELETE and TRUNCATE on the audit log from `stai_app`, so the hash chain cannot be rewritten even through a flaw in the application.
- **Set the three passwords before the first start** (`POSTGRES_PASSWORD`, `ASTRA_DB_OWNER_PASSWORD`, `ASTRA_DB_APP_PASSWORD`; letters and digits, for example `openssl rand -hex 24`): the roles are created when the database is first created, so changing a password later means `ALTER ROLE` as well as editing `.env`. A database that was created with the demo file cannot simply be switched over: restore a backup into a new production stack.
- **`python verify_db.py`** checks all of this from inside the API container, as the role the application really uses: the connection is encrypted and which TLS version, an unencrypted connection is refused, the role is not a superuser, it cannot create, drop or alter a table, and the audit log can be read and added to but not updated, deleted from or truncated. Every attempt to do something forbidden runs in a transaction that is rolled back, so the check changes nothing.

**Backups.** `BACKUP_PASSPHRASE_FILE=/secure/place/pass ./backup_db.sh` writes an AES-256 encrypted dump (key derived from the passphrase, 200,000 rounds), so the file is unreadable on a backup server or in cloud storage without it. `./restore_db.sh FILE [name]` restores into a **new** scratch database (never over the live one) and prints its table count and audit events: do this once, now, to know the backup works. Keep the passphrase apart from the backups and from `.env`, and keep `ASTRA_SECRET_KEY` safe too: without it the repository tokens, identity-provider credentials and webhook addresses in a restored copy cannot be read. Disk encryption for the database volume is the host's job (LUKS, BitLocker or the cloud's managed encryption).

### Data sent into ASTRA by applications

- **HTTPS only.** The SDK refuses to send the API key and events over plain `http` to any address except this machine (it switches itself off and says why); `ASTRA_ALLOW_INSECURE=1` overrides it on a network you fully control. It always checks the server's certificate and host name, and never negotiates below TLS 1.2.
- **A private certificate authority.** If ASTRA is served with a certificate from your own authority (`ASTRA_TLS=internal`, or an internal CA), set `ASTRA_CA_BUNDLE` to that authority's certificate file in the application: nothing has to be installed on the machine. With `ASTRA_TLS=internal` the authority's certificate is in the `caddy_data` volume at `pki/authorities/local/root.crt`.
- **Client certificates (optional, mutual TLS).** For the paths applications use to send data in (runtime events, telemetry, model records, decisions, canaries), a client certificate can be required on top of the API key, so a leaked key alone can no longer feed ASTRA false events. `./make_collector_cert.sh checkout-service` makes the authority (once) and one certificate per application; then `docker compose -f docker-compose.prod.yml -f docker-compose.mtls.yml up -d`. Without a certificate those paths answer 401 at the proxy; a certificate from another authority is refused in the handshake; people's browsers are not asked for one. The application sets `ASTRA_CLIENT_CERT` and `ASTRA_CLIENT_KEY`. Keep `client-ca.key` offline; replace the authority to revoke everything it signed.
- **Inside the server.** Traffic between the proxy, the studio and the API stays on private container networks on one host, unencrypted; on a shared or multi-host network, add TLS between them.

### Updating from signed releases

Every release is built, scanned and signed by GitHub Actions (`.github/workflows/`), so a server can run exactly what was tested instead of compiling code itself.

- **Every push and pull request** runs `ci.yml`: the backend tests against a real PostgreSQL, the SDK tests, a syntax check of the studio page; lint of the shell scripts, Dockerfiles, workflows, compose files and Caddyfile; a vulnerability audit of the Python dependencies (`pip-audit`); a scan of the repository for secrets and misconfiguration; and both images built and scanned for fixable high or critical vulnerabilities. `codeql.yml` adds static analysis of the code itself weekly and on pull requests. Dependabot opens pull requests for dependency, base-image and action updates.
- **A release** is a tag that starts with `v`, made on `main` (protect `v*` tags in the repository settings so only maintainers can make one). `release.yml` runs the whole CI again on that commit, builds each image and **scans it before publishing anything** (a fixable high or critical finding stops the release), publishes to `ghcr.io/<owner>/astra-backend` and `astra-studio` with build provenance and an SBOM, **signs each image by digest with cosign** (keyless: the signature is tied to this workflow and tag through GitHub's identity; there is no signing key to steal), attaches the SBOM as a signed attestation, and opens a GitHub release listing the digests.
- **On the server**, verify, then pull, then start (never build):

```bash
./verify_image.sh v1.4.0        # refuses an image that was not built and signed by this repository's release workflow for a v* tag
ASTRA_VERSION=1.4.0 docker compose -f docker-compose.prod.yml -f docker-compose.images.yml pull
ASTRA_VERSION=1.4.0 docker compose -f docker-compose.prod.yml -f docker-compose.images.yml up -d --no-build
python verify_https.py https://astra.example.org && python verify_db.py     # then check it, as after every update
```

Take a backup before updating (`backup_db.sh`): a migration changes the database, and migrations only add. To go back, start the previous version; to undo a migration, restore the backup into a new database. Pin by digest (`ASTRA_BACKEND_IMAGE`, `ASTRA_STUDIO_IMAGE`) where you can: a tag can be moved, a digest cannot. The packages are private unless you make them public; `docker login ghcr.io` with a token that can read packages.

**Not verified until the first release is made:** the pipeline was checked with the same tools locally (workflow lint, Dockerfile and shell lint, dependency audit, image and repository scans, compose and Caddyfile validation), but GitHub Actions itself can only run on GitHub, so the first tag is the real test of the signing and publishing steps. The actions are referenced by version tag, not commit hash: Dependabot keeps them current, and pinning each to a hash is a further step if your policy requires it.

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
