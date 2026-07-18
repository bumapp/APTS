# APTS Database — Deployment Runbook

Step-by-step guide for deploying the APTS PostgreSQL database
container on a fresh Ubuntu 24.04 host.


---

## 0. Prerequisites

* An Ubuntu 24.04 LTS VM with at least **2 vCPU, 2 GB RAM, 20 GB disk**
  (the DB alone is much lighter than the full stack).
* SSH access, initially as `root` or another sudo-capable account.
* The `database.zip` archive on your workstation, containing:
  * `docker-compose.database.yml` (the standalone DB compose file)
  * `bootstrap/init_db.sql`
  * `bootstrap/generate_certs.sh`
  * `bootstrap/generate_tokens.py`

---

## 1. Create a non-root user

Log in as root, then create a sudo-capable user:

```bash
adduser apts-admin
usermod -aG sudo apts-admin
exit
```

Log back in as the new user:

```bash
ssh apts-admin@<host-ip>
whoami                         # should print: apts-admin
id                             # note the UID (typically 1000 or 1001)
```

Never do the rest of this runbook as root — the postgres container runs
as UID 999 internally and expects its mounted files to have specific
ownership. Running the bootstrap as root produces files owned by UID 0
that the container can't read.

---

## 2. Update the OS

```bash
sudo apt-get update
sudo apt-get -y upgrade
```

Reboot if the kernel or `libc` was upgraded:

```bash
sudo reboot
```

Reconnect after the reboot.

---

## 3. Install the tools we need

```bash
sudo apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    openssl \
    python3 \
    python3-pip \
    unzip \
    git
```

Verify:

```bash
python3 --version     # Python 3.12.x
openssl version       # OpenSSL 3.x
```

---

## 4. Install Docker Engine + Compose v2

### 4.1 Remove any old Docker installation

```bash
for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do
    sudo apt-get remove -y "$pkg" 2>/dev/null || true
done
```

### 4.2 Add Docker's official GPG key and apt repository

```bash
sudo install -m 0755 -d /etc/apt/keyrings

sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
    https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
```

### 4.3 Install Docker Engine, CLI, and Compose

```bash
sudo apt-get install -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin
```

### 4.4 Let apts-admin run Docker without sudo

```bash
sudo usermod -aG docker apts-admin
```

**Log out and back in.** SSH sessions cache their group memberships at
login time; a new shell in the same session won't see the new group.

```bash
exit
ssh apts-admin@<host-ip>
groups                # must include 'docker'
```

### 4.5 Verify Docker works without sudo

```bash
docker version              # both Client and Server sections should print
docker compose version      # v2.x
docker run --rm hello-world # downloads and runs, no sudo needed
```

If `hello-world` prints its banner without asking for `sudo`, Docker is
ready.

---

## 5. Get the project files onto the host

### 5.1 Create a working directory

```bash
mkdir -p ~/apts
cd ~/apts
```

### 5.2 Transfer the archive

From your **workstation** (separate terminal):

```bash
scp apts-skeleton.zip apts-admin@<host-ip>:~/apts/
```

Back on the **host**:

```bash
cd ~/apts
unzip apts-skeleton.zip
cd apts-skeleton
```

### 5.3 Confirm the project files belong to apts-admin

```bash
ls -ld . && ls -l docker-compose.database.yml
```

Owner should be `apts-admin apts-admin` on both. If either shows
`root root`, fix it:

```bash
sudo chown -R "$USER:$USER" ~/apts
```

### 5.4 Make the bootstrap scripts executable

```bash
chmod +x bootstrap/generate_certs.sh bootstrap/generate_tokens.py
```

---

## 6. Prepare certificates and password

### 6.1 Generate the TLS certificates

```bash
./bootstrap/generate_certs.sh
```

Expected output:

```
==> generating certificates in ./certs/
    orchestrator: generated
    agent-recon:  generated
    ...
==> building trust bundle
certs:        21 files
trust bundle: ./certs/trust-bundle.pem
done.
```

Note: the script generates certs for every APTS component, not just the
database. The unused ones are harmless — they simply sit in `./certs/`
until other containers are deployed later.

Verify one cert has the right SAN:

```bash
openssl x509 -in certs/database.crt -noout -text | grep -A1 "Subject Alt"
# should show: DNS:database, DNS:localhost
```

### 6.2 Fix the DB cert ownership (critical)

The postgres image runs as UID 999 inside its container and refuses to
load a TLS key it doesn't own. The certs were just written by
apts-admin (UID 1000 or 1001), so we need to hand the two DB files over
to UID 999:

```bash
sudo chown 999:999 certs/database.key certs/database.crt
sudo chmod 600 certs/database.key
sudo chmod 644 certs/database.crt
```

Verify:

```bash
stat -c '%u %g %a %n' certs/database.key certs/database.crt
# 999 999 600 certs/database.key
# 999 999 644 certs/database.crt
```

### 6.3 Generate the DB password

```bash
mkdir -p tokens && chmod 700 tokens

openssl rand -base64 32 | tr -d '=+/' | cut -c1-32 > tokens/db_password.txt
chmod 600 tokens/db_password.txt

ls -la tokens/db_password.txt   # sanity check: mode 600, owned by apts-admin
```

The file name **must** be `db_password.txt` — it's referenced by name
in `docker-compose.database.yml` as the source of the `db_password`
secret. If you rename it, update the compose file too.

---

## 7. Bring up the database

### 7.1 Start the container

```bash
docker compose -f docker-compose.database.yml up -d database
```

Follow the logs until you see the ready message:

```bash
docker compose -f docker-compose.database.yml logs -f database
```

Expected sequence on a first-time-clean start:

```
PostgreSQL init process complete; ready for start up.
...
CREATE DATABASE
running /docker-entrypoint-initdb.d/00-init.sql
CREATE TABLE
CREATE INDEX
... (five CREATE TABLE lines in total)
...
database system is ready to accept connections
```

Ctrl-C once you see the final line.

### 7.2 Confirm health

```bash
docker compose -f docker-compose.database.yml ps database
# STATUS should include 'healthy'
```

### 7.3 Verify the schema loaded

```bash
docker compose -f docker-compose.database.yml exec -T database \
    psql -U apts -d apts -c "\dt"
```

Expected — exactly five tables:

```
              List of relations
 Schema |       Name        | Type  | Owner
--------+-------------------+-------+-------
 public | agent_results     | table | apts
 public | audit_log         | table | apts
 public | engagements       | table | apts
 public | engagement_state  | table | apts
 public | token_hashes      | table | apts
```

### 7.4 If §7.1 failed for any reason — wipe and retry

The postgres image only runs `initdb` on an empty data directory. If
the first startup failed partway through (bad cert permissions, wrong
password file name, etc.), the volume is left half-initialised and
every subsequent start silently skips the `CREATE DATABASE` step —
you'll end up with a running-but-empty server and errors like:

```
FATAL: database "apts" does not exist
```

If that happens, wipe the volume and start over:

```bash
docker compose -f docker-compose.database.yml down
docker volume rm apts-skeleton_db_data
docker volume ls | grep db_data      # should print nothing

# Fix whatever caused the original failure, then repeat §7.1
docker compose -f docker-compose.database.yml up -d database
docker compose -f docker-compose.database.yml logs -f database
```

Safe as long as no real data has been written yet.

---

## 8. Generate bearer tokens

Even though only the database is running, the token-generation step
still works — it just seeds the `token_hashes` table with hashes for
every APTS component. The raw token files sit in `./tokens/` waiting
for the other containers to be deployed later.

```bash
./bootstrap/generate_tokens.py
```

Expected output:

```
==> generating tokens for all components
    orchestrator: generated + upserted
    agent-recon:  generated + upserted
    ...
    sandbox:      generated + upserted

tokens written to ./tokens/
hashes upserted into token_hashes table
```

Note: `generate_tokens.py` uses `docker compose exec database psql ...`
internally. If you renamed the compose file, the script may need a
small tweak — see the manual-deployment appendix for details.

### 8.1 Confirm the DB and filesystem are in sync

Both should show the same 10 components:

```bash
ls tokens/*.token | wc -l    # should be 10
```

```bash
docker compose -f docker-compose.database.yml exec -T database \
    psql -U apts -d apts \
    -c "SELECT component FROM token_hashes ORDER BY component;"
```

Expected — ten components:

```
   component
---------------
 agent-adviser
 agent-exploit
 agent-mitre
 agent-recon
 agent-script
 agent-vuln
 database
 mcp-tools
 orchestrator
 sandbox
(10 rows)
```

---

## 9. What next

The database is now running and reachable at `database:5432` on the
`apts-net` bridge network. Tokens are seeded. Certificates for every
component are ready.

* If this deployment is standalone (DB only), the runbook ends here.
  You can inspect the DB with `docker compose -f docker-compose.database.yml
  exec database psql -U apts -d apts` and query away.
* If this is a first step toward the full stack, continue with the
  main deployment runbook from §5 to bring up the orchestrator,
  agents, MCP tools, and sandbox.

---

## 10. Everyday operations

Stop the database (data volume preserved):

```bash
docker compose -f docker-compose.database.yml down
```

Start it back up:

```bash
docker compose -f docker-compose.database.yml up -d
```

Follow logs:

```bash
docker compose -f docker-compose.database.yml logs -f database
```

Interactive psql:

```bash
docker compose -f docker-compose.database.yml exec database \
    psql -U apts -d apts
```

Nuke everything (**destroys DB data**):

```bash
docker compose -f docker-compose.database.yml down -v
rm -rf certs/ tokens/
```
