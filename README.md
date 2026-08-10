# Nano Blocker

**Intelligent Domain Blocker using UFW and DNS Filtering**

A complete, modular Flask web dashboard for blocking domains and IP addresses on
a Linux security lab. It combines **DNS filtering (dnsmasq)** for domain-level
control with **UFW** for IP-level enforcement, backed by SQLite.

> **Nano Blocker** is the product name; the repository may live in any folder.

---

## Project Overview

Nano Blocker gives an administrator a clean, dark dashboard to:

- Block and unblock domains (via poisoned DNS answers and/or UFW IP rules)
- Manage the UFW firewall (status, rules, enable/disable/reload/reset)
- Maintain blacklists and whitelists
- Create **temporary** blocks that expire automatically from stored timestamps
- Review a full security audit log

Every operation is real: DNS blocks are written to an application-owned
dnsmasq config, UFW rules are created/deleted with `ufw`, and the SQLite
database persists everything. There are no fake statistics and no simulated
system output.

> **Why DNS + UFW?**
> UFW operates on IP/network traffic and does not inherently provide reliable
> domain-name filtering. Nano Blocker therefore uses **DNS filtering as the
> primary domain-level control** (returning `0.0.0.0` for blocked domains) and
> **UFW for IP-level enforcement**. When a domain is blocked with the
> `DNS + UFW` method, its resolved IP addresses are added to the firewall and
> kept in sync when the domain's IPs change.

---

## Features

- **5 sidebar views only** — Dashboard, Domain Blocking, UFW Firewall,
  Blacklist & Whitelist, Temporary Blocks & Logs
- Session-based authentication (default `admin` / `admin`), password hashing,
  CSRF protection on every POST/DELETE
- Domain blocking with three methods: **DNS**, **UFW**, **DNS + UFW**
- Domain-to-IP resolution (IPv4 + IPv6), storage, and **IP re-sync** when
  addresses change
- Safe UFW management — rules are only removed when they carry the app's
  `IDB-*` comment tag; the ruleset is never flushed for normal blocking
- Temporary domain/IP blocks that survive restarts (timestamp-based expiry)
- Blacklist / whitelist with enable/disable and whitelist-overrides-blocking
- Filterable, searchable, exportable security audit log
- Background scheduler (expiry checks + IP sync) with duplicate-thread guard
- No shell-string construction anywhere — all system commands use argument lists

---

## Architecture

```
            +----------------------+
            |   Web Admin Panel    |
            |      Flask UI        |
            +----------+-----------+
                       |
                       v
            +----------------------+
            | Security Controller  |
            +----------+-----------+
                       |
        +--------------+---------------+
        |                              |
        v                              v
+-------------------+          +-------------------+
|   DNS Filtering   |          |       UFW         |
| dnsmasq / local   |          | Firewall Manager  |
+---------+---------+          +---------+---------+
          |                              |
          v                              v
   Domain Resolution              IP Blocking
   DNS Block/Allow                Rule Management
          |                              |
          +--------------+---------------+
                         |
                         v
              +----------------------+
              | SQLite Database      |
              +----------------------+
```

### Module layout

```
├── app.py                Flask app + error handlers
├── config.py             Central configuration (paths, tags, timeouts)
├── requirements.txt      Flask, Flask-WTF, Werkzeug
├── setup.sh              Linux installer
├── uninstall.sh          Linux uninstaller (only removes app-owned items)
├── database/
│   ├── database.py       Parameterized SQLite layer
│   └── schema.sql        admins, domains, domain_ips, blacklist, whitelist,
│                         firewall_rules, temporary_blocks, logs
├── services/
│   ├── utils.py          Validation (domains, IPs, ports, protocols) + errors
│   ├── logger.py         DB + file audit logging
│   ├── ufw_manager.py    Safe UFW subprocess wrapper, rule parser, IDB-* tags
│   ├── dns_manager.py    dnsmasq config management + reload
│   ├── domain_manager.py Block/unblock/refresh orchestration + resolution
│   ├── blacklist_manager.py / whitelist_manager.py
│   ├── temporary_block_manager.py   Timestamp-based temporary blocks
│   └── scheduler.py      Background expiry + IP sync thread
├── routes/               auth, dashboard, domains, firewall, lists, temporary
├── templates/            Jinja2 views (Nano Blocker UI)
└── static/
    ├── css/style.css     Dark cybersecurity theme
    ├── js/dashboard.js   Page controllers + shared helpers
    └── img/logo.svg      Placeholder logo — drop your own image here
```

---

## Requirements

- **Linux** (Debian/Ubuntu recommended) — the app performs real `ufw` and
  dnsmasq operations
- Python 3.9+
- UFW
- dnsmasq (or another local DNS filtering daemon)
- `sudo` configured for the service account (see below)

---

## Installation

On the Linux lab machine:

```bash
cd intelligent-domain-blocking
sudo bash setup.sh
```

`setup.sh` will:

1. Detect the distribution
2. Check Python, UFW and dnsmasq (warning if missing, but it keeps going)
3. Create a virtualenv and install dependencies from `requirements.txt`
4. Create `data/` and `logs/`
5. Initialize the SQLite schema and create the default admin account
6. Create `/etc/dnsmasq.d/intelligent-domain-blocker.conf`
7. Print the required sudoers policy
8. Start the app on `http://127.0.0.1:5000`

---

## UFW Setup

```bash
sudo apt install ufw          # Debian / Ubuntu
# or
sudo dnf install ufw          # Fedora
```

Enable it (optionally — the dashboard can also enable it):

```bash
sudo ufw --force enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
```

---

## DNS Filtering Setup

```bash
sudo apt install dnsmasq
sudo systemctl enable --now dnsmasq
```

Nano Blocker manages **only** `/etc/dnsmasq.d/intelligent-domain-blocker.conf`.
It never edits your main `dnsmasq.conf`. Blocked domains are written as
`address=/example.com/0.0.0.0`, which dnsmasq applies to the domain **and all
of its subdomains**. After any change the app reloads dnsmasq.

> DNS-over-HTTPS (DoH) / DNS-over-TLS (DoT) clients bypass local DNS filtering
> unless you also block those endpoints — see Limitations.

---

## Sudo Permission Setup

The web app runs UFW and dnsmasq commands through `sudo`. **Do not** grant
`ALL=(ALL) NOPASSWD: ALL`. Instead, scope sudo to exactly the commands the app
uses. For a service account named `nano`, add `/etc/sudoers.d/nano-blocker`:

```
nano ALL=(root) NOPASSWD: /usr/sbin/ufw status verbose
nano ALL=(root) NOPASSWD: /usr/sbin/ufw status numbered
nano ALL=(root) NOPASSWD: /usr/sbin/ufw allow
nano ALL=(root) NOPASSWD: /usr/sbin/ufw deny
nano ALL=(root) NOPASSWD: /usr/sbin/ufw reject
nano ALL=(root) NOPASSWD: /usr/sbin/ufw delete
nano ALL=(root) NOPASSWD: /usr/sbin/ufw --force enable
nano ALL=(root) NOPASSWD: /usr/sbin/ufw --force disable
nano ALL=(root) NOPASSWD: /usr/sbin/ufw --force reset
nano ALL=(root) NOPASSWD: /usr/sbin/ufw reload
nano ALL=(root) NOPASSWD: /usr/sbin/systemctl reload dnsmasq
nano ALL=(root) NOPASSWD: /usr/sbin/systemctl restart dnsmasq
nano ALL=(root) NOPASSWD: /usr/sbin/systemctl is-active dnsmasq
```

Install with `visudo -f /etc/sudoers.d/nano-blocker`. Adjust binary paths for
your distro (`/usr/bin/ufw` on some systems).

---

## Running the Application

```bash
# after setup.sh, or manually:
.venv/bin/python app.py
```

The app binds to **127.0.0.1** by default. Override with environment variables:

```bash
IDB_HOST=0.0.0.0 IDB_PORT=8080 IDB_SECRET_KEY="a-long-random-string" \
  IDB_ADMIN_PASSWORD="a-strong-password" .venv/bin/python app.py
```

---

## Default Login

| Field    | Value   |
|----------|---------|
| Username | `admin` |
| Password | `admin` |

These credentials are **for local testing only**. Change the password from the
sidebar → **Change Password** before any real deployment. The About & Settings
modal reminds you of this.

---

## Dashboard Usage

### Dashboard

Cards for blocked/allowed domains, blacklist/whitelist counts, UFW rules and
temporary blocks; live **UFW status** and **DNS filter status**; recent
security activity; quick actions (Block, Unblock, Blacklist, Temporary Block).

### Domain Blocking

- **Add Domain** — domain name, reason, block method (DNS / UFW / DNS + UFW).
  The domain is validated; shell operators and injection strings are rejected.
- Table shows domain, status (`BLOCKED` / `ALLOWED`), method, resolved IPs,
  reason, created time.
- Actions: **Block**, **Unblock**, **Refresh IPs**, **View Details**.

Blocking a domain:
1. Validate the domain
2. Check the whitelist (refused if whitelisted)
3. Persist to the database
4. Configure DNS filtering (`address=/domain/0.0.0.0`)
5. Resolve IPv4/IPv6 addresses
6. Store them in `domain_ips`
7. Apply UFW `deny out` rules tagged `IDB-DOMAIN-<domain>` (when UFW enabled)
8. Log the operation

Unblocking reverses all of it and removes **only** Nano Blocker's rules.

### UFW Firewall

- Live status, default incoming/outgoing policies
- **Add UFW Rule** — action (allow/deny/reject), direction, source/destination
  IP, port, protocol, comment. Every rule is tagged `IDB-USER-*`.
- Rules table with `APP` / `MANUAL` origin. Rules the app did **not** create
  require explicit confirmation before deletion.
- Controls: **Enable**, **Disable**, **Reload**, **Reset**. Disable and Reset
  require a confirmation dialog; Reset warns that ALL rules are removed.

### Blacklist & Whitelist

Two tabs. Values can be domains or IPs (auto-detected).

- **Blacklist** — known-bad values, can be enabled/disabled, removed.
- **Whitelist** — trusted values that **override blocking**. Attempting to
  block a whitelisted domain shows:
  > This domain is currently whitelisted. Remove it from the whitelist before blocking.

### Temporary Blocks & Logs

- Create temporary blocks (domain or IP) for 5 min → 24 h (or custom).
- Expiry uses the stored `expires_at` timestamp, so it survives restarts. The
  scheduler and every page load check for expirations.
- **Security Logs** — filterable (Domain / Firewall / Blacklist / Whitelist /
  Temporary / Authentication / DNS / Errors), searchable, **Export CSV**, and
  **Clear Logs** (confirmed).

---

## JSON API (all authenticated)

| Method | Endpoint                        | Purpose                        |
|--------|---------------------------------|--------------------------------|
| GET    | `/api/dashboard/stats`          | Live counts + UFW/DNS status   |
| GET    | `/api/domains`                  | List domains                   |
| GET    | `/api/domains/<id>`             | Domain details + resolved IPs  |
| POST   | `/api/domains/block`            | Block a domain                 |
| POST   | `/api/domains/unblock`          | Unblock a domain               |
| POST   | `/api/domains/refresh`          | Re-resolve IPs + sync UFW      |
| GET    | `/api/ufw/status`               | UFW status                     |
| GET    | `/api/ufw/rules`                | Numbered UFW rules             |
| POST   | `/api/ufw/rules`                | Add a rule                     |
| DELETE | `/api/ufw/rules/<num>`          | Delete a rule                  |
| POST   | `/api/ufw/enable` · `/disable` · `/reload` · `/reset` | UFW controls |
| GET/POST | `/api/lists/<blacklist\|whitelist>` | List / add entries         |
| POST   | `/api/lists/<tab>/<id>/toggle`  | Enable/disable entry           |
| DELETE | `/api/lists/<tab>/<id>`         | Remove entry                   |
| GET    | `/api/temporary`                | List temporary blocks          |
| POST   | `/api/temporary/block`          | Create a temporary block       |
| POST   | `/api/temporary/<id>/expire`    | Expire now                     |
| GET    | `/api/logs`                     | Filterable logs                |
| DELETE | `/api/logs`                     | Clear logs (confirm required)  |
| GET    | `/api/logs/export`              | Download logs as CSV           |
| POST   | `/api/auth/password`            | Change password                |

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| "UFW is not installed" | Install UFW, or accept DNS-only blocking. |
| "DNS filtering service is unavailable" | Install/start dnsmasq (`systemctl enable --now dnsmasq`). |
| "Permission denied" | Add the sudoers entries above; verify paths (`which ufw`). |
| App won't resolve domains | Check outbound DNS works (`getent hosts example.com`). |
| IPv6 rules not created | UFW needs IPv6 enabled (`IPV6=yes` in `/etc/default/ufw`). |
| Scheduler seems to run twice | That's Flask's dev reloader; in production it starts once. |
| Port already in use | Set `IDB_PORT` to another port. |
| Can't write dnsmasq config | Check that the app runs with the sudo rules above. |

Detailed technical errors go to `logs/application.log`. The UI only ever shows
friendly messages.

---

## Security Notes

- All system commands are executed via `subprocess.run([...])` with argument
  lists, `capture_output=True`, `text=True`, and a timeout. **No shell
  concatenation, no arbitrary command execution.**
- All SQL is parameterized.
- Every POST/DELETE is CSRF-protected.
- Passwords are hashed with Werkzeug.
- The app binds to `127.0.0.1` by default and should not be exposed publicly.
- Rule comments carry `IDB-DOMAIN-`, `IDB-TEMP-`, `IDB-IP-`, `IDB-USER-` tags
  so the app can identify its own rules and leave everything else alone.

---

## Limitations

1. Domain-to-IP mappings change frequently; IP sync keeps rules current but is
   not instantaneous.
2. CDN-hosted domains can share IP addresses — blocking an IP may affect more
   than the intended domain.
3. DNS filtering is the **primary** domain control; UFW is IP-level only.
4. HTTPS content cannot be inspected via DNS/UFW (they block the connection,
   not decrypt it).
5. DNS-over-HTTPS and DNS-over-TLS can bypass local DNS filtering unless those
   endpoints are separately blocked.
6. IPv6 must be considered when enforcing IP blocks.
7. This is intended for a **controlled Linux lab environment**.
8. Default credentials (`admin`/`admin`) are for testing only.

---

## Testing

Run through the following on the lab machine (and verify each button in the
UI — nothing is simulated):

### Authentication
- [ ] Login with `admin` / `admin`
- [ ] Logout
- [ ] Unauthenticated access to `/dashboard` redirects to `/login`
- [ ] API without a session returns 401

### Domain
- [ ] Add/block a domain (`example.com`) with `DNS + UFW`
- [ ] Confirm `address=/example.com/0.0.0.0` in the app's dnsmasq file
- [ ] Confirm an `IDB-DOMAIN-example-com` UFW rule appears
- [ ] Attempt to block a whitelisted domain → friendly refusal
- [ ] Refresh IPs and confirm the UFW rules track the resolution
- [ ] Unblock → DNS entry removed, app UFW rules removed, unrelated rules intact

### UFW
- [ ] Status reflects real `ufw status`
- [ ] Add a rule (tagged `IDB-USER-*`) and delete it
- [ ] Deleting a manual rule requires confirmation
- [ ] Reset UFW warns and requires confirmation

### Lists
- [ ] Add / remove a blacklist entry (domain + IP)
- [ ] Add / remove a whitelist entry
- [ ] Toggle enable/disable reflects in the UI

### Temporary
- [ ] Create a 5-minute block; status shows ACTIVE with countdown
- [ ] Wait for expiry (or use Expire Now) → status EXPIRED, enforcement removed
- [ ] Restart the app with an active block → it still expires correctly

### Logs
- [ ] Block/unblock/UFW/expiration events all appear
- [ ] Filters and search work
- [ ] Export CSV downloads
- [ ] Clear Logs requires confirmation

---

## Acceptance Checklist

```
[✓] Admin login works              [✓] Whitelist works
[✓] Dashboard works                [✓] Temporary blocking works
[✓] Exactly five sidebar views     [✓] Automatic temporary expiration works
[✓] Domain blocking works          [✓] Security logging works
[✓] Domain unblocking works        [✓] SQLite persistence works
[✓] DNS filtering works            [✓] Input validation works
[✓] Domain IP resolution works     [✓] Safe subprocess execution works
[✓] UFW status works               [✓] App-managed UFW rules identifiable
[✓] UFW rule management works      [✓] Unrelated UFW rules not deleted
[✓] Blacklist works                [✓] Installation documentation exists
                                   [✓] Troubleshooting documentation exists
```

---

## License / Demo

Built as a college cybersecurity project demonstration. Use it on a local
Linux security lab; do not rely on it as production network security without
hardening the deployment (dedicated service account, scoped sudo, changed
credentials, HTTPS front-end).
