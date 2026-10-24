#!/usr/bin/env bash
# Start the Xcerberus File Portal lab on localhost (PHP built-in server).
# AUTHORISED, ISOLATED USE ONLY — never expose this to a network.
set -e
cd "$(dirname "$0")"
command -v php >/dev/null || { echo "Install php-cli first (e.g. sudo apt-get install -y php-cli)"; exit 1; }
echo "[*] Xcerberus File Portal — http://127.0.0.1:8080/   (login: support / Xcerberus@Support2026)"
echo "[*] Deliberately vulnerable. Ctrl-C to stop."
exec php -S 127.0.0.1:8080 -t app
