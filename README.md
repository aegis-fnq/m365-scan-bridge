# m365-scan-bridge

A small SMTP relay that lets a scanner or multifunction printer that only speaks SMTP send mail
through **Microsoft Graph**, as one Microsoft 365 mailbox. Optionally, scans sent to a chosen
address are filed in a SharePoint folder instead of being emailed.

## Why

Microsoft is retiring basic authentication for SMTP AUTH in Exchange Online. Most scanners and
printers can only log in to SMTP with a username and password; they cannot do OAuth. Once basic
SMTP AUTH is gone, "scan to email" stops working.

This bridge runs on a small Linux machine on your LAN. The printer sends to it with ordinary SMTP
(STARTTLS plus a username and password that exist only on the bridge). The bridge then sends the
message through Microsoft Graph using an app-only credential (a certificate, or a client secret)
that Exchange restricts to one mailbox.

## How it works

```
printer --SMTP + STARTTLS + AUTH--> m365-scan-bridge --HTTPS (Graph sendMail / upload)--> Microsoft 365
```

1. The printer connects from an address listed in `allowed_clients`, upgrades to TLS 1.2 or
   later, and logs in. Anything else is refused (`530`, `535` or `550`). Five failed logins from
   one address within ten minutes lock that address out for the rest of the ten minutes.
2. Each message is rebuilt: From is forced to `sender`; To, Cc and Bcc hold exactly the SMTP
   envelope's recipients; every other header (Reply-To included) is dropped.
3. It is sent with Graph `sendMail` as `sender`. If a recipient is the SharePoint
   `trigger_address`, the message's attachments are uploaded to the configured folder instead
   (other recipients still get the email).
4. Hourly limits on messages and recipients, and a per-message recipient limit, cap misuse.
   After repeated delivery failures it emails `alert_address` (at most hourly).

Logs show peers, sizes, recipient counts and outcomes, never subjects or bodies. See
[SECURITY.md](SECURITY.md) for the threat model.

## Requirements

- A Linux machine with systemd on the same network as the printer, with a fixed (reserved)
  address. Commands below assume Debian or Ubuntu; adapt them for other distributions.
- [uv](https://docs.astral.sh/uv/) (it fetches Python 3.11 or later if the system lacks it)
  and `openssl`.
- A Microsoft 365 tenant, an admin who can register an Entra application, and Exchange Online
  PowerShell (`ExchangeOnlineManagement` module).
- The printer must support SMTP with STARTTLS and a username and password, and ideally the
  ability to import a CA certificate and verify the server's certificate.

## Install

Run as root (or with `sudo`) from a checkout of this repository. Replace `192.0.2.20` with the
bridge machine's reserved address and `192.0.2.10` with the printer's.

```sh
# 1. uv, installed system-wide
curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh

# 2. Service user, code and runtime directories (see "File ownership" below)
useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin m365-scan-bridge
install -d -o root -g root -m 755 /opt/m365-scan-bridge /etc/m365-scan-bridge
cp -r m365_scan_bridge deploy pyproject.toml uv.lock README.md LICENSE /opt/m365-scan-bridge/
chown -R root:root /opt/m365-scan-bridge
chmod -R u=rwX,go=rX /opt/m365-scan-bridge
chmod 755 /opt/m365-scan-bridge/deploy/*.sh
install -d -o m365-scan-bridge -g m365-scan-bridge -m 755 /opt/m365-scan-bridge/.venv /opt/m365-scan-bridge/.python
install -d -o m365-scan-bridge -g m365-scan-bridge -m 700 /var/cache/m365-scan-bridge
sudo -u m365-scan-bridge env UV_PYTHON_INSTALL_DIR=/opt/m365-scan-bridge/.python \
    UV_CACHE_DIR=/var/cache/m365-scan-bridge \
    /usr/local/bin/uv sync --locked --no-dev --project /opt/m365-scan-bridge

# 3. Settings (no secrets in this file); edit it as described under "Configuration reference"
cp deploy/config.example.toml /etc/m365-scan-bridge/config.toml

# 4. TLS: a local CA and a server certificate for the bridge's address (see "TLS" below)
sh deploy/make-ca.sh --ip 192.0.2.20

# 5. The SMTP password the printer will use
(umask 077; openssl rand -base64 18 > /etc/m365-scan-bridge/smtp-password)

# 6. The Graph credential. Stop here and work through "Entra app registration" and
#    "Restrict the app to one mailbox" below, then come back. That section creates the
#    credential file: graph-key.pem for a certificate (certificate_key_file), or
#    client-secret for a client secret (secret_file). Set the matching [credential]
#    keys in config.toml.

# 7. Ownership and modes. The service user owns only the files it reads; the directory,
#    ca-key.pem and cert.env stay root's.
cd /etc/m365-scan-bridge
chown m365-scan-bridge: config.toml smtp-password tls-key.pem tls-cert.pem
chmod 600 smtp-password tls-key.pem
for f in graph-key.pem client-secret; do
    [ -e "$f" ] && chown m365-scan-bridge: "$f" && chmod 600 "$f"
done
cd -

# 8. Check, then start
sudo -u m365-scan-bridge /opt/m365-scan-bridge/.venv/bin/m365-scan-bridge /etc/m365-scan-bridge/config.toml --check
cp deploy/m365-scan-bridge.service deploy/m365-scan-bridge-renew-cert.service \
   deploy/m365-scan-bridge-renew-cert.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now m365-scan-bridge m365-scan-bridge-renew-cert.timer

# 9. Firewall: only the printer may reach the port
ufw allow from 192.0.2.10 to any port 2525 proto tcp
```

### File ownership

Root runs `deploy/renew-cert.sh` and `deploy/make-ca.sh` (weekly, from the timer), and
`make-ca.sh` reads `/etc/m365-scan-bridge/cert.env` as a shell script. Anything the service user
could write there, it could use to run commands as root. So:

- `/opt/m365-scan-bridge` and everything in it is owned by root (directories 755, files 644,
  scripts 755), except `.venv` and `.python`, which belong to the service user so that `uv sync`
  can run as that user. uv's cache is `/var/cache/m365-scan-bridge`, also the service user's.
- `/etc/m365-scan-bridge` itself, `ca-key.pem` and `cert.env` stay owned by root. The service
  user owns only the individual files it reads (step 7).

To update the code later, copy the new files in as root, repeat the `chown`/`chmod` lines of step
2, give the runtime folders back to the service user with
`sudo chown -R m365-scan-bridge:m365-scan-bridge /opt/m365-scan-bridge/.venv /opt/m365-scan-bridge/.python`
(the recursive `chown` to root takes their contents too), then run the `uv sync` line and restart
the service.

`--check` proves that the settings load, the TLS certificate loads and Microsoft issues a token.
It does not prove the mailbox scope: use `Test-ServicePrincipalAuthorization` (below) for that.

Logs: `journalctl -u m365-scan-bridge`. The alert email shares the Graph path it reports on, so
for a second signal add `OnFailure=` to the unit, pointing at something that notifies you by
another route.

## Entra app registration (certificate credential)

1. In the Entra admin centre, **App registrations > New registration**: single tenant, no
   redirect URI. Note the **Application (client) ID** and **Directory (tenant) ID**.
2. **Do not add or consent `Mail.Send` under API permissions.** Consented there, it lets the app
   send as every mailbox in the tenant. The mailbox-scoped grant comes from Exchange, below.
3. Create the certificate on the bridge machine; the private key never leaves it:

   ```sh
   (umask 077; openssl req -x509 -newkey rsa:2048 -nodes -days 730 -subj "/CN=m365-scan-bridge" \
       -keyout /etc/m365-scan-bridge/graph-key.pem -out /etc/m365-scan-bridge/graph-cert.pem)
   openssl x509 -in /etc/m365-scan-bridge/graph-cert.pem -noout -fingerprint -sha1 | sed 's/.*=//; s/://g'
   ```

4. Under **Certificates & secrets > Certificates**, upload `graph-cert.pem` (the public half
   only). Check the thumbprint Entra shows matches the one printed, and put it in
   `certificate_thumbprint`.

A client secret also works, but it expires and has to be pasted by hand. To use one instead of
steps 3 and 4, add a secret under **Certificates & secrets > Client secrets**, write its value to
`/etc/m365-scan-bridge/client-secret` with `(umask 077; cat > /etc/m365-scan-bridge/client-secret)`,
and set `secret_file` (not `certificate_key_file` or `certificate_thumbprint`) in `[credential]`.

## Restrict the app to one mailbox (Exchange RBAC for Applications)

In Exchange Online PowerShell, with the app's client ID and the **Object ID of its Enterprise
Application** (service principal; not the app registration's object ID):

```powershell
Connect-ExchangeOnline            # if it fails with a WAM error, use: Connect-ExchangeOnline -DisableWAM

New-ServicePrincipal -AppId <client-id> -ObjectId <enterprise-app-object-id> -DisplayName "m365-scan-bridge"
New-ManagementScope -Name "Scan bridge mailbox" -RecipientRestrictionFilter "PrimarySmtpAddress -eq 'scanner@example.com'"
New-ManagementRoleAssignment -App <client-id> -Role "Application Mail.Send" -CustomResourceScope "Scan bridge mailbox"

Test-ServicePrincipalAuthorization -Identity <client-id> -Resource scanner@example.com   # expect InScope True
Test-ServicePrincipalAuthorization -Identity <client-id> -Resource someone@example.com   # expect InScope False
```

If `New-ManagementScope` says the organisation must be customised first, run
`Enable-OrganizationCustomization`; that can take about an hour to take effect before the scope
commands work. Role assignments can also take a while to propagate, so a `--check` that gets a
token but a first send that fails with 403 may just need more time.

The sending mailbox can be a shared mailbox (no licence needed).

## SharePoint filing (optional)

Mail addressed to `[sharepoint] trigger_address` has its attachments (or a single-part body that
is itself a file) uploaded to `folder` in the library `drive_id`, named with a timestamp. Existing
files are never overwritten.

1. In Entra, add the Microsoft Graph **application** permission `Sites.Selected` and grant admin
   consent. On its own it grants access to nothing.
2. As an admin (for example in Graph Explorer), grant the app write on the one site:

   ```http
   GET  https://graph.microsoft.com/v1.0/sites/<tenant>.sharepoint.com:/sites/<site-name>
        -> note "id"
   POST https://graph.microsoft.com/v1.0/sites/<site-id>/permissions
        {"roles": ["write"], "grantedToIdentities": [{"application": {"id": "<client-id>", "displayName": "m365-scan-bridge"}}]}
   GET  https://graph.microsoft.com/v1.0/sites/<site-id>/drives
        -> the "id" of the document library is drive_id
   ```

3. Fill in the `[sharepoint]` table and restart the service.

## TLS: use a small local CA

The printer should verify the bridge's certificate; otherwise anyone on the LAN who can pose as
the bridge can capture the printer's SMTP password. Rather than trusting a self-signed server
certificate directly, create a small local CA and import **only the CA certificate** into the
printer. Then the server certificate can be reissued without touching the printer again.

`deploy/make-ca.sh` does this:

- CA certificate: `basicConstraints = CA:TRUE`, `keyUsage = keyCertSign, cRLSign`, ten years.
  Its key `ca-key.pem` is mode 600 and stays root-owned. The script refuses to overwrite an
  existing CA key; use `--server-only` to reissue only the server certificate.
- Server certificate: `CA:FALSE`, `extendedKeyUsage = serverAuth`, with the bridge's IP address
  (and optional DNS name, `--dns`) in subjectAltName; 397 days. Key mode 600, owned by the
  service user; certificate mode 644. `--ip` must be an IPv4 or IPv6 address and `--dns` a plain
  host name (letters, digits, hyphens and dots). The address(es) are recorded in the root-owned
  `cert.env` for renewals; see Rotation to change them.
- `notBefore` is backdated by seven days, because a printer whose clock is a little behind would
  otherwise reject a brand-new certificate as not yet valid.

`deploy/renew-cert.sh` reissues the server certificate from the CA when fewer than 60 days remain
and restarts the service. `m365-scan-bridge-renew-cert.timer` runs it weekly.

In the printer, import `/etc/m365-scan-bridge/ca-cert.pem` as a trusted CA certificate and turn on
certificate verification for the outgoing mail server.

## Point the printer at it

In the printer's web interface, scan-to-email outgoing (SMTP) server:

- Server: the bridge's address (the one in the certificate); port: `listen_port` (2525)
- TLS: STARTTLS on, with server certificate verification on
- Authentication: on; username from `[smtp] username`, password from `smtp-password`
- Maximum email size: 2 MB (see Troubleshooting)

Send test scans to an internal address, an external address and, if used, the SharePoint trigger
address.

## Troubleshooting

**The printer reports "bad certificate" or a TLS/SSL error.** Check the printer's clock first.
A printer whose date is wrong rejects every certificate; we have seen one whose clock had reset to
2001 refuse a valid certificate with "bad certificate". Set the printer's NTP (time server)
setting and confirm the date, then retry. Next, check that the server address on the printer
matches an IP or DNS name in the certificate, and that the CA certificate (not the server
certificate) is imported as trusted.

**Large scans fail, or arrive split.** Graph accepts at most about 3 MB of message once encoded;
the bridge refuses anything bigger with `552 Message too big for email`. Many printers (HP among
them) split a scan across several emails when it exceeds their "maximum email size" setting.
The bridge does not reassemble those parts: each part is relayed as its own message, and must
itself fit under the limit. Set the printer's maximum email size to **2 MB** to leave headroom,
lower the scan resolution, or send large scans to the SharePoint trigger address (up to
`sharepoint_max_bytes` per file).

**The printer shows a failure code.**

- `530`/`535`: STARTTLS or login failed (wrong password, or locked out after five failures; wait
  ten minutes).
- `550 Not allowed to relay`: the printer's address is not in `allowed_clients`, or it did not log
  in.
- `451`: a temporary problem (Microsoft unreachable, throttled); the printer may retry.
- `452`: too many recipients, or the hourly limit is reached.
- `554`: a send that cannot safely be retried (it may already have gone out, or part of a
  SharePoint upload succeeded). Check the recipient's inbox or the folder before scanning again.

**Graph returns 403 on send.** The RBAC role assignment is missing, still propagating, or scoped
to a different mailbox than `sender`. Run `Test-ServicePrincipalAuthorization`.

**The service will not start.** Run the `--check` command from the install steps; it prints the
setting or file at fault, for example a missing `allowed_clients` or a secret file that others
can read.

## Configuration reference

The settings file is TOML. Unknown keys are rejected. Files named here, except `tls_cert_file`,
must be owned by the user running the bridge and not readable by group or others.

| Key | Required | Default | Meaning |
|---|---|---|---|
| `tenant_id` | yes | | Entra tenant (directory) ID |
| `client_id` | yes | | App registration's Application (client) ID |
| `sender` | yes | | Mailbox every message is sent as |
| `allowed_clients` | yes | none | Non-empty list of IP addresses allowed to connect and send |
| `listen_host` | no | `0.0.0.0` | Address to listen on |
| `listen_port` | no | `2525` | Port to listen on (1 to 65535) |
| `log_level` | no | `INFO` | `DEBUG`, `INFO`, `WARNING` or `ERROR` |
| `max_messages_per_hour` | no | `60` | 1 to 10000 |
| `max_recipients_per_hour` | no | `200` | 1 to 10000 |
| `max_recipients_per_message` | no | `50` | 1 to 500; may not exceed `max_recipients_per_hour` |
| `sharepoint_max_bytes` | no | `104857600` | Largest single file filed in SharePoint (up to 262144000) |
| `alert_address` | no | none | Address alerted after repeated delivery failures (at most hourly) |
| `alert_after_failures` | no | `3` | Failures in a row before alerting (1 to 100) |
| `[smtp] username` | yes | | Username the printer logs in with |
| `[smtp] password_file` | yes | | File holding the printer's password |
| `[smtp] tls_cert_file` | yes | | Server certificate (PEM) for STARTTLS |
| `[smtp] tls_key_file` | yes | | Server private key (PEM) |
| `[credential] certificate_key_file` | one of | | Private key for the Graph certificate credential |
| `[credential] certificate_thumbprint` | with key | | SHA-1 thumbprint of that certificate |
| `[credential] secret_file` | one of | | File holding a client secret, instead of a certificate |
| `[sharepoint] trigger_address` | if table | | Recipient address that means "file in SharePoint" |
| `[sharepoint] drive_id` | if table | | Document library's drive ID |
| `[sharepoint] folder` | if table | | Folder within the library (not the root) |

`[credential]` needs exactly one of `certificate_key_file` (with `certificate_thumbprint`) or
`secret_file`. The `[sharepoint]` table is optional, but if present all three keys are required.

## Rotation

- **Graph certificate:** create a new one as above, upload it, update `certificate_thumbprint`,
  restart, run `--check`, then remove the old certificate from Entra.
- **Client secret:** add a new secret, write it to the secret file, restart, run `--check`, then
  delete the old secret.
- **SMTP password:** generate a new one, restart, and update the printer.
- **TLS server certificate:** renewed automatically by the timer. The local CA lasts ten years.
- **Bridge address change:** run `sh /opt/m365-scan-bridge/deploy/make-ca.sh --server-only --ip
  <new address>` (add `--dns <name>` if the certificate should also carry a name; give both to
  keep both). It reissues the server certificate, records the new address in `cert.env` for
  renewals, and leaves the CA alone, so the printer needs no new CA certificate. Restart the
  service and update the printer's server address.

## Development

```sh
uv run --locked --extra dev pytest -q tests
```

## Licence

MIT; see [LICENSE](LICENSE).
