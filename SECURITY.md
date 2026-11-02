# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub's security advisories: on this
repository's **Security** tab, choose **Report a vulnerability**. Do not open a public issue.

Only the latest release receives security fixes.

## Threat model in brief

The bridge holds a credential that can send mail as a real mailbox, so it is built to expose that
credential to as little as possible.

- **LAN-only listener.** It is meant for a private network. Never expose its port to the
  internet, and firewall it to the scanner's address as well.
- **Allow-list of client IPs.** Only addresses in `allowed_clients` may send. There is no
  default; the bridge refuses to start without one.
- **SMTP AUTH required over TLS.** Clients must use STARTTLS (TLS 1.2 or later) and then log in
  with the bridge's own username and password; mail is refused otherwise. Five failed logins from
  one address within ten minutes lock that address out for the rest of the window. The scanner
  should verify the bridge's certificate (import your local CA into it); otherwise anyone on the
  LAN who can impersonate the bridge could capture the password.
- **App permission scoped to one mailbox.** The Entra application must **not** be granted
  tenant-wide `Mail.Send`. Exchange RBAC for Applications scopes the "Application Mail.Send" role
  to the single sending mailbox. Optional SharePoint filing uses `Sites.Selected`, granted on one
  site only.
- **Messages are rebuilt.** From is forced to the configured sender, recipients come only from
  the SMTP envelope, and every other header is dropped. Hourly limits cap the cost of misuse.
- **Secrets as files, mode 600.** The settings file holds no secret. The Graph key or client
  secret, the SMTP password and the TLS key are read from files that must be owned by the service
  user and readable by nobody else; the bridge refuses to start otherwise.
- **Logs** record peers, sizes, recipient counts and outcomes, never subjects or bodies.

### Residual risk

Anyone on the LAN who learns the SMTP password and can take over the scanner's IP address can send
mail as the configured mailbox, within the hourly limits. Keep the password only in the scanner
and the bridge, reserve the scanner's address, and consider a separate VLAN or switch-port
security for the scanner.
