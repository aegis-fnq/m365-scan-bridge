# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.2.0](https://github.com/aegis-fnq/m365-scan-bridge/compare/m365-scan-bridge-v0.1.0...m365-scan-bridge-v0.2.0) (2026-11-03)


### Features

* release m365-scan-bridge 0.1.0, an SMTP-to-Microsoft-Graph relay for scanners ([#1](https://github.com/aegis-fnq/m365-scan-bridge/issues/1)) ([1dc8bcf](https://github.com/aegis-fnq/m365-scan-bridge/commit/1dc8bcf049538d4b1810a8dc8038b0a90bd4d5b8))


### Bug Fixes

* **release:** bump the version in uv.lock with each release ([#3](https://github.com/aegis-fnq/m365-scan-bridge/issues/3)) ([59059d4](https://github.com/aegis-fnq/m365-scan-bridge/commit/59059d48570383dcfcca183a625f31313861ec78))

## [0.1.0] - 2026-11-03

### Added

- SMTP listener (STARTTLS, TLS 1.2 or later, SMTP AUTH required) that accepts mail only from
  allow-listed client IP addresses. `allowed_clients` is required; there is no default.
- Delivery through Microsoft Graph `sendMail` as one configured mailbox, with every message
  rebuilt: sender forced, recipients taken from the SMTP envelope, all other headers dropped.
- Optional filing of attachments in a SharePoint document library when mail is sent to a
  configured trigger address.
- App-only authentication with a certificate or a client secret, read from files that must be
  mode 600 and owned by the service user.
- Hourly message and recipient limits, a per-message recipient limit, lock-out after repeated
  failed logins, and an alert email after repeated delivery failures.
- systemd unit, local CA and certificate-renewal scripts, and a weekly renewal timer. The
  install keeps the code and the scripts root runs owned by root; the service user owns only its
  virtual environment, Python and uv cache. `make-ca.sh --server-only --ip/--dns` changes the
  certified address.

### Security

- `allowed_clients` entries are stored in canonical form, so any spelling of an address
  (upper case, leading zeros, IPv4-mapped IPv6) matches the connecting printer; IPv6 addresses
  with a zone (`%`) are refused.
- A SharePoint chunked upload refused with a 4xx (other than 408 or 429) fails permanently, and
  a network error on the final chunk, which may have completed the file, is never retried, so a
  scan is not filed twice.
- `make-ca.sh` accepts only a valid IP address for `--ip` and a plain host name for `--dns`.
- CI actions are pinned to full commit SHAs.
