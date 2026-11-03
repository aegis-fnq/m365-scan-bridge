"""What happens to one message from the printer.

Only the printer's address, logged in with the bridge's SMTP password over
STARTTLS, may send. Mail to any address is rebuilt (sender forced, recipients set
to exactly the envelope, every other header dropped) and sent through Graph as
the configured sender. Mail to the SharePoint trigger address has its files
filed in SharePoint instead. Logs carry the peer, sizes, recipient counts and
outcomes, never a subject or body.
"""

import asyncio
import base64
import collections
import email
import email.policy
import email.utils
import hmac
import ipaddress
import logging
import re
import time
from datetime import datetime
from email.message import EmailMessage

from aiosmtpd.smtp import AuthResult

from .config import GRAPH_REQUEST_LIMIT, Config
from .graph import GraphError

log = logging.getLogger(__name__)
SAFE_NAME = re.compile(r"[^A-Za-z0-9._ -]+")
MAX_NAME = 100
KEPT_HEADERS = {
    "subject", "date", "message-id", "mime-version",
    "content-type", "content-transfer-encoding", "content-disposition",
}
LOGIN_FAILURES_ALLOWED = 5
LOGIN_WINDOW = 600.0


def prepare(raw: bytes, recipients: list[str], sender: str) -> bytes:
    """Rebuild the message for Graph.

    From is the sender; To, Cc and Bcc hold exactly `recipients` (kept in To or
    Cc where the printer put them there, otherwise Bcc); every other header is
    dropped; Message-ID and Date exist.
    """
    msg = email.message_from_bytes(raw, policy=email.policy.SMTP)
    to_hdr = {a.lower() for _, a in email.utils.getaddresses(msg.get_all("To", []))}
    cc_hdr = {a.lower() for _, a in email.utils.getaddresses(msg.get_all("Cc", []))}
    for key in set(k.lower() for k in msg.keys()):
        if key not in KEPT_HEADERS:
            del msg[key]
    to = [r for r in recipients if r.lower() in to_hdr]
    placed = {r.lower() for r in to}
    cc = [r for r in recipients if r.lower() in cc_hdr and r.lower() not in placed]
    placed |= {r.lower() for r in cc}
    bcc = [r for r in recipients if r.lower() not in placed]
    msg["From"] = sender
    if to:
        msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)
    if bcc:
        msg["Bcc"] = ", ".join(bcc)
    if not msg["Message-ID"]:
        msg["Message-ID"] = email.utils.make_msgid(domain=sender.split("@")[-1])
    if not msg["Date"]:
        msg["Date"] = email.utils.formatdate(localtime=True)
    return msg.as_bytes()


def safe_name(name: str | None, n: int) -> str:
    cleaned = SAFE_NAME.sub("_", name or "").strip(" ._")
    if not cleaned:
        cleaned = f"scan-{n}.pdf"
    if len(cleaned) > MAX_NAME:
        stem, dot, ext = cleaned.rpartition(".")
        cleaned = (stem[: MAX_NAME - len(ext) - 1] + "." + ext) if dot and len(ext) <= 10 else cleaned[:MAX_NAME]
    return cleaned


def unique(name: str, taken: set[str]) -> str:
    """name, or name with -2, -3 ... before its extension, unused in `taken` (case-blind)."""
    stem, dot, ext = name.rpartition(".")
    if not dot:
        stem, ext = name, ""
    candidate, n = name, 1
    while candidate.lower() in taken:
        n += 1
        candidate = f"{stem}-{n}{dot}{ext}"
    taken.add(candidate.lower())
    return candidate


def peer_ip(session) -> str:
    """The client's address, with an IPv4 address seen through an IPv6 socket unwrapped."""
    if not session.peer:
        return ""
    try:
        ip = ipaddress.ip_address(session.peer[0])
    except ValueError:
        return str(session.peer[0])
    mapped = getattr(ip, "ipv4_mapped", None)
    return str(mapped or ip)


def attachments(raw: bytes) -> list[tuple[str, bytes]]:
    """Every file in the message: attachments, named inline parts, or a
    single-part message whose body is itself a file. Empty parts are skipped.
    Two files with the same name get distinct names, so neither overwrites or
    blocks the other."""
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    stamp = datetime.now().strftime("%Y-%m-%d %H%M%S")
    found = []
    taken: set[str] = set()
    parts = [msg] if not msg.is_multipart() else list(msg.walk())
    for part in parts:
        if part.is_multipart():
            continue
        disposition = part.get_content_disposition()
        is_file = (
            disposition == "attachment"
            or part.get_filename()
            or (part is msg and part.get_content_maintype() not in ("text",))
        )
        if not is_file:
            continue
        content = part.get_payload(decode=True) or b""
        if not content:
            continue
        found.append((unique(f"{stamp} {safe_name(part.get_filename(), len(found) + 1)}", taken), content))
    return found


def alert_message(sender: str, to: str, text: str) -> bytes:
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to
    msg["Subject"] = "Scan bridge: deliveries failing"
    msg["Date"] = email.utils.formatdate(localtime=True)
    msg["Message-ID"] = email.utils.make_msgid(domain=sender.split("@")[-1])
    msg.set_content(text)
    return msg.as_bytes()


class Limiter:
    """Messages and recipients per rolling hour."""

    def __init__(self, messages: int, recipients: int, clock=time.monotonic):
        self.messages, self.recipients, self.clock = messages, recipients, clock
        self.window = collections.deque()

    def allow(self, n_recipients: int):
        """Reserve room for one message; returns a ticket, or None when over a limit."""
        now = self.clock()
        while self.window and now - self.window[0][0] > 3600:
            self.window.popleft()
        if len(self.window) + 1 > self.messages:
            return None
        if sum(n for _, n in self.window) + n_recipients > self.recipients:
            return None
        ticket = (now, n_recipients)
        self.window.append(ticket)
        return ticket

    def release(self, ticket) -> None:
        """Give back a reservation for a message that will be retried."""
        try:
            self.window.remove(ticket)
        except ValueError:
            pass


def _bytes(value) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode()
    return b""


class Authenticator:
    """aiosmtpd authenticator: one username and password, compared in constant time,
    tried only from an allowed address, with repeated failures from one address
    locked out for a while."""

    def __init__(self, config: Config, clock=time.monotonic):
        self.username = config.smtp_username.encode()
        self.password = config.smtp_password.encode()
        self.allowed = set(config.allowed_clients)
        self.clock = clock
        self.failures: dict[str, collections.deque] = {}

    def _locked(self, peer: str, now: float) -> bool:
        recent = self.failures.get(peer)
        if recent is None:
            return False
        while recent and now - recent[0] > LOGIN_WINDOW:
            recent.popleft()
        if not recent:
            del self.failures[peer]  # keep the table from growing for ever
            return False
        return len(recent) >= LOGIN_FAILURES_ALLOWED

    def __call__(self, server, session, envelope, mechanism, auth_data):
        # handled=False on every refusal makes aiosmtpd send the 535 itself;
        # True would leave the client waiting for an answer that never comes.
        if mechanism not in ("LOGIN", "PLAIN"):
            return AuthResult(success=False, handled=False)
        peer = peer_ip(session) or "?"
        if peer not in self.allowed:
            # No password guessing from anywhere but the printer, whatever the firewall does.
            log.warning("SMTP login from %s refused: not an allowed address", peer)
            return AuthResult(success=False, handled=False)
        now = self.clock()
        if self._locked(peer, now):
            log.warning("SMTP login from %s refused: too many recent failures", peer)
            return AuthResult(success=False, handled=False)
        login = _bytes(getattr(auth_data, "login", None))
        password = _bytes(getattr(auth_data, "password", None))
        ok = hmac.compare_digest(login, self.username) & hmac.compare_digest(password, self.password)
        if not ok:
            self.failures.setdefault(peer, collections.deque()).append(now)
            log.warning("failed SMTP login from %s", peer)
            return AuthResult(success=False, handled=False)
        return AuthResult(success=True)


class Handler:
    """aiosmtpd handler. Rejects anyone but the logged-in printer, then delivers."""

    def __init__(self, config: Config, graph, limiter: Limiter | None = None):
        self.config = config
        self.graph = graph
        self.limiter = limiter or Limiter(config.max_messages_per_hour, config.max_recipients_per_hour)
        self.failures = 0
        self.last_alert = 0.0

    def _allowed(self, session) -> bool:
        return peer_ip(session) in self.config.allowed_clients and bool(
            getattr(session, "authenticated", False)
        )

    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        if not self._allowed(session):
            log.warning("refused MAIL from %s: not the logged-in printer", session.peer)
            return "550 5.7.1 Not allowed to relay"
        envelope.mail_from = address
        envelope.mail_options.extend(mail_options)
        return "250 OK"

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        if not self._allowed(session):
            return "550 5.7.1 Not allowed to relay"
        if any(r.lower() == address.lower() for r in envelope.rcpt_tos):
            return "250 OK"  # already a recipient; send once
        if len(envelope.rcpt_tos) >= self.config.max_recipients_per_message:
            return "452 4.5.3 Too many recipients"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def _call(self, fn, *args):
        return await asyncio.get_running_loop().run_in_executor(None, fn, *args)

    async def handle_DATA(self, server, session, envelope):
        if not self._allowed(session):
            return "550 5.7.1 Not allowed to relay"
        try:
            result = await self._deliver(session, envelope)
        except Exception as exc:
            # The type only: an exception's text can quote the message's own headers.
            log.error("unexpected %s delivering a message from %s", type(exc).__name__, peer_ip(session))
            result = "451 4.3.0 Temporary delivery failure"
        await self._note(result)
        return result

    async def _deliver(self, session, envelope):
        raw = envelope.original_content or envelope.content
        size = len(raw)
        sp = self.config.sharepoint
        trigger = sp.trigger_address if sp else None
        to_sharepoint = any(r.lower() == trigger for r in envelope.rcpt_tos)
        to_mail = [r for r in envelope.rcpt_tos if r.lower() != trigger]

        prepared = None
        if to_mail:
            prepared = prepare(raw, to_mail, self.config.sender)
            if len(base64.b64encode(prepared)) > GRAPH_REQUEST_LIMIT:
                log.warning("refused %d-byte message for mail: over the Graph limit", size)
                return "552 5.3.4 Message too big for email; lower the scan size or split it"
        files = []
        if to_sharepoint:
            files = attachments(raw)
            if not files:
                log.warning("SharePoint message from %s had no file (%d bytes)", session.peer[0], size)
                return "554 5.6.0 No file to file"
            if any(len(c) > self.config.sharepoint_max_bytes for _, c in files):
                return "552 5.3.4 File too big for SharePoint"

        ticket = self.limiter.allow(len(to_mail) + int(to_sharepoint))
        if ticket is None:
            log.warning("refused message from %s: hourly limit reached", session.peer[0])
            return "452 4.7.0 Hourly sending limit reached; try later"

        filed = 0
        try:
            for name, content in files:
                await self._call(self.graph.upload, name, content)
                filed += 1
            if files:
                log.info("filed %d file(s) in SharePoint from %s (%d bytes)", filed, session.peer[0], size)
            if prepared is not None:
                await self._call(self.graph.send_mime, prepared)
                log.info("sent %d-byte message from %s to %d recipient(s)", size, session.peer[0], len(to_mail))
        except GraphError as exc:
            log.error("delivery failed after filing %d of %d file(s): %s", filed, len(files), exc)
            # Once anything is filed, or sendMail may have gone out, a retry would duplicate it.
            if filed == 0 and exc.retryable:
                self.limiter.release(ticket)  # nothing went out; the retry should not count twice
                return "451 4.3.0 Temporary delivery failure"
            return "554 5.3.0 Delivery failed; not retried to avoid duplicates"
        return "250 Message accepted"

    async def _note(self, result: str) -> None:
        """Count delivery failures in a row; alert by email (at most hourly) past the threshold."""
        if result.startswith("250"):
            self.failures = 0
            return
        # 452 counts too: the hourly limit held for long is a sign of trouble worth hearing about.
        if not (result.startswith(("451", "452")) or result.startswith("554 5.3.0")):
            return
        self.failures += 1
        cfg = self.config
        now = time.monotonic()
        if cfg.alert_address and self.failures >= cfg.alert_after_failures and (
            not self.last_alert or now - self.last_alert > 3600
        ):
            text = (f"The scanner bridge has failed {self.failures} deliveries in a row. "
                    f"Last result: {result}. Check: journalctl -u m365-scan-bridge")
            try:
                await self._call(self.graph.send_mime, alert_message(cfg.sender, cfg.alert_address, text))
            except Exception:
                # The alert shares the failing path, so it may fail too; try again next failure.
                log.exception("could not send the failure alert")
                return
            self.last_alert = now
