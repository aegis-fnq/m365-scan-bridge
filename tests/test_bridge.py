import asyncio
import email
import email.policy
import io
import json
import os
import urllib.error
from email.message import EmailMessage
from types import SimpleNamespace

import pytest

from m365_scan_bridge import __main__ as main_mod
from m365_scan_bridge import config as cfgmod
from m365_scan_bridge.config import Config, ConfigError, SharePoint
from m365_scan_bridge.graph import CHUNK, Graph, GraphError, retry_after
from m365_scan_bridge.handler import Authenticator, Handler, Limiter, attachments, prepare, safe_name

SENDER = "scanner@example.com"
PRINTER = ("192.0.2.10", 40000)


def scan(to="someone@example.com", cc=None, with_id=False, size=10, extra_headers=None):
    msg = EmailMessage()
    msg["From"] = "printer@local"
    msg["To"] = to
    if cc:
        msg["Cc"] = cc
    msg["Subject"] = "Scan"
    for k, v in (extra_headers or {}).items():
        msg[k] = v
    if with_id:
        msg["Message-ID"] = "<keep@printer>"
    msg.set_content("scan attached")
    msg.add_attachment(b"%PDF" + b"x" * size, maintype="application", subtype="pdf", filename="scan 1.pdf")
    return msg.as_bytes()


class FakeGraph:
    def __init__(self, send_fail=None, upload_fail_at=None, upload_error=None):
        self.sent, self.uploads = [], []
        self.send_fail, self.upload_fail_at, self.upload_error = send_fail, upload_fail_at, upload_error

    def send_mime(self, mime):
        if self.send_fail:
            raise self.send_fail
        self.sent.append(mime)

    def upload(self, name, content):
        if self.upload_fail_at is not None and len(self.uploads) == self.upload_fail_at:
            raise self.upload_error
        self.uploads.append((name, content))
        return "https://sp/x"


def config(**kw):
    base = dict(tenant_id="t", client_id="c", sender=SENDER, smtp_username="printer", smtp_password="pw",
                allowed_clients=(PRINTER[0],))
    base.update(kw)
    return Config(**base)


SP = SharePoint(trigger_address="scans@sharepoint.local", drive_id="d", folder="Scans")


def run(handler, raw, rcpts, peer=PRINTER, authenticated=True):
    session = SimpleNamespace(peer=peer, authenticated=authenticated)
    env = SimpleNamespace(mail_from=None, mail_options=[], rcpt_tos=[], original_content=raw, content=raw)

    async def go():
        r = await handler.handle_MAIL(None, session, env, "printer@local", [])
        if not r.startswith("250"):
            return r
        for rc in rcpts:
            r = await handler.handle_RCPT(None, session, env, rc, [])
            if not r.startswith("250"):
                return r
        return await handler.handle_DATA(None, session, env)

    return asyncio.run(go())


def parsed(mime):
    return email.message_from_bytes(mime, policy=email.policy.default)


# --- message preparation ---

def test_prepare_sets_recipients_to_exactly_the_envelope():
    raw = scan(to="a@example.com, notsent@example.com", cc="c@example.com")
    out = parsed(prepare(raw, ["a@example.com", "c@example.com", "hidden@example.com"], SENDER))
    assert out["From"] == SENDER
    assert out["To"] == "a@example.com"
    assert out["Cc"] == "c@example.com"
    assert out["Bcc"] == "hidden@example.com"
    assert "notsent" not in prepare(raw, ["a@example.com"], SENDER).decode()


def test_prepare_drops_every_other_header_and_adds_message_id():
    raw = scan(extra_headers={"Reply-To": "evil@example.com", "X-Thing": "1", "Sender": "x@y"})
    out = parsed(prepare(raw, ["someone@example.com"], SENDER))
    assert out["Reply-To"] is None and out["X-Thing"] is None and out["Sender"] is None
    assert out["Message-ID"] and out["Date"] and out["Subject"] == "Scan"


def test_prepare_keeps_existing_message_id():
    assert parsed(prepare(scan(with_id=True), ["someone@example.com"], SENDER))["Message-ID"] == "<keep@printer>"


def test_trigger_address_is_never_a_mail_recipient():
    g = FakeGraph()
    raw = scan(to="someone@example.com, scans@sharepoint.local")
    assert run(Handler(config(sharepoint=SP), g), raw, ["someone@example.com", "scans@sharepoint.local"]).startswith("250")
    assert "scans@sharepoint.local" not in g.sent[0].decode()
    assert len(g.uploads) == 1


# --- access control ---

def test_unknown_address_is_refused():
    g = FakeGraph()
    assert run(Handler(config(), g), scan(), ["a@example.com"], peer=("10.0.0.9", 1)).startswith("550")
    assert g.sent == []


def test_printer_address_without_login_is_refused():
    g = FakeGraph()
    assert run(Handler(config(), g), scan(), ["a@example.com"], authenticated=False).startswith("550")


def test_authenticator_checks_username_and_password():
    auth = Authenticator(config())
    session = SimpleNamespace(peer=PRINTER)
    good = auth(None, session, None, "LOGIN", SimpleNamespace(login=b"printer", password=b"pw"))
    bad = auth(None, session, None, "PLAIN", SimpleNamespace(login=b"printer", password=b"nope"))
    assert good.success and not bad.success
    # handled must be False on failure, or aiosmtpd never answers and the printer hangs
    # (found by a live STARTTLS + AUTH run on 02/11/2026).
    assert bad.handled is False


def test_hourly_limits():
    t = [0.0]
    lim = Limiter(messages=2, recipients=3, clock=lambda: t[0])
    assert lim.allow(1) and lim.allow(2)
    assert not lim.allow(1)          # third message in the hour
    t[0] = 3601
    assert lim.allow(3) and not Limiter(5, 3).allow(4)


def test_per_message_recipient_cap():
    g = FakeGraph()
    r = run(Handler(config(max_recipients_per_message=2), g), scan(), ["a@x.com", "b@x.com", "c@x.com"])
    assert r.startswith("452") and g.sent == []


def test_hourly_limit_refuses_delivery():
    g = FakeGraph()
    h = Handler(config(max_messages_per_hour=1), g)
    assert run(h, scan(), ["a@example.com"]).startswith("250")
    assert run(h, scan(), ["a@example.com"]).startswith("452")
    assert len(g.sent) == 1


# --- delivery and failures ---

def test_mail_is_sent_through_graph():
    g = FakeGraph()
    assert run(Handler(config(), g), scan(), ["someone@example.com"]).startswith("250")
    assert len(g.sent) == 1


def test_oversize_mail_is_refused_on_encoded_size():
    g = FakeGraph()
    assert run(Handler(config(), g), scan(size=3_200_000), ["someone@example.com"]).startswith("552")
    assert g.sent == []


def test_sharepoint_size_limit_checked_before_any_upload():
    g = FakeGraph()
    r = run(Handler(config(sharepoint=SP, sharepoint_max_bytes=5), g), scan(to="scans@sharepoint.local"),
            ["scans@sharepoint.local"])
    assert r.startswith("552") and g.uploads == []


def test_failure_after_a_file_is_filed_is_permanent():
    two = EmailMessage()
    two["To"] = "scans@sharepoint.local"
    two.set_content("x")
    two.add_attachment(b"1", maintype="application", subtype="pdf", filename="a.pdf")
    two.add_attachment(b"2", maintype="application", subtype="pdf", filename="b.pdf")
    g = FakeGraph(upload_fail_at=1, upload_error=GraphError(503, "busy", retryable=True))
    r = run(Handler(config(sharepoint=SP), g), two.as_bytes(), ["scans@sharepoint.local"])
    assert r.startswith("554") and len(g.uploads) == 1


def test_retryable_error_before_anything_is_done_is_temporary():
    r = run(Handler(config(), FakeGraph(send_fail=GraphError(429, "x", retryable=True))), scan(), ["a@example.com"])
    assert r.startswith("451")


def test_unsafe_send_failure_is_permanent():
    r = run(Handler(config(), FakeGraph(send_fail=GraphError(0, "timeout", retryable=False))), scan(), ["a@example.com"])
    assert r.startswith("554")


def test_unexpected_exception_is_temporary_and_logged(caplog):
    r = run(Handler(config(), FakeGraph(send_fail=RuntimeError("boom"))), scan(), ["a@example.com"])
    assert r.startswith("451")
    assert "unexpected RuntimeError" in caplog.text
    assert "boom" not in caplog.text  # an exception's text can quote the message; never logged


def test_repeated_failures_send_one_alert():
    g = FakeGraph(send_fail=GraphError(503, "x", retryable=True))
    h = Handler(config(alert_address="admin@example.com", alert_after_failures=2), g)
    alerts = []
    g.send_mime = lambda mime: alerts.append(mime) if b"deliveries failing" in mime else (_ for _ in ()).throw(GraphError(503, "x", retryable=True))
    for _ in range(4):
        run(h, scan(), ["a@example.com"])
    assert len(alerts) == 1


# --- files ---

def test_attachment_names_are_made_safe():
    for bad in ("../../etc/passwd", "..\\..\\win.ini", "a/b\\c:d*e?.pdf", "", "...", "x" * 300 + ".pdf"):
        name = safe_name(bad, 1)
        assert "/" not in name and "\\" not in name and ":" not in name
        assert not name.startswith(".") and 0 < len(name) <= 100
    assert safe_name("x" * 300 + ".pdf", 1).endswith(".pdf")


def test_single_part_pdf_and_inline_parts_are_files_and_empty_parts_skipped():
    single = EmailMessage()
    single.set_content(b"%PDF-1.4", maintype="application", subtype="pdf")
    assert len(attachments(single.as_bytes())) == 1
    multi = EmailMessage()
    multi.set_content("body")
    multi.add_attachment(b"img", maintype="image", subtype="jpeg", filename="p.jpg", disposition="inline")
    multi.add_attachment(b"", maintype="application", subtype="pdf", filename="empty.pdf")
    files = attachments(multi.as_bytes())
    assert [n.split(" ", 2)[-1] for n, _ in files] == ["p.jpg"]


# --- Graph client ---

class FakeResp(io.BytesIO):
    status = 202

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeApp:
    def __init__(self, result=None, raises=None):
        self.result, self.raises = result or {"access_token": "tok"}, raises

    def acquire_token_for_client(self, scopes):
        if self.raises:
            raise self.raises
        return self.result


def http_error(req, code, retry_after_value=None):
    hdrs = {"Retry-After": retry_after_value} if retry_after_value else {}
    return urllib.error.HTTPError(req.full_url, code, "x", hdrs, io.BytesIO(b"detail"))


def test_sendmail_retries_429_only():
    calls, waits = [], []

    def opener(req, timeout):
        calls.append(req)
        if len(calls) == 1:
            raise http_error(req, 429, "1")
        return FakeResp(b"")

    Graph(config(), app=FakeApp(), opener=opener, sleep=waits.append).send_mime(b"MIME")
    assert len(calls) == 2 and waits == [1.0]
    assert calls[1].full_url.endswith("/users/scanner%40example.com/sendMail")
    assert calls[1].headers["Authorization"] == "Bearer tok"


def test_sendmail_is_never_repeated_after_a_5xx_or_timeout():
    for exc in (lambda req: http_error(req, 503), lambda req: TimeoutError("slow")):
        calls = []

        def opener(req, timeout, exc=exc):
            calls.append(req)
            raise exc(req)

        with pytest.raises(GraphError) as e:
            Graph(config(), app=FakeApp(), opener=opener, sleep=lambda s: None).send_mime(b"M")
        assert len(calls) == 1 and not e.value.retryable


def test_idempotent_calls_retry_network_errors_then_give_up():
    calls = []

    def opener(req, timeout):
        calls.append(req)
        raise ConnectionResetError("reset")

    sp_cfg = config(sharepoint=SP)
    with pytest.raises(GraphError) as e:
        Graph(sp_cfg, app=FakeApp(), opener=opener, sleep=lambda s: None, attempts=3).upload("a.pdf", b"x")
    assert len(calls) == 3 and e.value.status == 0


def test_token_failures_retry_only_when_they_can_recover():
    with pytest.raises(GraphError) as e:
        Graph(config(), app=FakeApp(raises=OSError("dns")), opener=None).token()
    assert e.value.retryable
    with pytest.raises(GraphError) as e:
        Graph(config(), app=FakeApp(result={"error": "temporarily_unavailable"})).token()
    assert e.value.retryable and e.value.status == 401
    with pytest.raises(GraphError) as e:  # a wrong secret will not fix itself
        Graph(config(), app=FakeApp(result={"error": "invalid_client"})).token()
    assert not e.value.retryable and e.value.status == 401


def test_retry_after_parsing_and_cap():
    assert retry_after("5", 2) == 5
    assert retry_after("100000", 2) == 60
    assert retry_after("Wed, 21 Oct 2015 07:28:00 GMT", 2) == 0
    assert retry_after("nonsense", 2) == 2
    assert retry_after(None, 128) == 60


def test_upload_session_ranges_and_no_token_to_upload_url():
    seen = []
    size = CHUNK * 3 + 10  # over the 4 MiB simple-upload limit

    def opener(req, timeout):
        seen.append(req)
        if req.full_url.endswith("createUploadSession"):
            return FakeResp(json.dumps({"uploadUrl": "https://upload.example/u"}).encode())
        return FakeResp(json.dumps({"webUrl": "https://sp/f"}).encode())

    url = Graph(config(sharepoint=SP), app=FakeApp(), opener=opener).upload("big.pdf", b"x" * size)
    assert url == "https://sp/f"
    puts = [r for r in seen if r.full_url == "https://upload.example/u"]
    assert [r.headers["Content-range"] for r in puts] == [
        f"bytes 0-{CHUNK - 1}/{size}", f"bytes {CHUNK}-{2 * CHUNK - 1}/{size}",
        f"bytes {2 * CHUNK}-{3 * CHUNK - 1}/{size}", f"bytes {3 * CHUNK}-{size - 1}/{size}",
    ]
    assert all("Authorization" not in r.headers for r in puts)


def test_upload_session_conflict_is_an_error_not_filed():
    calls = []

    def opener(req, timeout):
        calls.append(req)
        if len(calls) == 1:
            raise urllib.error.HTTPError(req.full_url, 503, "busy", {}, io.BytesIO(b""))
        raise urllib.error.HTTPError(req.full_url, 409, "exists", {}, io.BytesIO(b""))

    g = Graph(config(sharepoint=SP), app=FakeApp(), opener=opener, sleep=lambda s: None)
    with pytest.raises(GraphError) as e:
        g.upload("big.pdf", b"x" * (5 * 1024 * 1024))
    assert e.value.status == 409


def test_upload_chunk_is_not_resent_after_it_may_have_arrived():
    puts = []

    def opener(req, timeout):
        if req.full_url.endswith("createUploadSession"):
            return FakeResp(json.dumps({"uploadUrl": "https://upload.example/u"}).encode())
        puts.append(req)
        raise urllib.error.HTTPError(req.full_url, 503, "busy", {}, io.BytesIO(b""))

    g = Graph(config(sharepoint=SP), app=FakeApp(), opener=opener, sleep=lambda s: None)
    with pytest.raises(GraphError) as e:
        g.upload("big.pdf", b"x" * (5 * 1024 * 1024))
    assert len(puts) == 1 and e.value.retryable  # the printer re-sends the whole scan


def chunked_upload(fail_on_put, exc_for):
    """Upload four chunks; every PUT from number fail_on_put (1-based) on raises exc_for(req)."""
    puts = []

    def opener(req, timeout):
        if req.full_url.endswith("createUploadSession"):
            return FakeResp(json.dumps({"uploadUrl": "https://upload.example/u"}).encode())
        puts.append(req)
        if len(puts) >= fail_on_put:
            raise exc_for(req)
        return FakeResp(b"{}")

    g = Graph(config(sharepoint=SP), app=FakeApp(), opener=opener, sleep=lambda s: None)
    with pytest.raises(GraphError) as e:
        g.upload("big.pdf", b"x" * (CHUNK * 3 + 10))
    return e.value, puts


@pytest.mark.parametrize("code", [400, 403, 404, 413, 416])
def test_upload_chunk_refusal_is_permanent(code):
    err, puts = chunked_upload(1, lambda req: http_error(req, code))
    assert len(puts) == 1 and err.status == code and not err.retryable


@pytest.mark.parametrize("code", [408, 429, 503])
def test_upload_chunk_temporary_status_is_retryable(code):
    err, _ = chunked_upload(2, lambda req: http_error(req, code))
    assert err.status == code and err.retryable


def test_upload_network_error_on_earlier_chunk_is_retryable():
    err, puts = chunked_upload(2, lambda req: TimeoutError("slow"))
    assert len(puts) == 2 and err.status == 0 and err.retryable


def test_upload_network_error_on_final_chunk_is_permanent():
    # The final chunk may have completed the file; a re-sent scan could file it twice.
    err, puts = chunked_upload(4, lambda req: TimeoutError("slow"))
    assert len(puts) == 4 and err.status == 0 and not err.retryable


def test_upload_permanent_chunk_failure_is_554_and_counts_toward_alert():
    msg = EmailMessage()
    msg["To"] = SP.trigger_address
    msg.set_content("x")
    msg.add_attachment(b"1", maintype="application", subtype="pdf", filename="a.pdf")
    h = Handler(config(sharepoint=SP), FakeGraph(upload_fail_at=0, upload_error=GraphError(403, "no", retryable=False)))
    r = run(h, msg.as_bytes(), [SP.trigger_address])
    assert r.startswith("554 5.3.0") and h.failures == 1


def test_upload_session_without_url_is_an_error():
    def opener(req, timeout):
        return FakeResp(b"not json")

    with pytest.raises(GraphError):
        Graph(config(sharepoint=SP), app=FakeApp(), opener=opener).upload("big.pdf", b"x" * (5 * 1024 * 1024))


# --- settings ---

def write_settings(tmp_path, extra="", smtp=True, clients='allowed_clients = ["192.0.2.10"]'):
    secret = tmp_path / "secret"
    secret.write_text("s")
    pw = tmp_path / "pw"
    pw.write_text("pw")
    cert = tmp_path / "cert.pem"
    cert.write_text("c")
    key = tmp_path / "key.pem"
    key.write_text("k")
    if os.name == "posix":
        for f in (secret, pw, key):
            f.chmod(0o600)
    smtp_block = (f'[smtp]\nusername="printer"\npassword_file="{pw.as_posix()}"\n'
                  f'tls_cert_file="{cert.as_posix()}"\ntls_key_file="{key.as_posix()}"\n') if smtp else ""
    p = tmp_path / "c.toml"
    p.write_text(
        f'tenant_id="t"\nclient_id="c"\nsender="{SENDER}"\n{"" if "allowed_clients" in extra else clients}\n{extra}\n'
        f'[credential]\nsecret_file="{secret.as_posix()}"\n{smtp_block}',
        encoding="utf-8",
    )
    return p


def test_config_loads(tmp_path):
    c = cfgmod.load(write_settings(tmp_path))
    assert c.smtp_password == "pw" and c.allowed_clients == ("192.0.2.10",)


@pytest.mark.parametrize("extra", [
    'listen_port = 70000', 'listen_port = "25"', 'allowed_clients = "192.0.2.10"',
    'allowed_clients = ["printer"]', 'log_level = "LOUD"', 'max_messages_per_hour = 0', 'sharepoint = 5',
])
def test_config_rejects_bad_values(tmp_path, extra):
    with pytest.raises(ConfigError):
        cfgmod.load(write_settings(tmp_path, extra))


@pytest.mark.parametrize("clients", ["", "allowed_clients = []"])
def test_config_requires_allowed_clients(tmp_path, clients):
    with pytest.raises(ConfigError, match="allowed_clients"):
        cfgmod.load(write_settings(tmp_path, clients=clients))


@pytest.mark.parametrize("written, peer", [
    ("2001:DB8::0001", "2001:db8::1"),
    ("::ffff:192.0.2.10", "192.0.2.10"),
])
def test_allowed_clients_are_stored_canonically(tmp_path, written, peer):
    c = cfgmod.load(write_settings(tmp_path, clients=f'allowed_clients = ["{written}"]'))
    assert c.allowed_clients == (peer,)
    assert run(Handler(c, FakeGraph()), scan(), ["a@example.com"], peer=(peer, 25)).startswith("250")


def test_allowed_clients_rejects_scoped_ipv6(tmp_path):
    with pytest.raises(ConfigError, match="zone"):
        cfgmod.load(write_settings(tmp_path, clients='allowed_clients = ["fe80::1%eth0"]'))


def test_config_requires_smtp_block(tmp_path):
    with pytest.raises(ConfigError):
        cfgmod.load(write_settings(tmp_path, smtp=False))


@pytest.mark.skipif(os.name != "posix", reason="file modes are POSIX")
def test_config_refuses_world_readable_secret(tmp_path):
    p = write_settings(tmp_path)
    (tmp_path / "secret").chmod(0o644)
    with pytest.raises(ConfigError):
        cfgmod.load(p)


def test_check_reports_graph_failure_cleanly(tmp_path, capsys, monkeypatch):
    p = write_settings(tmp_path)

    class BadGraph:
        def __init__(self, cfg):
            pass

        def token(self):
            raise GraphError(401, "invalid_client")

    monkeypatch.setattr(main_mod, "tls_context", lambda cfg: None)
    assert main_mod.main([str(p), "--check"], graph_factory=BadGraph) == 1
    assert "invalid_client" in capsys.readouterr().err


def test_check_succeeds(tmp_path, capsys, monkeypatch):
    p = write_settings(tmp_path)

    class GoodGraph:
        def __init__(self, cfg):
            pass

        def token(self):
            return "tok"

    monkeypatch.setattr(main_mod, "tls_context", lambda cfg: None)
    assert main_mod.main([str(p), "--check"], graph_factory=GoodGraph) == 0


def test_bad_settings_exit_2(tmp_path, capsys):
    assert main_mod.main([str(tmp_path / "missing.toml"), "--check"]) == 2


# --- second review round ---

def test_empty_smtp_password_file_is_refused(tmp_path):
    p = write_settings(tmp_path)
    (tmp_path / "pw").write_text("  \n")
    with pytest.raises(ConfigError, match="empty"):
        cfgmod.load(p)


@pytest.mark.parametrize("extra", [
    'max_message_bytes = 1000',                                   # retired key
    'max_recipients_per_message = 300\nmax_recipients_per_hour = 100',
])
def test_config_rejects_unknown_keys_and_inconsistent_caps(tmp_path, extra):
    with pytest.raises(ConfigError):
        cfgmod.load(write_settings(tmp_path, extra))


@pytest.mark.parametrize("folder", ['"/"', '" / "', '""'])
def test_sharepoint_root_folder_refused(tmp_path, folder):
    p = write_settings(tmp_path)
    p.write_text(p.read_text() + f'[sharepoint]\ntrigger_address="s@x"\ndrive_id="d"\nfolder={folder}\n')
    with pytest.raises(ConfigError):
        cfgmod.load(p)


def test_credential_values_must_be_strings(tmp_path):
    p = write_settings(tmp_path)
    p.write_text(p.read_text().replace(f'secret_file="{(tmp_path / "secret").as_posix()}"', "secret_file=5"))
    with pytest.raises(ConfigError):
        cfgmod.load(p)


def test_single_part_scan_keeps_its_filename():
    single = EmailMessage()
    single["To"] = "a@example.com"
    single.set_content(b"%PDF-1.4", maintype="application", subtype="pdf", filename="Scan_001.pdf")
    out = parsed(prepare(single.as_bytes(), ["a@example.com"], SENDER))
    assert out.get_filename() == "Scan_001.pdf"


def test_duplicate_recipients_are_sent_once():
    g = FakeGraph()
    assert run(Handler(config(), g), scan(to="a@example.com"), ["A@example.com", "a@EXAMPLE.com"]).startswith("250")
    assert g.sent[0].decode().lower().count("a@example.com") == 1


def test_limiter_not_consumed_by_refused_or_retried_messages():
    h = Handler(config(max_messages_per_hour=1), FakeGraph(send_fail=GraphError(429, "x", retryable=True)))
    assert run(h, scan(size=3_200_000), ["a@example.com"]).startswith("552")   # too big: not counted
    assert run(h, scan(), ["a@example.com"]).startswith("451")                 # retryable: released
    h.graph = FakeGraph()
    assert run(h, scan(), ["a@example.com"]).startswith("250")


def test_sendmail_retried_when_connection_never_opened():
    import socket
    calls = []

    def opener(req, timeout):
        calls.append(req)
        if len(calls) == 1:
            raise urllib.error.URLError(socket.gaierror("no dns"))
        return FakeResp(b"")

    Graph(config(), app=FakeApp(), opener=opener, sleep=lambda s: None).send_mime(b"M")
    assert len(calls) == 2


def test_sendmail_refused_connection_is_retryable_when_out_of_attempts():
    def opener(req, timeout):
        raise urllib.error.URLError(ConnectionRefusedError())

    with pytest.raises(GraphError) as e:
        Graph(config(), app=FakeApp(), opener=opener, sleep=lambda s: None, attempts=2).send_mime(b"M")
    assert e.value.retryable


def test_simple_upload_conflict_after_retry_means_already_filed():
    calls = []

    def opener(req, timeout):
        calls.append(req)
        if len(calls) == 1:
            raise http_error(req, 503)
        raise http_error(req, 409)

    Graph(config(sharepoint=SP), app=FakeApp(), opener=opener, sleep=lambda s: None).upload("a.pdf", b"x")
    assert len(calls) == 2 and "conflictBehavior=fail" in calls[0].full_url


def test_simple_upload_conflict_on_first_attempt_is_an_error():
    def opener(req, timeout):
        raise http_error(req, 409)

    with pytest.raises(GraphError):
        Graph(config(sharepoint=SP), app=FakeApp(), opener=opener, sleep=lambda s: None).upload("a.pdf", b"x")


def test_transient_token_failure_is_retried_inside_the_call():
    class FlakyApp:
        n = 0

        def acquire_token_for_client(self, scopes):
            self.n += 1
            if self.n == 1:
                raise OSError("dns")
            return {"access_token": "tok"}

    def opener(req, timeout):
        return FakeResp(b"")

    Graph(config(), app=FlakyApp(), opener=opener, sleep=lambda s: None).send_mime(b"M")


def test_alert_retried_until_it_succeeds():
    attempts = {"alerts": 0}

    class G(FakeGraph):
        def send_mime(self, mime):
            if b"deliveries failing" in mime:
                attempts["alerts"] += 1
                if attempts["alerts"] == 1:
                    raise GraphError(503, "x", retryable=True)
                return
            raise GraphError(503, "x", retryable=True)

    h = Handler(config(alert_address="d@example.com", alert_after_failures=1), G())
    for _ in range(3):
        run(h, scan(), ["a@example.com"])
    assert attempts["alerts"] == 2   # first alert failed, second sent, third suppressed for the hour


def test_smtp_size_limit_allows_encoded_sharepoint_files():
    assert main_mod.smtp_size_limit(config()) == cfgmod.GRAPH_REQUEST_LIMIT
    big = config(sharepoint=SP, sharepoint_max_bytes=30 * 1024 * 1024)
    assert main_mod.smtp_size_limit(big) >= 30 * 1024 * 1024 * 4 // 3


def test_authenticator_refusals():
    auth = Authenticator(config())
    s = SimpleNamespace(peer=PRINTER)
    assert not auth(None, s, None, "LOGIN", SimpleNamespace(login=b"other", password=b"pw")).success
    unsupported = auth(None, s, None, "CRAM-MD5", SimpleNamespace(login=b"printer", password=b"pw"))
    assert not unsupported.success and unsupported.handled is False
    assert not auth(None, s, None, "PLAIN", object()).success                 # malformed auth_data
    assert auth(None, s, None, "PLAIN", SimpleNamespace(login="printer", password="pw")).success


def test_authenticator_refuses_other_addresses_and_unwraps_ipv6_mapped():
    auth = Authenticator(config())
    good = SimpleNamespace(login=b"printer", password=b"pw")
    assert not auth(None, SimpleNamespace(peer=("192.0.2.50", 1)), None, "LOGIN", good).success
    assert auth(None, SimpleNamespace(peer=("::ffff:192.0.2.10", 1, 0, 0)), None, "LOGIN", good).success
    assert auth.failures == {}  # nothing recorded for an address never allowed to try


def test_authenticator_forgets_old_failures():
    t = [0.0]
    auth = Authenticator(config(), clock=lambda: t[0])
    s = SimpleNamespace(peer=PRINTER)
    auth(None, s, None, "LOGIN", SimpleNamespace(login=b"printer", password=b"bad"))
    t[0] = 601
    assert auth(None, s, None, "LOGIN", SimpleNamespace(login=b"printer", password=b"pw")).success
    assert auth.failures == {}


def test_two_files_with_one_name_get_distinct_names():
    msg = EmailMessage()
    msg["To"] = "scans@sharepoint.local"
    msg.set_content("scans")
    for _ in range(3):
        msg.add_attachment(b"%PDF1", maintype="application", subtype="pdf", filename="Scan.pdf")
    names = [n for n, _ in attachments(msg.as_bytes())]
    assert len({n.lower() for n in names}) == 3
    assert names[1].endswith("Scan-2.pdf") and names[2].endswith("Scan-3.pdf")


def test_hourly_limit_counts_toward_the_alert():
    g = FakeGraph()
    alerts = []
    g.send_mime = lambda mime: alerts.append(mime)
    h = Handler(config(alert_address="admin@example.com", alert_after_failures=2, max_messages_per_hour=1), g)
    run(h, scan(), ["a@example.com"])
    for _ in range(2):
        assert run(h, scan(), ["a@example.com"]).startswith("452")
    assert any(b"deliveries failing" in m for m in alerts)


def test_empty_sharepoint_table_is_refused(tmp_path):
    with pytest.raises(ConfigError):
        cfgmod.load(write_settings(tmp_path, extra="[sharepoint]\n"))


def test_authenticator_locks_out_after_repeated_failures():
    t = [0.0]
    auth = Authenticator(config(), clock=lambda: t[0])
    s = SimpleNamespace(peer=PRINTER)
    for _ in range(5):
        auth(None, s, None, "LOGIN", SimpleNamespace(login=b"printer", password=b"bad"))
    good = SimpleNamespace(login=b"printer", password=b"pw")
    assert not auth(None, s, None, "LOGIN", good).success                       # locked
    t[0] = 601
    assert auth(None, s, None, "LOGIN", good).success                           # window passed


def _self_signed(tmp_path):
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + dt.timedelta(days=1)).sign(key, hashes.SHA256()))
    (tmp_path / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "key.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return tmp_path / "cert.pem", tmp_path / "key.pem"


def test_live_smtp_requires_starttls_and_login(tmp_path):
    import smtplib
    import socket
    import ssl

    from aiosmtpd.controller import Controller

    cert, key = _self_signed(tmp_path)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    cfg = config(tls_cert_file=cert, tls_key_file=key, allowed_clients=("127.0.0.1",))
    g = FakeGraph()
    controller = Controller(
        Handler(cfg, g), hostname="127.0.0.1", port=port, tls_context=main_mod.tls_context(cfg),
        require_starttls=True, authenticator=Authenticator(cfg), auth_required=True, auth_require_tls=True,
        data_size_limit=main_mod.smtp_size_limit(cfg),
    )
    controller.start()
    ctx = ssl._create_unverified_context()
    msg = "Subject: t\r\nTo: a@example.com\r\n\r\nbody"
    try:
        with smtplib.SMTP("127.0.0.1", port, timeout=10) as c:
            c.ehlo()
            with pytest.raises(smtplib.SMTPSenderRefused) as e:
                c.sendmail("p@x", ["a@example.com"], msg)       # no STARTTLS
            assert e.value.smtp_code == 530
        with smtplib.SMTP("127.0.0.1", port, timeout=10) as c:
            c.starttls(context=ctx)
            with pytest.raises(smtplib.SMTPAuthenticationError):
                c.login("printer", "wrong")
        with smtplib.SMTP("127.0.0.1", port, timeout=10) as c:
            c.starttls(context=ctx)
            c.login("printer", "pw")
            c.sendmail("p@x", ["a@example.com"], msg)
    finally:
        controller.stop()
    assert len(g.sent) == 1
