"""The two Microsoft Graph calls the bridge makes: send mail, and upload a file.

App-only (client credentials). The app's reach is limited outside this code:
an Exchange role assignment scopes sending to the one mailbox, and
Sites.Selected scopes writing to the one SharePoint site.

`GraphError.retryable` says whether trying the same message again is safe.
sendMail is never repeated once its request may have reached Microsoft, because
a repeat could send the scan twice.
"""

import base64
import email.utils
import http.client
import json
import logging
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

import msal

from .config import Config

GRAPH = "https://graph.microsoft.com/v1.0"
SCOPE = ["https://graph.microsoft.com/.default"]
SIMPLE_UPLOAD_LIMIT = 4 * 1024 * 1024
CHUNK = 5 * 320 * 1024  # a multiple of 320 KiB, as Graph requires
RETRYABLE = {429, 500, 502, 503, 504}
PERMANENT_TOKEN_ERRORS = {"invalid_client", "unauthorized_client", "invalid_grant", "invalid_request"}
MAX_WAIT = 60.0
NETWORK_ERRORS = (urllib.error.URLError, TimeoutError, ConnectionError, http.client.HTTPException)

log = logging.getLogger(__name__)


class GraphError(RuntimeError):
    def __init__(self, status: int, message: str, retryable: bool = False):
        super().__init__(f"Graph returned {status}: {message}")
        self.status = status
        self.retryable = retryable


def retry_after(value: str | None, default: float) -> float:
    """Seconds to wait from a Retry-After header (seconds or HTTP-date), capped."""
    if not value:
        return min(default, MAX_WAIT)
    try:
        wait = float(value)
    except ValueError:
        try:
            when = email.utils.parsedate_to_datetime(value)
            wait = (when - datetime.now(timezone.utc)).total_seconds()
        except (TypeError, ValueError):
            wait = default
    return max(0.0, min(wait, MAX_WAIT))


def never_sent(exc: Exception) -> bool:
    """True when the error proves the connection never opened, so nothing was sent.

    urllib wraps errors from opening the connection in URLError; a name-lookup
    failure, a refused connection and a failed TLS handshake all happen before
    the request body is written.
    """
    reason = getattr(exc, "reason", None)
    return isinstance(exc, urllib.error.URLError) and isinstance(
        reason, (socket.gaierror, ConnectionRefusedError, ssl.SSLError)
    )


def build_credential(config: Config):
    if config.secret_file:
        return config.secret_file.read_text(encoding="utf-8").strip()
    return {
        "private_key": config.certificate_key_file.read_text(encoding="utf-8"),
        "thumbprint": config.certificate_thumbprint,
    }


def _json(data: bytes, what: str) -> dict:
    try:
        value = json.loads(data or b"{}")
    except ValueError:
        raise GraphError(0, f"{what}: response was not JSON") from None
    if not isinstance(value, dict):
        raise GraphError(0, f"{what}: response was not a JSON object")
    return value


class Graph:
    def __init__(self, config: Config, app=None, opener=None, sleep=time.sleep, attempts: int = 4):
        self.config = config
        self.app = app or msal.ConfidentialClientApplication(
            config.client_id,
            authority=f"https://login.microsoftonline.com/{config.tenant_id}",
            client_credential=build_credential(config),
        )
        self.opener = opener or urllib.request.urlopen
        self.sleep = sleep
        self.attempts = attempts

    def token(self) -> str:
        try:
            result = self.app.acquire_token_for_client(scopes=SCOPE)
        except Exception as exc:  # msal raises plain exceptions for network trouble
            raise GraphError(0, f"token request failed: {exc}", retryable=True) from None
        if "access_token" not in result:
            # A wrong or expired credential will not fix itself: fail plainly rather
            # than have the printer retry for ever. Anything else may be an outage.
            permanent = result.get("error") in PERMANENT_TOKEN_ERRORS
            raise GraphError(401, result.get("error_description") or result.get("error") or "no token",
                             retryable=not permanent)
        return result["access_token"]

    def _request(self, method, url, body, content_type, *, auth=True, extra=None, idempotent=True,
                 conflict_means_done=False):
        """Make one Graph call, retrying where that is safe.

        With idempotent False a retry happens only when the failure proves
        Microsoft never received the request: a 429, a token failure, or a
        connection that never opened (name lookup, refused, TLS handshake).
        With conflict_means_done, a 409 on a retry means an earlier attempt
        already stored the file.
        """
        for attempt in range(1, self.attempts + 1):
            last = attempt == self.attempts
            headers = {"Content-Type": content_type}
            try:
                if auth:
                    headers["Authorization"] = f"Bearer {self.token()}"
            except GraphError as exc:
                if exc.retryable and not last:
                    self.sleep(min(2.0**attempt, MAX_WAIT))
                    continue
                raise
            headers.update(extra or {})
            req = urllib.request.Request(url, data=body, method=method, headers=headers)
            try:
                with self.opener(req, timeout=120) as resp:
                    return resp.status, resp.read()
            except urllib.error.HTTPError as exc:
                detail = exc.read()[:500].decode("utf-8", "replace")
                if exc.code == 409 and conflict_means_done and attempt > 1:
                    return 409, b"{}"
                safe = exc.code == 429 or (idempotent and exc.code in RETRYABLE)
                if safe and not last:
                    wait = retry_after(exc.headers.get("Retry-After") if exc.headers else None, 2.0**attempt)
                    log.warning("Graph %s on attempt %d; retrying in %.0fs", exc.code, attempt, wait)
                    self.sleep(wait)
                    continue
                raise GraphError(exc.code, detail, retryable=safe) from None
            except NETWORK_ERRORS as exc:
                safe = idempotent or never_sent(exc)
                if safe and not last:
                    self.sleep(min(2.0**attempt, MAX_WAIT))
                    continue
                # Otherwise the request may have been delivered: do not repeat it.
                raise GraphError(0, f"network error: {exc}", retryable=safe) from None
        raise GraphError(0, "retries exhausted", retryable=True)

    def send_mime(self, mime: bytes) -> None:
        """Send a raw MIME message as the configured sender."""
        sender = urllib.parse.quote(self.config.sender)
        status, _ = self._request(
            "POST", f"{GRAPH}/users/{sender}/sendMail", base64.b64encode(mime), "text/plain",
            idempotent=False,
        )
        if status != 202:
            raise GraphError(status, "sendMail did not answer 202 Accepted")

    def upload(self, name: str, content: bytes) -> str:
        """Upload one file into the SharePoint folder; returns its web URL."""
        sp = self.config.sharepoint
        path = urllib.parse.quote(f"{sp.folder}/{name}")
        base = f"{GRAPH}/drives/{sp.drive_id}/root:/{path}:"
        # conflictBehavior=fail: if a retried simple upload finds the file already there,
        # an earlier attempt stored it, so it is not filed a second time under a new name.
        # Names carry a timestamp and are unique within a message, so a conflict on the
        # first attempt is a real clash and is reported, never treated as filed.
        if len(content) <= SIMPLE_UPLOAD_LIMIT:
            _, data = self._request(
                "PUT", f"{base}/content?@microsoft.graph.conflictBehavior=fail",
                content, "application/octet-stream", conflict_means_done=True,
            )
            return _json(data, "upload").get("webUrl", "")
        body = json.dumps({"item": {"@microsoft.graph.conflictBehavior": "fail"}}).encode()
        # No conflict_means_done here: a session creates no file until its last chunk
        # lands, so a 409 always means some other file already holds the name.
        _, data = self._request("POST", f"{base}/createUploadSession", body, "application/json")
        upload_url = _json(data, "createUploadSession").get("uploadUrl")
        if not isinstance(upload_url, str) or not upload_url.startswith("https://"):
            raise GraphError(0, "createUploadSession returned no usable uploadUrl")
        total = len(content)
        result = b"{}"
        for start in range(0, total, CHUNK):
            chunk = content[start:start + CHUNK]
            end = start + len(chunk) - 1
            # The upload URL is pre-authorised; sending a token to it is refused.
            # A chunk is repeated only when it provably never left: a re-sent chunk
            # Microsoft already holds is answered 416, which would fail a good upload.
            # Whether the printer may re-send the whole scan depends on the failure:
            # - a 4xx other than 408 or 429 is a refusal that will recur: permanent;
            # - a network error with no reply on the final chunk is ambiguous, because
            #   that chunk may have completed the file: permanent, to avoid a duplicate;
            # - anything else (a 5xx, 408, 429, or no reply on an earlier chunk) left no
            #   file behind: temporary, and the printer re-sends the scan.
            final = end == total - 1
            try:
                _, result = self._request(
                    "PUT", upload_url, chunk, "application/octet-stream", auth=False,
                    extra={"Content-Range": f"bytes {start}-{end}/{total}"}, idempotent=False,
                )
            except GraphError as exc:
                if 400 <= exc.status < 500:
                    retryable = exc.status in (408, 429)
                elif exc.status == 0:
                    retryable = not final or exc.retryable
                else:
                    retryable = True
                exc.retryable = retryable
                raise
        return _json(result, "upload").get("webUrl", "")
