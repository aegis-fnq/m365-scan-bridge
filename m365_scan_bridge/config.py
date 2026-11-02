"""Load and check the bridge's settings file.

The settings file holds no secret. It names the files the Graph credential and
the printer's SMTP password are read from; each must be owned by the service
user and readable by nobody else.
"""

import ipaddress
import os
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path

# Graph accepts a request of at most 4 MiB; sendMail carries the MIME message
# base64-encoded, so the encoded form of the prepared message must fit.
GRAPH_REQUEST_LIMIT = 4 * 1024 * 1024
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
TOP_LEVEL_KEYS = {
    "tenant_id", "client_id", "sender", "listen_host", "listen_port", "allowed_clients", "log_level",
    "max_messages_per_hour", "max_recipients_per_hour", "max_recipients_per_message",
    "sharepoint_max_bytes", "alert_address", "alert_after_failures", "smtp", "credential", "sharepoint",
}


class ConfigError(ValueError):
    """The settings file is missing, malformed or unsafe."""


@dataclass(frozen=True)
class SharePoint:
    trigger_address: str
    drive_id: str
    folder: str


@dataclass(frozen=True)
class Config:
    tenant_id: str
    client_id: str
    sender: str
    smtp_username: str = ""
    smtp_password: str = ""
    tls_cert_file: Path | None = None
    tls_key_file: Path | None = None
    listen_host: str = "0.0.0.0"
    listen_port: int = 2525
    allowed_clients: tuple[str, ...] = ()  # no default: the settings file must name the clients
    max_messages_per_hour: int = 60
    max_recipients_per_hour: int = 200
    max_recipients_per_message: int = 50
    sharepoint_max_bytes: int = 100 * 1024 * 1024
    secret_file: Path | None = None
    certificate_key_file: Path | None = None
    certificate_thumbprint: str | None = None
    sharepoint: SharePoint | None = None
    alert_address: str | None = None
    alert_after_failures: int = 3
    log_level: str = "INFO"


def private_file(path: Path, what: str) -> Path:
    """The file exists, is owned by this process's user and nobody else can read it."""
    try:
        st = path.stat()
    except OSError as exc:
        raise ConfigError(f"{what} {path} cannot be read: {exc.strerror}") from None
    if not stat.S_ISREG(st.st_mode):
        raise ConfigError(f"{what} {path} is not a file")
    if os.name == "posix":
        if st.st_uid != os.geteuid():
            raise ConfigError(f"{what} {path} is not owned by the user running the bridge")
        if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise ConfigError(
                f"{what} {path} is readable by others (mode {oct(st.st_mode & 0o777)}); chmod 600 it"
            )
    return path


def _read_secret(path: Path, what: str) -> str:
    private_file(path, what)
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ConfigError(f"{what} {path} cannot be read: {exc.strerror}") from None
    if not value:
        raise ConfigError(f"{what} {path} is empty")
    return value


def _int(raw: dict, key: str, default: int, low: int, high: int) -> int:
    value = raw.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{key} must be a whole number, not {value!r}")
    if not low <= value <= high:
        raise ConfigError(f"{key} must be between {low} and {high}, not {value}")
    return value


def _str(raw: dict, key: str, required: bool = True, default: str | None = None) -> str | None:
    value = raw.get(key, default)
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{key} must be a non-empty string")
    return value.strip()


def _table(raw: dict, key: str) -> dict | None:
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ConfigError(f"[{key}] must be a table")
    return value


def _parse(path: Path) -> dict:
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"settings file {path} does not exist") from None
    except OSError as exc:
        raise ConfigError(f"settings file {path} cannot be read: {exc.strerror}") from None
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"settings file {path} is not valid TOML: {exc}") from None
    unknown = sorted(set(raw) - TOP_LEVEL_KEYS)
    if unknown:
        raise ConfigError(f"unknown setting(s): {', '.join(unknown)}")
    return raw


def _clients(raw: dict) -> tuple[str, ...]:
    if "allowed_clients" not in raw:
        raise ConfigError(
            "allowed_clients is required: list the IP address(es) of the scanner(s) allowed to send, "
            'e.g. allowed_clients = ["192.0.2.10"]'
        )
    clients = raw["allowed_clients"]
    if not isinstance(clients, list) or not clients:
        raise ConfigError("allowed_clients must be a non-empty list of IP addresses")
    canonical = []
    for c in clients:
        if isinstance(c, str) and "%" in c:
            raise ConfigError(
                f"allowed_clients entry {c!r} has an IPv6 zone (%...); give the address without it"
            )
        try:
            ip = ipaddress.ip_address(c)
        except (ValueError, TypeError):
            raise ConfigError(f"allowed_clients entry {c!r} is not an IP address") from None
        # Stored in the same canonical form peer_ip() produces, so that any spelling of
        # an address (upper case, leading zeros, IPv4-mapped IPv6) matches the peer.
        canonical.append(str(getattr(ip, "ipv4_mapped", None) or ip))
    return tuple(canonical)


def _log_level(raw: dict) -> str:
    level = str(raw.get("log_level", "INFO")).upper()
    if level not in LOG_LEVELS:
        raise ConfigError(f"log_level must be one of {', '.join(LOG_LEVELS)}")
    return level


def _credential(raw: dict) -> dict:
    cred = _table(raw, "credential") or {}
    secret = _str(cred, "secret_file", required=False)
    key = _str(cred, "certificate_key_file", required=False)
    thumbprint = _str(cred, "certificate_thumbprint", required=False)
    if bool(secret) == bool(key):
        raise ConfigError("[credential] needs exactly one of secret_file or certificate_key_file")
    if key and not thumbprint:
        raise ConfigError("[credential] certificate_key_file needs certificate_thumbprint")
    if thumbprint and not key:
        raise ConfigError("[credential] certificate_thumbprint needs certificate_key_file")
    return {
        "secret_file": private_file(Path(secret), "secret file") if secret else None,
        "certificate_key_file": private_file(Path(key), "certificate key file") if key else None,
        "certificate_thumbprint": thumbprint,
    }


def _smtp(raw: dict) -> dict:
    smtp = _table(raw, "smtp")
    if not smtp:
        raise ConfigError("[smtp] is required: username, password_file, tls_cert_file, tls_key_file")
    cert = Path(_str(smtp, "tls_cert_file"))
    if not cert.is_file():
        raise ConfigError(f"tls_cert_file {cert} does not exist")
    return {
        "smtp_username": _str(smtp, "username"),
        "smtp_password": _read_secret(Path(_str(smtp, "password_file")), "SMTP password file"),
        "tls_cert_file": cert,
        "tls_key_file": private_file(Path(_str(smtp, "tls_key_file")), "TLS key file"),
    }


def _sharepoint(raw: dict) -> SharePoint | None:
    sp = _table(raw, "sharepoint")
    if sp is None:
        return None  # an empty [sharepoint] table is a mistake, and the keys below say so
    folder = _str(sp, "folder").strip("/").strip()
    if not folder:
        raise ConfigError("[sharepoint] folder must name a folder, not the library root")
    return SharePoint(trigger_address=_str(sp, "trigger_address").lower(), drive_id=_str(sp, "drive_id"), folder=folder)


def _limits(raw: dict) -> dict:
    limits = {
        "max_messages_per_hour": _int(raw, "max_messages_per_hour", 60, 1, 10_000),
        "max_recipients_per_hour": _int(raw, "max_recipients_per_hour", 200, 1, 10_000),
        "max_recipients_per_message": _int(raw, "max_recipients_per_message", 50, 1, 500),
        "sharepoint_max_bytes": _int(raw, "sharepoint_max_bytes", 100 * 1024 * 1024, 1, 250 * 1024 * 1024),
        "alert_after_failures": _int(raw, "alert_after_failures", 3, 1, 100),
    }
    if limits["max_recipients_per_message"] > limits["max_recipients_per_hour"]:
        raise ConfigError("max_recipients_per_message cannot exceed max_recipients_per_hour")
    return limits


def load(path: str | Path) -> Config:
    raw = _parse(Path(path))
    return Config(
        tenant_id=_str(raw, "tenant_id"),
        client_id=_str(raw, "client_id"),
        sender=_str(raw, "sender"),
        listen_host=_str(raw, "listen_host", default="0.0.0.0"),
        listen_port=_int(raw, "listen_port", 2525, 1, 65535),
        allowed_clients=_clients(raw),
        sharepoint=_sharepoint(raw),
        alert_address=_str(raw, "alert_address", required=False),
        log_level=_log_level(raw),
        **_smtp(raw),
        **_credential(raw),
        **_limits(raw),
    )
