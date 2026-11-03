"""Run the bridge: m365-scan-bridge /etc/m365-scan-bridge/config.toml"""

import argparse
import logging
import signal
import ssl
import sys
import threading

from aiosmtpd.controller import Controller

from . import config as config_mod
from .graph import Graph, GraphError
from .handler import Authenticator, Handler


def tls_context(cfg) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    # Some printer firmware still offers TLS 1.0 and 1.1; 1.2 is the floor we accept.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cfg.tls_cert_file, cfg.tls_key_file)
    return ctx


def smtp_size_limit(cfg) -> int:
    """Largest message the SMTP side accepts. A file travels base64-encoded inside
    the message, a third bigger than the file, so allow for that plus headers."""
    if not cfg.sharepoint:
        return config_mod.GRAPH_REQUEST_LIMIT
    return max(config_mod.GRAPH_REQUEST_LIMIT, cfg.sharepoint_max_bytes * 4 // 3 + 1024 * 1024)


def main(argv=None, graph_factory=Graph) -> int:
    parser = argparse.ArgumentParser(prog="m365-scan-bridge")
    parser.add_argument("config", help="path to the settings file")
    parser.add_argument("--check", action="store_true", help="load settings and get a Graph token, then exit")
    args = parser.parse_args(argv)

    try:
        cfg = config_mod.load(args.config)
    except config_mod.ConfigError as exc:
        print(f"m365-scan-bridge: {exc}", file=sys.stderr)
        return 2
    logging.basicConfig(level=cfg.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        graph = graph_factory(cfg)
        if args.check:
            tls_context(cfg)
            graph.token()
            print("settings loaded, TLS certificate loaded and a Graph token was issued")
            return 0
        ctx = tls_context(cfg)
    except (GraphError, OSError, ssl.SSLError, ValueError) as exc:
        print(f"m365-scan-bridge: {exc}", file=sys.stderr)
        return 1

    limit = smtp_size_limit(cfg)
    controller = Controller(
        Handler(cfg, graph), hostname=cfg.listen_host, port=cfg.listen_port,
        tls_context=ctx, require_starttls=True,
        authenticator=Authenticator(cfg), auth_required=True, auth_require_tls=True,
        data_size_limit=limit,
    )
    try:
        controller.start()
    except (OSError, RuntimeError) as exc:  # port in use, no permission, bad address
        print(f"m365-scan-bridge: cannot listen on {cfg.listen_host}:{cfg.listen_port}: {exc}", file=sys.stderr)
        return 1
    logging.getLogger(__name__).info("listening on %s:%d", cfg.listen_host, cfg.listen_port)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    stop.wait()
    controller.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
