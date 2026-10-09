#!/usr/bin/env python3
"""Exchange-shaped SMTP servers for test-smtp-matrix.sh.

Mailpit covers the well-behaved SMTP servers. This file reproduces the
shapes Mailpit cannot, the ones an on-prem Microsoft Exchange receive
connector commonly presents (discussion #4244):

  exchange    Client Frontend style. Plaintext EHLO offers STARTTLS and
              only "AUTH NTLM GSSAPI"; after STARTTLS it offers
              "AUTH GSSAPI NTLM LOGIN PLAIN". MAIL FROM without
              authentication is refused with "530 5.7.1 Client was not
              authenticated". Bad credentials get
              "535 5.7.3 Authentication unsuccessful".
  nostarttls  A connector with TLS turned off: no STARTTLS, only
              "AUTH NTLM GSSAPI", and anonymous relay accepted (the usual
              "application relay" connector).
  privateca   Like "exchange" but the certificate is signed by a CA the
              client has not been told about, and PLAIN/LOGIN are offered
              after STARTTLS only.

Accepted messages are relayed unchanged to RELAY_HOST:RELAY_PORT (a Mailpit
sink) so the test can assert delivery through one API.

Configuration is by environment: SHAPE, PORT (default 2525), TLS_CERT,
TLS_KEY, AUTH_USER, AUTH_PASS, RELAY_HOST, RELAY_PORT.

Requires aiosmtpd (pip install aiosmtpd).
"""

import asyncio
import logging
import os
import smtplib
import ssl
import sys

from aiosmtpd.smtp import MISSING, SMTP, AuthResult, LoginPassword

SHAPE = os.environ.get("SHAPE", "exchange")
PORT = int(os.environ.get("PORT", "2525"))
TLS_CERT = os.environ.get("TLS_CERT", "")
TLS_KEY = os.environ.get("TLS_KEY", "")
AUTH_USER = os.environ.get("AUTH_USER", "ak")
AUTH_PASS = os.environ.get("AUTH_PASS", "")
RELAY_HOST = os.environ.get("RELAY_HOST", "")
RELAY_PORT = int(os.environ.get("RELAY_PORT", "1025"))

if SHAPE not in ("exchange", "nostarttls", "privateca"):
    sys.exit(f"unknown SHAPE {SHAPE!r}")

logging.basicConfig(
    level=logging.INFO, format=f"%(asctime)s {SHAPE} %(message)s", stream=sys.stdout
)
log = logging.getLogger("smtpd")

ADVERTISE_PLAINTEXT = {
    "exchange": "250-AUTH NTLM GSSAPI",
    "nostarttls": "250-AUTH NTLM GSSAPI",
    "privateca": None,
}
ADVERTISE_TLS = {
    "exchange": "250-AUTH GSSAPI NTLM LOGIN PLAIN",
    "privateca": "250-AUTH LOGIN PLAIN",
}
REQUIRE_AUTH = SHAPE in ("exchange", "privateca")


def authenticator(server, session, envelope, mechanism, auth_data):
    ok = (
        isinstance(auth_data, LoginPassword)
        and auth_data.login.decode() == AUTH_USER
        and auth_data.password.decode() == AUTH_PASS
    )
    log.info("AUTH %s user=%r -> %s", mechanism, getattr(auth_data, "login", b"").decode(), "ok" if ok else "535")
    if ok:
        return AuthResult(success=True)
    return AuthResult(
        success=False, handled=False, message="535 5.7.3 Authentication unsuccessful"
    )


class Handler:
    async def handle_EHLO(self, server, session, envelope, hostname, responses):
        session.host_name = hostname
        encrypted = server._tls_protocol is not None
        out = [r for r in responses if not r.startswith("250-AUTH")]
        line = ADVERTISE_TLS.get(SHAPE) if encrypted else ADVERTISE_PLAINTEXT[SHAPE]
        if line:
            out.insert(len(out) - 1 if out[-1].startswith("250 ") else len(out), line)
        log.info("EHLO %s tls=%s -> %s", hostname, encrypted, " | ".join(out))
        return out

    async def handle_AUTH(self, server, session, envelope, args):
        # Exchange refuses basic mechanisms it did not advertise.
        encrypted = server._tls_protocol is not None
        mech = args[0].upper() if args else ""
        if mech in ("PLAIN", "LOGIN") and (not encrypted or SHAPE == "nostarttls"):
            log.info("AUTH %s before TLS -> 504", mech)
            return "504 5.7.4 Unrecognized authentication type"
        return MISSING

    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        if REQUIRE_AUTH and not session.authenticated:
            log.info("MAIL FROM %s unauthenticated -> 530", address)
            return "530 5.7.1 Client was not authenticated"
        envelope.mail_from = address
        envelope.mail_options.extend(mail_options)
        return "250 2.1.0 Sender OK"

    async def handle_DATA(self, server, session, envelope):
        log.info("DATA from=%s to=%s", envelope.mail_from, envelope.rcpt_tos)
        if RELAY_HOST:
            try:
                await asyncio.get_running_loop().run_in_executor(None, relay, envelope)
            except Exception as exc:  # noqa: BLE001
                log.info("relay failed: %s", exc)
                return "451 4.4.0 relay to sink failed"
        return "250 2.6.0 Queued mail for delivery"


def relay(envelope):
    with smtplib.SMTP(RELAY_HOST, RELAY_PORT, timeout=10) as s:
        s.sendmail(envelope.mail_from, envelope.rcpt_tos, envelope.original_content)


def main():
    tls_context = None
    if SHAPE != "nostarttls":
        tls_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        tls_context.load_cert_chain(TLS_CERT, TLS_KEY)

    def factory():
        return SMTP(
            Handler(),
            hostname="mail.aksmtp.test",
            ident="Microsoft ESMTP MAIL Service ready",
            tls_context=tls_context,
            require_starttls=False,
            auth_require_tls=False,
            authenticator=authenticator,
            auth_exclude_mechanism=[],
            decode_data=False,
        )

    loop = asyncio.new_event_loop()
    server = loop.run_until_complete(loop.create_server(factory, "0.0.0.0", PORT))
    log.info("listening on %d", PORT)
    try:
        loop.run_forever()
    finally:
        server.close()


if __name__ == "__main__":
    main()
