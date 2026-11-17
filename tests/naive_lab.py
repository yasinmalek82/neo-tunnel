"""Exercise frp over an authenticated, destination-limited NaiveProxy HTTP/2 link."""
import argparse
import base64
import contextlib
import json
import os
import secrets
import socket
import ssl
import subprocess
import tempfile
import urllib.request
from pathlib import Path

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import ResponseReceived, StreamReset

from lab import ROOT, allocate_ports, app_sample, application, assert_probe, checked, loopback
from lab import prepare_credentials, remap, start, wait_for


def connect_status(proxy, ca, credentials, host, port):
    tls = ssl.create_default_context(cafile=ca)
    tls.set_alpn_protocols(["h2"])
    with socket.create_connection(("127.0.0.1", proxy), timeout=4) as raw:
        with tls.wrap_socket(raw, server_hostname="proxy.example.net") as session:
            assert session.selected_alpn_protocol() == "h2"
            h2 = H2Connection(config=H2Configuration(client_side=True, validate_outbound_headers=False))
            h2.initiate_connection()
            auth = base64.b64encode(credentials.encode()).decode()
            h2.send_headers(1, [(":method", "CONNECT"), (":authority", f"{host}:{port}"),
                                ("proxy-authorization", f"Basic {auth}")])
            session.sendall(h2.data_to_send())
            while packet := session.recv(4096):
                for event in h2.receive_data(packet):
                    if isinstance(event, ResponseReceived):
                        return int(dict(event.headers)[b":status"])
                    if isinstance(event, StreamReset):
                        raise AssertionError(f"HTTP/2 stream reset {event.error_code}")
                pending = h2.data_to_send()
                if pending:
                    session.sendall(pending)
    raise AssertionError("the proxy closed the HTTP/2 connection without a response")


def http_request(port):
    with urllib.request.urlopen(f"http://{loopback(port)}/readyz", timeout=4) as response:
        return response.read()


def exercise(args, work, stack):
    prepare_credentials(work)
    creds = work / "secrets"
    password = secrets.token_hex(16)
    (creds / "naive.token").write_text(secrets.token_hex(32) + "\n")
    (creds / "naive-client.crt").write_bytes((creds / "primary-client.crt").read_bytes())
    (creds / "naive-client.key").write_bytes((creds / "primary-client.key").read_bytes())
    cert = creds / "proxy.crt"
    checked(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=proxy.example.net",
             "-keyout", "proxy.key", "-out", "proxy.csr"], creds)
    ext = creds / "proxy.ext"
    ext.write_text("subjectAltName=DNS:proxy.example.net\nauthorityKeyIdentifier=keyid\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
    checked(["openssl", "x509", "-req", "-in", "proxy.csr", "-days", "2", "-CA", "ca.crt",
             "-CAkey", "ca.key", "-CAcreateserial", "-extfile", ext.name, "-out", cert.name], creds)
    ca = Path("/usr/local/share/ca-certificates/neo-lab-ca.crt")
    ca.write_bytes((creds / "ca.crt").read_bytes())
    stack.callback(ca.unlink, missing_ok=True)
    checked(["update-ca-certificates"], work, timeout=120)

    with Path("/etc/hosts").open("a") as hosts:
        hosts.write("127.0.0.1 proxy.example.net\n")

    transport, metrics, forward, canary, app, probe, proxy, socks, forbidden = allocate_ports(9)
    ports = {17020: transport, 17023: metrics, 17121: forward, 17122: canary, 14443: app, 18080: probe}
    samples = ROOT / "examples" / "naive"
    for name in ("frps-naive.toml", "frpc-naive.toml"):
        content = remap((samples / name).read_text(), ports).replace(":1080", f":{socks}")
        (work / name).write_text(content)
    config = (samples / "Caddyfile").read_text().replace(":443", f":{proxy}")
    config = config.replace("/etc/neo-tunnel/secrets", str(creds)).replace("17020", str(transport))
    config = config.replace("{$NEO_PROXY_USER}", "neo-lab").replace("{$NEO_PROXY_PASSWORD}", password)
    (work / "Caddyfile").write_text(config)
    checked([args.caddy, "validate", "--config", "Caddyfile", "--adapter", "caddyfile"], work)
    start(stack, work, "caddy", [args.caddy, "run", "--config", "Caddyfile", "--adapter", "caddyfile"])

    def alpn():
        try:
            tls = ssl.create_default_context(cafile=creds / "ca.crt")
            tls.set_alpn_protocols(["h2"])
            with socket.create_connection(("127.0.0.1", proxy), timeout=2) as raw:
                with tls.wrap_socket(raw, server_hostname="proxy.example.net") as session:
                    return session.selected_alpn_protocol()
        except OSError as exc:
            return repr(exc)

    wait_for("authenticated TLS endpoint negotiates HTTP/2", alpn, "h2", timeout=10)
    name = "naive.json"
    config = {"listen": f"socks://{loopback(socks)}", "proxy": f"https://neo-lab:{password}@proxy.example.net:{proxy}"}
    (work / name).write_text(json.dumps(config))
    start(stack, work, "naive", [args.naive, name])

    stack.enter_context(application(app, "naive", work))
    stack.enter_context(application(forbidden, "forbidden", work))
    start(stack, work, "probe", [args.probe, "serve", "-listen", loopback(probe)])
    for role in ("frps", "frpc"):
        binary = args.frp_dir / role
        name = f"{role}-naive.toml"
        checked([binary, "verify", "-c", name], work)
        start(stack, work, role, [binary, "-c", name])

    for protocol in ("tcp", "udp"):
        wait_for(f"NaiveProxy carries frp {protocol} payload", lambda: app_sample(forward, protocol), b"naive:lab-payload\n", timeout=25)
    assert http_request(canary) == b"backhaul-ready-v1\n"
    assert_probe(args, work, canary)
    for label, pw, host, dest, code in (
        ("invalid proxy credentials", "incorrect-password", "127.0.0.1", transport, 407),
        ("non-allowlisted port", password, "127.0.0.1", forbidden, 403),
        ("non-allowlisted address", password, "127.0.0.2", transport, 403),
    ):
        status = connect_status(proxy, creds / "ca.crt", f"neo-lab:{pw}", host, dest)
        assert status == code, (label, status)
        print(f"PASS NaiveProxy forward proxy rejects {label} (HTTP {code})", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("caddy", "naive", "frp-dir", "probe"):
        parser.add_argument(f"--{key}", type=Path, required=True)
    args = parser.parse_args()
    for key, path in vars(args).items():
        setattr(args, key, path.resolve(strict=True))
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="neo-naive-") as temp:
        work = Path(temp)
        try:
            with contextlib.ExitStack() as stack:
                exercise(args, work, stack)
        except (AssertionError, OSError, subprocess.SubprocessError):
            for file in work.glob("*.log"):
                print(f"{file.name}\n{file.read_text(errors='replace')[-2500:]}")
            raise


if __name__ == "__main__":
    main()
