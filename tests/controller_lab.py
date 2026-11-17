"""Controller acceptance fixture used by lab.py with isolated frp and HAProxy."""
import datetime
import http.server
import json
import ssl
import subprocess
import sys
import time
from pathlib import Path

from lab import IRAN_LAB_IP, PEER_LAB_IP, allocate_ports, checked, loopback, start


class AgentFixture(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        marker = Path(self.server.label)
        utc = datetime.datetime.now(datetime.timezone.utc)
        if marker.with_suffix(".stale").exists():
            utc -= datetime.timedelta(seconds=31)
        data = {
            "at": utc.isoformat(),
            "host_cpu_fraction": .91 if marker.with_suffix(".cpu").exists() else .20,
            "host_memory_available_fraction": .10 if marker.with_suffix(".memory").exists() else .65,
            "tool_cpu_seconds": time.monotonic() / 10,
            "tool_working_set_bytes": 24 << 20,
            "baseline_ready": True, "baseline_cpu_mean": .2, "baseline_available_mean": .65,
            "sustained_pressure": marker.with_suffix(".sustained").exists(),
        }
        self.result(data)

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        operation = request["action"]
        if operation not in ("claim", "release"):
            self.send_error(409)
            return
        self.result({})

    def result(self, body):
        content = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


def serve(label, address, port):
    server = http.server.ThreadingHTTPServer((address, int(port)), AgentFixture)
    server.label = label
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain("secrets/management.crt", "secrets/management.key")
    context.load_verify_locations("secrets/ca.crt")
    context.verify_mode = ssl.CERT_REQUIRED
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def management_cert(work):
    creds = work / "secrets"
    checked(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
             "-subj", "/CN=Management Fixture", "-keyout", "management.key", "-out", "management.csr"], creds)
    (creds / "management.ext").write_text(
        f"subjectAltName=IP:127.0.0.1,IP:{IRAN_LAB_IP},IP:{PEER_LAB_IP}\nextendedKeyUsage=serverAuth\n"
    )
    checked(["openssl", "x509", "-req", "-in", "management.csr", "-days", "2",
             "-extfile", "management.ext", "-CA", "ca.crt", "-CAkey", "ca.key",
             "-CAcreateserial", "-out", "management.crt"], creds)


def exercise(args, work, stack, peer, assigned):
    management_cert(work)
    addresses = ("127.0.0.1", PEER_LAB_IP)
    ports = allocate_ports(2)
    for label, addr, port, namespace in zip(("iran", "peer"), addresses, ports, (None, peer), strict=True):
        start(stack, work, f"agent-{label}", [sys.executable, Path(__file__).resolve(), label, addr, str(port)], namespace)
    config = {
        "state_dir": str(work / "controller"),
        "iran_agent": f"https://{addresses[0]}:{ports[0]}",
        "peer_agent": f"https://{addresses[1]}:{ports[1]}",
        "identity": {"cert": "secrets/primary-client.crt", "key": "secrets/primary-client.key", "ca": "secrets/ca.crt"},
        "haproxy_socket": str(work / "haproxy.sock"),
        "map_file": str(work / "route.map"), "initial": "primary",
        "profiles": {
            profile: {"canary": loopback(assigned[canary]), "carrier": carrier,
                      "app_url": f"http://{loopback(assigned[app])}/healthz", "app_body": "ok\n"}
            for profile, app, canary, carrier in (("primary", 17101, 17102, "tcp/tls"), ("standby", 17111, 17112, "quic"))
        },
    }
    config_path = work / "controller.json"
    config_path.write_text(json.dumps(config))
    cli = [args.controller, "--config", config_path, "--json"]
    time.sleep(1)
    status = json.loads(checked([*cli, "status"], work))
    assert status["iran"] and status["peer"] and status["isp_experience"] is None, status
    assert status["application_ready"] == {"primary": True, "standby": True}, status
    print("PASS controller reports both authenticated agents and actual application replies", flush=True)
    for flag in ("iran.cpu", "peer.memory", "peer.stale"):
        path = work / flag
        path.touch()
        try:
            rejected = subprocess.run([*cli, "calibrate"], capture_output=True, text=True, cwd=work, timeout=8)
            assert rejected.returncode != 0 and ("headroom" in rejected.stderr or "stale" in rejected.stderr), rejected
            if flag == "peer.stale":
                status = json.loads(checked([*cli, "status"], work))
                assert status["peer"] is None and status["path_health"]["primary"]["state"] == "UP", status
            print(f"PASS controller refuses calibration with {flag}", flush=True)
        finally:
            path.unlink()

    running = start(stack, work, "calibration", [*cli, "calibrate"])
    deadline = time.monotonic() + 10
    while not (work / "controller" / "state.json").exists() and time.monotonic() < deadline:
        time.sleep(.05)
    conflict = subprocess.run([*cli, "rollback"], capture_output=True, text=True, cwd=work, timeout=5)
    assert conflict.returncode != 0 and "already running" in conflict.stderr, conflict
    time.sleep(8)
    (work / "peer.sustained").touch()
    assert running.wait(timeout=20) == 0
    interrupted = json.loads((work / "calibration.log").read_text())
    assert interrupted["baseline"]["uncertain"] and not interrupted["eligible"], interrupted
    (work / "peer.sustained").unlink()
    print("PASS concurrent change is rejected and new peer pressure stops a calibration already running", flush=True)

    completed = json.loads(checked([*cli, "calibrate"], work, timeout=315))
    for result in (completed["baseline"], completed["candidate"]):
        assert result["samples"] == result["success"] == 60, result
        assert result["useful_bytes"] == 8396800, result
        assert result["iran"]["cpu_seconds_per_gib"] is not None, result
        assert result["peer"]["extra_bytes"] is None, result
    assert completed["baseline"]["useful_bytes"] + completed["candidate"]["useful_bytes"] <= (64 << 20)
    print("PASS a full A/B/A calibration records 60 successes per profile and stays within its data cap", flush=True)

    # Isolate switching mechanics from the lab's noisy carrier measurements.
    completed["eligible"] = True
    completed["baseline"]["p95_ms"] = 100
    completed["candidate"]["p95_ms"] = 50
    completed["baseline"]["p95_under_load_ms"] = 100
    completed["candidate"]["p95_under_load_ms"] = 50
    proposal = work / "controller" / ("proposal-" + completed["id"] + ".json")
    proposal.write_text(json.dumps(completed))
    from lab import app_sample, via_stream
    import socket
    with socket.create_connection(("127.0.0.1", assigned[16443]), timeout=10) as session, session.makefile("rb") as reader:
        assert via_stream(session, reader) == b"primary:lab-payload\n"
        for _ in range(2):
            state = json.loads(checked([*cli, "apply", completed["id"]], work))
            assert state["active"]["profile"] == "standby", state
        assert app_sample(assigned[16443]) == b"standby:lab-payload\n"
        assert via_stream(session, reader) == b"primary:lab-payload\n"
        state = json.loads(checked([*cli, "rollback"], work))
        assert state["active"]["profile"] == "primary", state
        assert app_sample(assigned[16443]) == b"primary:lab-payload\n"
    stale = subprocess.run([*cli, "apply", completed["id"]], capture_output=True, text=True, cwd=work, timeout=5)
    assert stale.returncode != 0 and "stale" in stale.stderr, stale
    print("PASS apply, idempotent retry, session drain, rollback and rejection of old evidence", flush=True)


if __name__ == "__main__":
    serve(*sys.argv[1:])
