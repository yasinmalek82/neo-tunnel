"""Loopback integration test for the shipped configurations. No services or live hosts."""
import argparse
import contextlib
import json
import os
import re
import secrets
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOOPBACK = "127.0.0.1"

# Numbers from examples/ are replaced with unused loopback ports.
CONFIG_PORTS = (16443, 17000, 17003, 17010, 17011, 17013, 17101, 17102, 17111, 17112)
IRAN_LAB_IP = "10.212.0.1"
PEER_LAB_IP = "10.212.0.2"
PROXY_PORTS = {"primary": (17101, 17102), "standby": (17111, 17112)}


def loopback(port):
    return f"{LOOPBACK}:{port}"


def allocate_ports(count):
    with contextlib.ExitStack() as sockets:
        ports = []
        for _ in range(count):
            tcp = sockets.enter_context(socket.socket())
            tcp.bind((LOOPBACK, 0))
            port = tcp.getsockname()[1]
            udp = sockets.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            udp.bind((LOOPBACK, port))
            ports.append(port)
        return ports


def checked(args, cwd, timeout=12):
    run = subprocess.run(
        args, cwd=cwd, timeout=timeout, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if run.returncode != 0:
        raise AssertionError(f"{Path(args[0]).name} exited {run.returncode}:\n{run.stdout}")
    return run.stdout


def prepare_credentials(work):
    folder = work / "secrets"
    folder.mkdir()
    for lane in PROXY_PORTS:
        (folder / f"{lane}.token").write_text(secrets.token_hex(32) + "\n")

    checked([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
        "-subj", "/CN=Local Backhaul Lab CA", "-keyout", "ca.key", "-out", "ca.crt",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    ], folder)
    for name, common_name, purpose in (
        ("iran", "iran.example.net", "serverAuth"),
        ("primary-client", "primary.example.net", "clientAuth"),
        ("standby-client", "standby.example.net", "clientAuth"),
    ):
        ext = folder / f"{name}.ext"
        ext.write_text(
            "basicConstraints=critical,CA:FALSE\n"
            f"extendedKeyUsage={purpose}\n"
            f"subjectAltName=DNS:{common_name}\n"
        )
        checked([
            "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-subj", f"/CN={common_name}", "-keyout", f"{name}.key", "-out", f"{name}.csr",
        ], folder)
        checked([
            "openssl", "x509", "-req", "-in", f"{name}.csr", "-days", "2",
            "-extfile", ext.name, "-CA", "ca.crt", "-CAkey", "ca.key",
            "-CAcreateserial", "-out", f"{name}.crt",
        ], folder)


def render(work, assigned, local_apps, local_canaries, network=False):
    for name in ("primary", "standby"):
        for role in ("frps", "frpc"):
            filename = f"{role}-{name}.toml"
            config = (ROOT / "examples" / filename).read_text()
            ports = dict(assigned)
            if role == "frpc":
                config = config.replace('serverAddr = "iran.example.net"', f'serverAddr = "{IRAN_LAB_IP if network else LOOPBACK}"')
                ports.update({14443: local_apps[name], 18080: local_canaries[name]})
            elif network:
                config = config.replace('bindAddr = "127.0.0.1"', f'bindAddr = "{IRAN_LAB_IP}"')
            (work / filename).write_text(remap(config, ports))
    config = (ROOT / "examples" / "haproxy.cfg").read_text()
    config = config.replace("/run/neo-tunnel/haproxy.sock", str(work / "haproxy.sock"))
    config = config.replace("/etc/neo-tunnel/runtime/route.map", str(work / "route.map"))
    (work / "route.map").write_text("preference primary\n")
    (work / "haproxy.cfg").write_text(remap(config, assigned))


def remap(config, ports):
    return re.sub(r"\b\d{5}\b", lambda m: str(ports.get(int(m[0]), m[0])), config)


class StreamApplication(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(65)
        try:
            while message := self.rfile.readline(128):
                if message.startswith(b"GET /healthz "):
                    while self.rfile.readline(4096) not in (b"\r\n", b"\n", b""):
                        pass
                    if (self.server.work / (self.server.label.decode() + ".unhealthy")).exists():
                        self.wfile.write(b"HTTP/1.0 503 Unavailable\r\nContent-Length: 0\r\n\r\n")
                    else:
                        self.wfile.write(b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nok\n")
                    return
                self.wfile.write(self.server.label + b":" + message)
        except OSError:
            pass


class DatagramApplication(socketserver.BaseRequestHandler):
    def handle(self):
        packet, sock = self.request
        sock.sendto(self.server.label + b":" + packet, self.client_address)


class TCPFixture(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


@contextlib.contextmanager
def application(port, lane, work=None):
    with (
        TCPFixture((LOOPBACK, port), StreamApplication) as tcp,
        socketserver.UDPServer((LOOPBACK, port), DatagramApplication) as udp,
    ):
        for server in (tcp, udp):
            server.work = Path.cwd() if work is None else work
            server.label = lane.encode()
            threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True).start()
        try:
            yield
        finally:
            tcp.shutdown()
            udp.shutdown()


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def start(stack, work, name, args, peer=None):
    if peer:
        args = ["ip", "netns", "exec", peer, *args]
    with (work / f"{name}.log").open("wb") as output:
        process = subprocess.Popen(args, cwd=work, stdout=output, stderr=subprocess.STDOUT)
    stack.callback(stop, process)
    return process


def wait_for(label, sample, expected, timeout=55):
    started = time.monotonic()
    while time.monotonic() - started < timeout:
        actual = sample()
        if actual == expected:
            seconds = time.monotonic() - started
            print(f"PASS {label} ({seconds:.2f}s)", flush=True)
            return
        time.sleep(0.08)
    raise AssertionError(f"{label}: expected {expected!r}, got {actual!r}")


def via_stream(sock, reader):
    sock.sendall(b"lab-payload\n")
    return reader.readline(128)


def app_sample(port, protocol="tcp"):
    try:
        if protocol == "udp":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.settimeout(0.35)
                udp.connect((LOOPBACK, port))
                udp.send(b"lab-payload\n")
                return udp.recv(128)
        with socket.create_connection((LOOPBACK, port), timeout=0.35) as tcp, tcp.makefile("rb") as reader:
            return via_stream(tcp, reader)
    except OSError:
        return None


def assert_probe(args, work, port):
    reply = checked([
        args.probe, "check", "-tcp", loopback(port), "-udp", loopback(port),
        "-n", "5", "-timeout", "1s",
    ], work)
    samples = [json.loads(line) for line in reply.splitlines()]
    assert [(v["transport"], v["received"]) for v in samples] == [("tcp", 5), ("udp", 5)], samples


def exercise(args, work, stack):
    keys = list(CONFIG_PORTS) + ["app-primary", "app-standby", "canary-primary", "canary-standby"]
    assigned = dict(zip(keys, allocate_ports(len(keys)), strict=True))
    local_apps = {lane: assigned[f"app-{lane}"] for lane in PROXY_PORTS}
    local_canaries = {lane: assigned[f"canary-{lane}"] for lane in PROXY_PORTS}
    render(work, assigned, local_apps, local_canaries, args.netns)
    peer = netns(work, stack) if args.netns else None
    prepare_credentials(work)
    edge_port = assigned[16443]
    frps, frpc = args.frp_dir / "frps", args.frp_dir / "frpc"

    for lane in PROXY_PORTS:
        if peer:
            start(stack, work, f"app-{lane}", [
                sys.executable, Path(__file__).resolve(), "--fixture", str(local_apps[lane]), lane
            ], peer)
        else:
            stack.enter_context(application(local_apps[lane], lane, work))
        for binary, prefix in ((frps, "frps"), (frpc, "frpc")):
            checked([binary, "verify", "-c", f"{prefix}-{lane}.toml"], work)
        start(stack, work, f"frps-{lane}", [frps, "-c", f"frps-{lane}.toml"])
    checked([args.haproxy, "-c", "-f", "haproxy.cfg"], work)

    def canary(lane):
        return start(stack, work, f"canary-{lane}", [
            args.probe, "serve", "-listen", loopback(local_canaries[lane]),
        ], peer)

    canaries, clients = {}, {}
    for lane, (proxy_port, probe_port) in PROXY_PORTS.items():
        canaries[lane] = canary(lane)
        clients[lane] = start(stack, work, f"frpc-{lane}", [frpc, "-c", f"frpc-{lane}.toml"], peer)
        expected = f"{lane}:lab-payload\n".encode()
        for protocol in ("tcp", "udp"):
            wait_for(f"{lane} carries {protocol} payload", lambda: app_sample(assigned[proxy_port], protocol), expected)
        assert_probe(args, work, assigned[probe_port])
        print(f"PASS {lane} canary (5 TCP and 5 UDP replies)", flush=True)

    edge = start(stack, work, "edge", [args.haproxy, "-db", "-f", "haproxy.cfg"])
    primary = b"primary:lab-payload\n"
    standby = b"standby:lab-payload\n"
    wait_for("new connection prefers primary", lambda: app_sample(edge_port), primary)

    wait_for("standby becomes ready before measuring failover",
             lambda: any("standby,via_standby," in row and ",UP," in row
                         for row in runtime(work, "show stat").splitlines()), True)

    runtime(work, f"set map {work / 'route.map'} preference standby")
    wait_for("runtime preference sends new connections to standby", lambda: app_sample(edge_port), standby)
    runtime(work, f"set map {work / 'route.map'} preference primary")
    wait_for("runtime rollback sends new connections to primary", lambda: app_sample(edge_port), primary)

    if peer:
        if args.controller:
            from controller_lab import exercise as exercise_controller
            exercise_controller(args, work, stack, peer, assigned)
        exercise_network(work, peer, args, assigned)
        marker = work / "primary.unhealthy"
        marker.touch()
        wait_for("unhealthy destination application triggers TCP failover", lambda: app_sample(edge_port), standby)
        marker.unlink()
        wait_for("healthy application restores primary", lambda: app_sample(edge_port), primary)

    # The primary app still answers through frp, but the health payload no longer returns.
    stop(canaries["primary"])
    assert app_sample(assigned[17101]) == primary, "primary app is supposed to stay reachable"
    wait_for("failed round trip moves new connections to ready standby", lambda: app_sample(edge_port), standby)

    with socket.create_connection((LOOPBACK, edge_port), timeout=60) as sock, sock.makefile("rb") as reader:
        assert via_stream(sock, reader) == standby, "persistent session should start on standby"
        canaries["primary"] = canary("primary")
        wait_for("recovering primary receives new connections", lambda: app_sample(edge_port), primary)
        assert via_stream(sock, reader) == standby, "established session was interrupted or moved"
        print("PASS established standby session survives failback", flush=True)

    stop(clients["primary"])
    wait_for("a stopped primary tunnel moves new connections to standby", lambda: app_sample(edge_port), standby)
    stop(canaries["standby"])
    wait_for("no ready path closes new connections", lambda: app_sample(edge_port), b"")
    assert edge.poll() is None, "edge process died instead of declining a connection"

    valid = (work / "frpc-primary.toml").read_text()
    invalid = valid.replace('serverName = "iran.example.net"', 'serverName = "wrong.example.net"')
    invalid = invalid.replace("loginFailExit = false", "loginFailExit = true")
    (work / "frpc-invalid-name.toml").write_text(invalid)
    refused = subprocess.run(
        (["ip", "netns", "exec", peer] if peer else []) + [frpc, "-c", "frpc-invalid-name.toml"], cwd=work,
        capture_output=True, text=True, timeout=10,
    )
    assert refused.returncode != 0 and "certificate" in refused.stdout + refused.stderr, refused
    print("PASS frpc rejects a mismatched server certificate name", flush=True)


def runtime(work, command):
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(2)
        client.connect(str(work / "haproxy.sock"))
        client.sendall((command + "\n").encode())
        client.shutdown(socket.SHUT_WR)
        with client.makefile() as reply:
            return reply.read()


def netns(work, stack):
    peer = f"neo-peer-{os.getpid()}"
    checked(["ip", "netns", "add", peer], work)
    stack.callback(checked, ["ip", "netns", "delete", peer], work)
    checked(["ip", "link", "add", "v-iran", "type", "veth", "peer", "name", "v-peer"], work)
    stack.callback(checked, ["ip", "link", "delete", "v-iran"], work)
    checked(["ip", "link", "set", "v-peer", "netns", peer], work)
    for namespace, iface, addr in (([], "v-iran", IRAN_LAB_IP), (["ip", "netns", "exec", peer], "v-peer", PEER_LAB_IP)):
        checked([*namespace, "ip", "addr", "add", f"{addr}/30", "dev", iface], work)
        checked([*namespace, "ip", "link", "set", iface, "up"], work)
        checked([*namespace, "ip", "link", "set", "lo", "up"], work)
    return peer


def exercise_network(work, peer, args, assigned):
    netem = ["ip", "netns", "exec", peer, "tc", "qdisc"]
    setup = [*netem, "replace", "dev", "v-peer", "root", "netem"]
    cleanup = [*netem, "del", "dev", "v-peer", "root"]
    checked([*setup, "delay", "35ms", "10ms", "loss", "3%", "rate", "2mbit"], work)
    try:
        for transport in ("tcp", "udp"):
            wait_for(f"{transport} delivers data with network impairment", lambda: app_sample(assigned[17101], transport),
                     b"primary:lab-payload\n", timeout=10)
        checked([*setup, "loss", "100%"], work)
        wait_for("one-way link loss prevents both carriers from answering",
                 lambda: (app_sample(assigned[17101]), app_sample(assigned[17111])), (None, None), timeout=20)
    finally:
        checked(cleanup, work)
    wait_for("network returns to normal", lambda: app_sample(assigned[16443]), b"primary:lab-payload\n")
    assert_probe(args, work, assigned[17102])


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--fixture":
        with application(int(sys.argv[2]), sys.argv[3]):
            threading.Event().wait()
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller", type=Path, help="also verify the controller workflow in the isolated Linux lab")
    parser.add_argument("--netns", action="store_true", help="create a separate Linux peer network namespace in an isolated test container")
    parser.add_argument("--frp-dir", type=Path, required=True, help="directory with frpc and frps v0.72.0")
    parser.add_argument("--haproxy", type=Path, required=True, help="path to HAProxy")
    parser.add_argument("--probe", type=Path, required=True, help="path to compiled backhaul-probe")
    args = parser.parse_args()
    args.frp_dir, args.haproxy, args.probe = (
        value.resolve(strict=True) for value in (args.frp_dir, args.haproxy, args.probe)
    )
    if args.controller:
        if not args.netns:
            parser.error("--controller requires --netns")
        args.controller = args.controller.resolve(strict=True)
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="backhaul-test-") as data:
        work = Path(data)
        try:
            with contextlib.ExitStack() as stack:
                exercise(args, work, stack)
        except (AssertionError, OSError, subprocess.SubprocessError) as exc:
            for log in sorted(work.glob("*.log")):
                print(f"\n{log.name}\n{log.read_text(errors='replace')[-2500:]}", flush=True)
            raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
