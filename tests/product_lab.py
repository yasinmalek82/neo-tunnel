"""Install the release on two disposable, isolated systemd containers."""
import argparse
import contextlib
import json
import os
import re
import subprocess
import time
from pathlib import Path


def docker(*args, data=None, timeout=90):
    run = subprocess.run(["docker", *args], input=data, capture_output=True, text=True, timeout=timeout)
    if run.returncode:
        # The setup command includes a temporary enrollment secret.
        detail = re.sub(r"(neo-tunnel://)[^'\s]+", r"\1REDACTED", run.stderr + run.stdout)
        raise RuntimeError(f"Docker {args[0]} failed ({run.returncode})\n{detail}")
    return run.stdout


def ready(check, timeout=70):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if result := check():
                return result
        except (RuntimeError, ValueError):
            pass
        time.sleep(1)
    raise AssertionError("timed out waiting for test service")


def run(image, bundle, upgrade_from=None):
    key = f"neo-product-{os.getpid()}"
    network, iran, foreign = key + "-net", key + "-iran", key + "-foreign"
    with contextlib.ExitStack() as cleanup:
        docker("network", "create", "--internal", network)
        cleanup.callback(docker, "network", "rm", network)
        initial = "/neo-previous" if upgrade_from else "/neo-release"
        mounts = ["-v", f"{bundle}:/neo-release:ro"]
        if upgrade_from:
            mounts.extend(["-v", f"{upgrade_from}:/neo-previous:ro"])
        for name in (iran, foreign):
            docker("run", "-d", "--privileged", "--cgroupns=private", "--network", network,
                   "--name", name, "--tmpfs", "/run", "--tmpfs", "/run/lock",
                   *mounts, image)
            cleanup.callback(docker, "rm", "-f", name)
            ready(lambda: docker("exec", name, "systemctl", "show", "-p", "SystemState", "--value").strip()
                  in ("running", "degraded"))
        try:
            docker("exec", iran, "bash", f"{initial}/install.sh", "--bundle", initial, "--install-only")
            docker("exec", "-d", foreign, "python3", "-m", "http.server", "14443", "--bind", "127.0.0.1")
            result = docker("exec", "-i", iran, "neo-tunnel", "setup-iran",
                            data=f"{iran}\nno\n16443\n14443\nyes\n")
            assert result.isascii(), "installer printed non-ASCII text"
            link = re.search(r"'(neo-tunnel://[^']+)'", result).group(1)
            # Keep the temporary token out of command arguments.
            install = ["exec", "-i", foreign, "bash", f"{initial}/install.sh",
                       "--bundle", initial, "--join-stdin"]
            response = docker(*install, data=link + "\n")
            assert response.isascii(), "foreign installer printed non-ASCII text"

            def status():
                snapshot = json.loads(docker("exec", iran, "neo-tunnel", "status", "--json"))
                if not snapshot["iran"] or not snapshot["peer"]:
                    return None
                health = snapshot["path_health"]
                if all(health.get(k, {}).get("state") == "UP" for k in ("primary", "standby")):
                    return snapshot
                return None

            ready(status)
            docker("exec", iran, "curl", "-fsS", "http://127.0.0.1:16443/")
            print("PASS clean install, one-time join, working TCP traffic, TCP/TLS + QUIC and both agents", flush=True)

            ready_status = docker("exec", iran, "neo-tunnel", "status")
            assert ready_status.isascii() and "Ready" in ready_status
            docker(*install, data=link + "\n")
            ready(status)
            print("PASS idempotent foreign reinstall and ASCII terminal status", flush=True)

            if upgrade_from:
                units = ["neo-frp@frps-primary.service", "neo-frp@frps-standby.service", "neo-haproxy.service"]
                before = docker("exec", iran, "systemctl", "show", "--property=MainPID", *units)
                docker("exec", iran, "bash", "/neo-release/install.sh", "--bundle", "/neo-release", "--install-only")
                after = docker("exec", iran, "systemctl", "show", "--property=MainPID", *units)
                assert before == after, (before, after)
                assert docker("exec", iran, "cat", "/usr/local/share/neo-tunnel/install-version").strip() == "v0.2.1"
                docker("exec", iran, "curl", "-fsS", "http://127.0.0.1:16443/")
                print("PASS v0.2.0 upgrade preserves all tunnel service processes and TCP forwarding", flush=True)

            def pilot_status():
                return json.loads(docker("exec", iran, "neo-tunnel", "pilot", "status", "--json"))

            ready(lambda: pilot_status()["peer_minutes"] > 0, 85)
            first = pilot_status()
            assert first["active"], first
            docker("exec", iran, "neo-tunnel", "pilot", "stop")
            stopped = pilot_status()
            assert not stopped["active"] and stopped["pilot"]["auto_disabled"], stopped

            def dashboard_time():
                raw = docker("exec", iran, "cat", "/var/lib/neo-tunnel/controller/dashboard.json")
                return json.loads(raw)["at"]

            before_restart = dashboard_time()
            docker("exec", iran, "systemctl", "restart", "neo-watch.service")
            ready(lambda: dashboard_time() != before_restart, 30)
            after_restart = pilot_status()
            assert after_restart == stopped, after_restart
            print("PASS automatic pilot and persistent opt-out after watcher restart", flush=True)
            docker("exec", iran, "neo-tunnel", "pilot", "export")
            panel = docker("exec", iran, "curl", "-fsS", "http://127.0.0.1:8787/")
            assert 'dir="rtl"' in panel and "/report" in panel and ("TCP/TLS" in panel or "QUIC" in panel)
            report = docker("exec", iran, "tar", "-xOzf", "/var/lib/neo-tunnel/controller/pilot-report.tar.gz", "summary.json")
            assert json.loads(report)["peer_minutes"] > 0, report
            print("PASS persistent pilot, sanitized bundle and private RTL dashboard", flush=True)
            def usage():
                raw = docker("exec", iran, "systemctl", "show", "neo-dashboard.service",
                             "-p", "MemoryCurrent", "-p", "CPUUsageNSec")
                return {key: int(value) for key, value in (line.split("=") for line in raw.splitlines())}

            before, started = usage(), time.monotonic()
            for _ in range(2):
                docker("exec", iran, "curl", "-fsS", "http://127.0.0.1:8787/")
                time.sleep(5)
            after = usage()
            rss = after["MemoryCurrent"]
            cpu = (after["CPUUsageNSec"] - before["CPUUsageNSec"]) / 1e9 / (time.monotonic() - started) * 100
            assert rss < 32 << 20 and cpu < 1.0, (rss, cpu)
            print(f"PASS dashboard service budget ({rss / (1<<20):.1f} MiB, {cpu:.3f}% of one core)", flush=True)
        except Exception:
            for name in (iran, foreign):
                try:
                    output = docker("exec", name, "journalctl", "--no-pager", "-n", "85", "-u", "neo-*")
                    print(re.sub(r"(neo-tunnel://)[^'\s]+", r"\1REDACTED", output))
                except RuntimeError:
                    pass
            raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="neo-tunnel-systemd:debian13")
    parser.add_argument("--bundle", type=Path, default=Path("build/release"))
    parser.add_argument("--upgrade-from", type=Path, help="install v0.2.0 before upgrading to the new bundle")
    args = parser.parse_args()
    prior = args.upgrade_from.resolve(strict=True) if args.upgrade_from else None
    run(args.image, args.bundle.resolve(strict=True), prior)
