"""Check real Linux cgroup samples and certificate authentication in an isolated container."""
import argparse
import contextlib
import json
import os
import ssl
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from controller_lab import management_cert
from lab import allocate_ports, loopback, prepare_credentials, start


def exercise(binary, work, stack):
    group_root = Path("/sys/fs/cgroup")
    if not Path("/.dockerenv").exists() or Path("/proc/self/cgroup").read_text().strip() != "0::/":
        raise RuntimeError("run this only inside an isolated container with a private cgroup namespace")
    siblings = group_root / "neo-lab-control"
    group = group_root / "neo-lab-tool"
    siblings.mkdir()
    group.mkdir()
    (siblings / "cgroup.procs").write_text(str(os.getpid()))
    (group_root / "cgroup.subtree_control").write_text("+cpu +memory")
    (group / "cpu.max").write_text("50000 100000")
    (group / "memory.max").write_text(str(64 << 20))
    (group / "memory.swap.max").write_text("0")
    prepare_credentials(work)
    management_cert(work)
    port, = allocate_ports(1)
    config_path = work / "agent.json"
    config_path.write_text(json.dumps({
        "listen": loopback(port),
        "state_dir": str(work / "agent"),
        "identity": {"ca": "secrets/ca.crt", "cert": "secrets/management.crt", "key": "secrets/management.key"},
        "tool_cgroup": str(group),
        "units": {},
    }))
    start(stack, work, "agent", [binary, "agent", "--config", config_path])
    tls = ssl.create_default_context(cafile=work / "secrets/ca.crt")
    # Temporary certificate fixtures created by the lab use only the required EKU and SAN.
    tls.verify_flags &= ~ssl.VERIFY_X509_STRICT
    url = f"https://{loopback(port)}/v1/resources"
    time.sleep(.5)
    try:
        with urllib.request.urlopen(url, context=tls, timeout=3):
            raise AssertionError("agent accepted a missing client certificate")
    except ssl.SSLError as exc:
        assert "certificate required" in str(exc).lower(), str(exc)
    tls.load_cert_chain(work / "secrets/primary-client.crt", work / "secrets/primary-client.key")

    def sample():
        with urllib.request.urlopen(url, context=tls, timeout=4) as response:
            return json.load(response)

    burner = start(stack, work, "cpu", [sys.executable, "-c",
        "import os,sys; open(sys.argv[1],'w').write(str(os.getpid())); exec('while True: pass')",
        group / "cgroup.procs",
    ])
    time.sleep(12)
    r = sample()
    assert r["effective_cpu"] == .5 and r["tool_cpu_seconds"] > 2 and r["tool_working_set_bytes"] > 0, r
    assert r["tool_cpu_fraction_of_effective_capacity"] > .80 and not r["baseline_ready"], r
    print("PASS authenticated agent distinguishes host load, tool CPU quota and working set", flush=True)
    burner.terminate()
    burner.wait(timeout=3)
    victim = start(stack, work, "memory", [sys.executable, "-c",
        "import os,sys; open(sys.argv[1],'w').write(str(os.getpid())); data=bytearray(b'x')*(160<<20)",
        group / "cgroup.procs",
    ])
    rc = victim.wait(timeout=10)
    assert rc == -9, (rc, (group / "memory.events").read_text())
    for _ in range(10):
        if sample()["oom_observed"]:
            print("PASS agent observes cgroup OOM while continuing to serve authenticated readings", flush=True)
            break
        time.sleep(1)
    else:
        raise AssertionError("agent missed cgroup OOM")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    args = p.parse_args()
    with tempfile.TemporaryDirectory(prefix="neo-agent-") as data:
        work = Path(data)
        try:
            with contextlib.ExitStack() as stack:
                exercise(args.binary.resolve(strict=True), work, stack)
        except Exception:
            for path in work.glob("*.log"):
                print(path.name, path.read_text(errors="replace")[-2000:])
            raise


if __name__ == "__main__":
    main()
