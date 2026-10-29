"""Live swarm runtime for the exo P2P ring (F-33..F-36).

Bridges the pure-planner world of ``cluster_sim.py`` to real machines:
UDP LAN discovery, a versioned TCP swarm handshake, worker process
orchestration for llama.cpp ``--rpc`` backends, and cluster verification
that feeds live node inventory into ``ClusterCoordinator.plan_cluster()``.

100% Python Standard Library — runs on scavenged laptops, Raspberry Pis,
and macOS with zero pip dependencies.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from .cluster_sim import ClusterCoordinator

SWARM_PROTO = "swarm/1"
DEFAULT_DISCOVERY_PORT = 50051
DEFAULT_RPC_PORT = 50052
DEFAULT_HANDSHAKE_TIMEOUT = 5.0
DEFAULT_DISCOVERY_WINDOW = 3.0
ANNOUNCE_INTERVAL_SEC = 1.0


class SwarmError(Exception):
    """Base class for swarm runtime failures."""


class SwarmHandshakeError(SwarmError):
    """A node failed the TCP swarm handshake (offline, wrong proto, timeout)."""


class SwarmWorkerError(SwarmError):
    """A llama.cpp RPC worker failed to start or open its port."""


def _json_line_send(sock: socket.socket, payload: Dict[str, Any]) -> None:
    sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))


def _json_line_recv(sock: socket.socket, timeout: float) -> Dict[str, Any]:
    sock.settimeout(timeout)
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 65536:
            raise SwarmHandshakeError("handshake reply exceeded 64KB")
    if not buf.strip():
        raise SwarmHandshakeError("connection closed before handshake reply")
    try:
        return json.loads(buf.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise SwarmHandshakeError(f"malformed handshake reply: {exc}") from exc


class SwarmNode:
    """A single swarm node: UDP announcer + TCP handshake responder.

    Run one per machine (or several on loopback for testing):
        python -m emyrge.swarm node --port 50052 --rpc-port 50053 ...
    """

    def __init__(
        self,
        node_id: str,
        port: int,
        rpc_port: int = DEFAULT_RPC_PORT,
        ram_mb: int = 4096,
        vram_mb: int = 0,
        arch: str = "x86_64",
        discovery_target: Tuple[str, int] = ("255.255.255.255", DEFAULT_DISCOVERY_PORT),
        announce_interval: float = ANNOUNCE_INTERVAL_SEC,
    ) -> None:
        self.node_id = node_id
        self.port = port
        self.rpc_port = rpc_port
        self.ram_mb = ram_mb
        self.vram_mb = vram_mb
        self.arch = arch
        self.discovery_target = discovery_target
        self.announce_interval = announce_interval
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []
        self._udp_sock: Optional[socket.socket] = None
        self._tcp_sock: Optional[socket.socket] = None

    # -- info --------------------------------------------------------------

    def info(self) -> Dict[str, Any]:
        return {
            "id": self.node_id,
            "name": self.node_id,
            "ip": "127.0.0.1",  # replaced by observed source IP on the coordinator side
            "port": self.port,
            "rpc_port": self.rpc_port,
            "ram_mb": self.ram_mb,
            "vram_mb": self.vram_mb,
            "arch": self.arch,
            "proto": SWARM_PROTO,
        }

    # -- announce thread -----------------------------------------------------

    def _announce_loop(self, stop_evt: threading.Event) -> None:
        payload = json.dumps({"type": "announce", **self.info()}).encode("utf-8")
        while not stop_evt.is_set():
            try:
                if self._udp_sock is None:
                    self._udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    self._udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                self._udp_sock.sendto(payload, self.discovery_target)
            except OSError:
                pass  # discovery target unreachable — node keeps serving TCP regardless
            stop_evt.wait(self.announce_interval)

    # -- tcp responder -------------------------------------------------------

    def _handle_connection(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        with conn:
            try:
                hello = _json_line_recv(conn, DEFAULT_HANDSHAKE_TIMEOUT)
                if hello.get("proto") != SWARM_PROTO:
                    _json_line_send(conn, {"error": f"unsupported proto: {hello.get('proto')}"})
                    return
                _json_line_send(conn, {"proto": SWARM_PROTO, "node": self.info()})
            except (SwarmHandshakeError, OSError):
                pass

    def _tcp_loop(self, stop_evt: threading.Event) -> None:
        assert self._tcp_sock is not None
        self._tcp_sock.listen(8)
        self._tcp_sock.settimeout(0.5)
        while not stop_evt.is_set():
            try:
                conn, addr = self._tcp_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._handle_connection, args=(conn, addr), daemon=True)
            t.start()

    # -- lifecycle -----------------------------------------------------------

    def start(self) -> None:
        stop_evt = self._stop
        threads = [
            threading.Thread(target=self._announce_loop, args=(stop_evt,), daemon=True),
            threading.Thread(target=self._tcp_loop, args=(stop_evt,), daemon=True),
        ]
        # bind on the calling thread so callers can connect immediately after start()
        self._tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._tcp_sock.bind(("0.0.0.0", self.port))
        self._threads = threads
        for t in threads:
            t.start()

    def stop(self) -> None:
        self._stop.set()
        for sock in (self._tcp_sock, self._udp_sock):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        # joining guarantees the listening fd is fully released before we return,
        # so an immediate re-bind of the same port can't hit EADDRINUSE
        for t in self._threads:
            t.join(timeout=2.0)

    def __enter__(self) -> "SwarmNode":
        self.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop()


class CoordinatorDiscovery:
    """Listens for UDP swarm announces and tracks live nodes."""

    def __init__(self, discovery_port: int = DEFAULT_DISCOVERY_PORT) -> None:
        self.discovery_port = discovery_port
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("0.0.0.0", discovery_port))
        self._sock.settimeout(0.5)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._listen_loop, daemon=True)

    def _listen_loop(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(8192)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                msg = json.loads(data.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue
            if msg.get("type") != "announce" or msg.get("proto") != SWARM_PROTO:
                continue
            node = dict(msg)
            node["ip"] = addr[0]  # announce origin is authoritative
            with self._lock:
                self.nodes[node["id"]] = node

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass

    def snapshot(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(n) for n in self.nodes.values()]


def handshake_node(ip: str, port: int, timeout: float = DEFAULT_HANDSHAKE_TIMEOUT) -> Dict[str, Any]:
    """Perform the TCP swarm handshake with a node; return its inventory dict.

    Raises SwarmHandshakeError on any failure (refused, timeout, bad proto).
    """
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except OSError as exc:
        raise SwarmHandshakeError(f"{ip}:{port} connect failed: {exc}") from exc
    with sock:
        try:
            _json_line_send(sock, {"proto": SWARM_PROTO, "role": "coordinator"})
            reply = _json_line_recv(sock, timeout)
        except OSError as exc:
            raise SwarmHandshakeError(f"{ip}:{port} io error: {exc}") from exc
    if reply.get("proto") != SWARM_PROTO or "node" not in reply:
        raise SwarmHandshakeError(f"{ip}:{port} bad handshake reply: {reply.get('error', reply)}")
    node = dict(reply["node"])
    node["ip"] = ip
    return node


class RpcWorkerLauncher:
    """Launches llama.cpp ``llama-rpc-server`` workers for cluster backends.

    Accepts a custom ``worker_cmd`` (defaults to ``llama-rpc-server`` on PATH)
    so the harness can substitute a stub binary for loopback testing.
    """

    def __init__(
        self,
        worker_cmd: Optional[str] = None,
        readiness_probe: Optional[Callable[[int, float], bool]] = None,
        startup_timeout: float = 10.0,
    ) -> None:
        self.worker_cmd = worker_cmd or shutil.which("llama-rpc-server") or "llama-rpc-server"
        self.readiness_probe = readiness_probe or self._port_open_probe
        self.startup_timeout = startup_timeout
        self.procs: List[subprocess.Popen] = []

    @staticmethod
    def _port_open_probe(port: int, timeout: float) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1.0):
                    return True
            except OSError:
                time.sleep(0.1)
        return False

    def launch(self, port: int, extra_args: Optional[List[str]] = None) -> subprocess.Popen:
        args = [self.worker_cmd, "--host", "127.0.0.1", "--port", str(port)]
        if extra_args:
            args += extra_args
        try:
            proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError as exc:
            raise SwarmWorkerError(f"failed to spawn worker on port {port}: {exc}") from exc
        self.procs.append(proc)
        if not self.readiness_probe(port, self.startup_timeout):
            self.terminate()
            raise SwarmWorkerError(f"worker on port {port} never opened its port")
        return proc

    def terminate(self) -> None:
        for proc in self.procs:
            if proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    try:
                        proc.kill()
                    except OSError:
                        pass
        self.procs = []


class CoordinatorRuntime:
    """Forms a live cluster: discover (or seed) → handshake → plan → verify."""

    def __init__(
        self,
        handshake_timeout: float = DEFAULT_HANDSHAKE_TIMEOUT,
        worker_launcher: Optional[RpcWorkerLauncher] = None,
        launch_workers: bool = False,
    ) -> None:
        self.handshake_timeout = handshake_timeout
        self.launch_workers = launch_workers
        self.worker_launcher = worker_launcher or RpcWorkerLauncher()
        self.launcher_owned = worker_launcher is None

    def form_cluster(
        self,
        seeds: Optional[List[Dict[str, Any]]] = None,
        discovered: Optional[List[Dict[str, Any]]] = None,
        simulate_drop: bool = False,
    ) -> Dict[str, Any]:
        """Handshake each seed/discovered node, keep survivors, plan the cluster.

        ``seeds`` are ip/port specs; ``discovered`` are announce dicts from
        CoordinatorDiscovery. Returns the planner plan plus live verification
        fields (handshakes, workers, verified_at).
        """
        candidates: List[Dict[str, Any]] = []
        for s in seeds or []:
            candidates.append({"ip": s["ip"], "port": int(s.get("port", DEFAULT_RPC_PORT))})
        for d in discovered or []:
            candidates.append({"ip": d["ip"], "port": int(d.get("port", DEFAULT_RPC_PORT))})

        verified: List[Dict[str, Any]] = []
        handshake_results: List[Dict[str, Any]] = []
        for c in candidates:
            try:
                node = handshake_node(c["ip"], c["port"], timeout=self.handshake_timeout)
                verified.append(node)
                handshake_results.append({"ip": c["ip"], "port": c["port"], "ok": True, "id": node.get("id")})
            except SwarmHandshakeError as exc:
                handshake_results.append({"ip": c["ip"], "port": c["port"], "ok": False, "error": str(exc)})

        workers: List[Dict[str, Any]] = []
        if self.launch_workers and verified:
            for node in verified:
                try:
                    self.worker_launcher.launch(node.get("rpc_port", DEFAULT_RPC_PORT))
                    workers.append({"node_id": node["id"], "rpc_port": node.get("rpc_port"), "ok": True})
                except SwarmWorkerError as exc:
                    workers.append({"node_id": node.get("id"), "ok": False, "error": str(exc)})

        plan = ClusterCoordinator.plan_cluster(verified, simulate_drop=simulate_drop)
        plan["live"] = {
            "handshakes": handshake_results,
            "verified_nodes": [n["id"] for n in verified],
            "workers": workers,
            "verified_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "cluster_formed": len(verified) >= 1,
        }
        return plan

    def shutdown(self) -> None:
        if self.launcher_owned:
            self.worker_launcher.terminate()


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="python -m emyrge.swarm")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_node = sub.add_parser("node", help="run a swarm node (announcer + handshake responder)")
    p_node.add_argument("--id", default=f"node-{os.getpid()}")
    p_node.add_argument("--port", type=int, default=DEFAULT_RPC_PORT)
    p_node.add_argument("--rpc-port", type=int, default=DEFAULT_RPC_PORT + 1)
    p_node.add_argument("--ram-mb", type=int, default=4096)
    p_node.add_argument("--vram-mb", type=int, default=0)
    p_node.add_argument("--arch", default="x86_64")
    p_node.add_argument("--discovery-target", default="255.255.255.255:50051")

    p_coord = sub.add_parser("coordinate", help="discover nodes and form a cluster")
    p_coord.add_argument("--discovery-port", type=int, default=DEFAULT_DISCOVERY_PORT)
    p_coord.add_argument("--window", type=float, default=DEFAULT_DISCOVERY_WINDOW)
    p_coord.add_argument("--seed", action="append", default=[], help="ip:port of a node to handshake directly")
    p_coord.add_argument("--simulate-drop", action="store_true")
    p_coord.add_argument("--json", action="store_true", help="machine-readable output only")

    args = parser.parse_args(argv)

    if args.cmd == "node":
        target = args.discovery_target.split(":")
        node = SwarmNode(
            node_id=args.id,
            port=args.port,
            rpc_port=args.rpc_port,
            ram_mb=args.ram_mb,
            vram_mb=args.vram_mb,
            arch=args.arch,
            discovery_target=(target[0], int(target[1]) if len(target) > 1 else DEFAULT_DISCOVERY_PORT),
        )
        node.start()
        print(f"swarm node {args.id} listening on 0.0.0.0:{args.port}", flush=True)
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            node.stop()
        return 0

    # coordinate
    seeds = []
    for s in args.seed:
        ip, _, port = s.partition(":")
        seeds.append({"ip": ip, "port": int(port) if port else DEFAULT_RPC_PORT})
    discovery = None
    if not seeds:
        discovery = CoordinatorDiscovery(discovery_port=args.discovery_port)
        discovery.start()
        time.sleep(args.window)
        discovered = discovery.snapshot()
        discovery.stop()
    else:
        discovered = []

    runtime = CoordinatorRuntime()
    plan = runtime.form_cluster(seeds=seeds, discovered=discovered, simulate_drop=args.simulate_drop)
    if args.json:
        print(json.dumps(plan, indent=2))
    else:
        live = plan["live"]
        print(f"cluster formed: {len(live['verified_nodes'])} node(s) verified")
        print(f"unlocked: tier {plan['unlocked_tier']} — {plan['unlocked_model']}")
        print(f"rpc command: {plan['rpc_command']}")
        for h in live["handshakes"]:
            status = "OK" if h["ok"] else f"FAIL ({h['error']})"
            print(f"  {h['ip']}:{h['port']} -> {status}")
    return 0 if plan["live"]["cluster_formed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
