"""Live swarm runtime tests: discovery, TCP handshake, cluster formation.

Everything runs on loopback with in-process SwarmNode servers (plus one
subprocess e2e for the CLI entrypoints) — no real llama.cpp binaries needed.
"""

import json
import os
import socket
import subprocess
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from emyrge.swarm.cluster_sim import DEFAULT_SWARM_NODES
from emyrge.swarm.runtime import (
    CoordinatorDiscovery,
    CoordinatorRuntime,
    SwarmHandshakeError,
    SwarmNode,
    handshake_node,
)


def start_node(node_id, port, **kwargs):
    node = SwarmNode(node_id=node_id, port=port, **kwargs)
    node.start()
    # wait until the TCP listener accepts
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return node
        except OSError:
            time.sleep(0.05)
    node.stop()
    raise RuntimeError(f"node {node_id} never bound port {port}")


class TestHandshake(unittest.TestCase):
    def setUp(self):
        self.nodes = [start_node("n1", 50060, ram_mb=8192, rpc_port=50061)]

    def tearDown(self):
        for n in self.nodes:
            n.stop()

    def test_handshake_returns_node_inventory(self):
        node = handshake_node("127.0.0.1", 50060)
        self.assertEqual(node["id"], "n1")
        self.assertEqual(node["ram_mb"], 8192)
        self.assertEqual(node["rpc_port"], 50061)
        self.assertEqual(node["proto"], "swarm/1")

    def test_handshake_wrong_port_raises(self):
        with self.assertRaises(SwarmHandshakeError):
            handshake_node("127.0.0.1", 59999, timeout=1.0)

    def test_handshake_non_json_service_raises(self):
        garbage = socket.socket()
        garbage.bind(("127.0.0.1", 50062))
        garbage.listen(1)
        try:
            def junk():
                conn, _ = garbage.accept()
                conn.sendall(b"HELLO THERE\n")
                conn.close()
            import threading
            t = threading.Thread(target=junk, daemon=True)
            t.start()
            with self.assertRaises(SwarmHandshakeError):
                handshake_node("127.0.0.1", 50062, timeout=2.0)
        finally:
            garbage.close()


class TestDiscovery(unittest.TestCase):
    def test_udp_announce_is_discovered(self):
        node = SwarmNode(
            node_id="disc-1", port=50070, rpc_port=50071,
            discovery_target=("127.0.0.1", 50080), announce_interval=0.1,
        )
        node.start()
        disc = CoordinatorDiscovery(discovery_port=50080)
        disc.start()
        try:
            deadline = time.time() + 5
            while time.time() < deadline and not disc.snapshot():
                time.sleep(0.05)
            snap = disc.snapshot()
            self.assertEqual(len(snap), 1)
            self.assertEqual(snap[0]["id"], "disc-1")
            self.assertEqual(snap[0]["ram_mb"], 4096)
        finally:
            disc.stop()
            node.stop()

    def test_non_swarm_datagram_ignored(self):
        disc = CoordinatorDiscovery(discovery_port=50081)
        disc.start()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(b"not json", ("127.0.0.1", 50081))
            time.sleep(0.3)
            self.assertEqual(disc.snapshot(), [])
        finally:
            disc.stop()


class TestClusterFormation(unittest.TestCase):
    def setUp(self):
        self.nodes = [
            start_node("coord-a", 50090, ram_mb=16384, vram_mb=0, rpc_port=50091),
            start_node("coord-b", 50092, ram_mb=32768, vram_mb=0, rpc_port=50093),
        ]

    def tearDown(self):
        for n in self.nodes:
            n.stop()

    def test_form_cluster_via_seeds(self):
        runtime = CoordinatorRuntime()
        plan = runtime.form_cluster(
            seeds=[{"ip": "127.0.0.1", "port": 50090}, {"ip": "127.0.0.1", "port": 50092}]
        )
        self.assertTrue(plan["live"]["cluster_formed"])
        self.assertEqual(plan["live"]["verified_nodes"], ["coord-a", "coord-b"])
        self.assertEqual(len(plan["layer_split"]), 2)
        # live plan reflects actual discovered memory, not the fixture
        self.assertEqual(plan["pooled_ram_mb"], 16384 + 32768)

    def test_form_cluster_tier_from_live_memory(self):
        runtime = CoordinatorRuntime()
        plan = runtime.form_cluster(seeds=[{"ip": "127.0.0.1", "port": 50090}])
        self.assertEqual(plan["unlocked_tier"], 3)  # 16gb pooled
        self.assertEqual(len(plan["layer_split"]), 1)

    def test_dead_node_is_reported_but_does_not_crash(self):
        runtime = CoordinatorRuntime()
        plan = runtime.form_cluster(
            seeds=[{"ip": "127.0.0.1", "port": 50090}, {"ip": "127.0.0.1", "port": 59999}]
        )
        self.assertEqual(plan["live"]["verified_nodes"], ["coord-a"])
        failed = [h for h in plan["live"]["handshakes"] if not h["ok"]]
        self.assertEqual(len(failed), 1)
        self.assertIn("connect failed", failed[0]["error"])

    def test_all_dead_nodes_mean_cluster_not_formed(self):
        runtime = CoordinatorRuntime()
        plan = runtime.form_cluster(seeds=[{"ip": "127.0.0.1", "port": 59999}])
        self.assertFalse(plan["live"]["cluster_formed"])
        self.assertEqual(plan["unlocked_tier"], 0)

    def test_form_cluster_from_discovered(self):
        """Full discovery path: node announces via UDP, coordinator forms from snapshot."""
        disc = CoordinatorDiscovery(discovery_port=50097)
        disc.start()
        announcer = SwarmNode(
            node_id="disc-coord", port=50094, rpc_port=50096,
            discovery_target=("127.0.0.1", 50097), announce_interval=0.1,
        )
        announcer.start()
        try:
            deadline = time.time() + 5
            while time.time() < deadline and not disc.snapshot():
                time.sleep(0.05)
            runtime = CoordinatorRuntime()
            plan = runtime.form_cluster(discovered=disc.snapshot())
            self.assertTrue(plan["live"]["cluster_formed"])
            self.assertIn("disc-coord", plan["live"]["verified_nodes"])
        finally:
            disc.stop()
            announcer.stop()

    def test_plan_matches_static_fixture_shapes(self):
        runtime = CoordinatorRuntime()
        plan = runtime.form_cluster(
            seeds=[{"ip": "127.0.0.1", "port": 50090}, {"ip": "127.0.0.1", "port": 50092}]
        )
        # same invariants as the pure planner: contiguous layers, split sums to total
        total = plan["exo_config"]["total_layers"]
        self.assertEqual(sum(s["layers"] for s in plan["layer_split"]), total)
        self.assertIn("--rpc", plan["rpc_command"])
        self.assertIn("tensor-split", plan["rpc_command"])


class TestCliEndToEnd(unittest.TestCase):
    """Real subprocess e2e: swarm-node CLI + coordinator CLI on loopback."""

    def test_node_and_coordinate_cli(self):
        env = dict(os.environ, PYTHONPATH=os.path.join(os.path.dirname(__file__), "..", "src"))
        node_proc = subprocess.Popen(
            [sys.executable, "-m", "emyrge.swarm", "node", "--id", "cli-node", "--port", "50100",
             "--rpc-port", "50101", "--discovery-target", "127.0.0.1:50102", "--ram-mb", "8192"],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.time() + 10
            while time.time() < deadline:
                try:
                    with socket.create_connection(("127.0.0.1", 50100), timeout=0.5):
                        break
                except OSError:
                    if node_proc.poll() is not None:
                        out = node_proc.stdout.read().decode()
                        self.fail(f"node CLI died early: {out}")
                    time.sleep(0.1)
            coord = subprocess.run(
                [sys.executable, "-m", "emyrge.swarm", "coordinate", "--seed", "127.0.0.1:50100", "--json"],
                env=env, capture_output=True, timeout=30,
            )
            self.assertEqual(coord.returncode, 0, coord.stderr.decode())
            plan = json.loads(coord.stdout)
            self.assertEqual(plan["live"]["verified_nodes"], ["cli-node"])
            self.assertEqual(plan["unlocked_tier"], 2)  # 8192 pooled
        finally:
            node_proc.terminate()
            node_proc.wait(timeout=5)

    def test_coordinate_with_no_nodes_exits_nonzero(self):
        env = dict(os.environ, PYTHONPATH=os.path.join(os.path.dirname(__file__), "..", "src"))
        coord = subprocess.run(
            [sys.executable, "-m", "emyrge.swarm", "coordinate", "--seed", "127.0.0.1:59999", "--json"],
            env=env, capture_output=True, timeout=30,
        )
        self.assertEqual(coord.returncode, 1)
        plan = json.loads(coord.stdout)
        self.assertFalse(plan["live"]["cluster_formed"])


if __name__ == "__main__":
    unittest.main()
