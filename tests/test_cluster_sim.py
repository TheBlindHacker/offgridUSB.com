"""Unit tests for the exo swarm cluster planner (F-33..F-36)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from emyrge.swarm.cluster_sim import ClusterCoordinator, DEFAULT_SWARM_NODES


def make_node(id="n1", ip="192.168.10.101", port=50052, ram_mb=8192, vram_mb=0,
              arch="x86_64", online=True, **extra):
    node = {"id": id, "name": id, "ip": ip, "port": port, "ram_mb": ram_mb,
            "vram_mb": vram_mb, "arch": arch, "online": online}
    node.update(extra)
    return node


class TestPlanClusterBasics(unittest.TestCase):
    def test_default_nodes_plan(self):
        plan = ClusterCoordinator.plan_cluster()
        self.assertEqual(plan["unlocked_tier"], 4)
        self.assertEqual(len(plan["nodes"]), 4)
        self.assertEqual(plan["fallback_status"]["state"], "HEALTHY")
        self.assertIn("llama-server", plan["rpc_command"])
        self.assertEqual(plan["exo_config"]["cluster_mode"], "exo_p2p_ring")

    def test_plan_is_deterministic(self):
        self.assertEqual(ClusterCoordinator.plan_cluster(), ClusterCoordinator.plan_cluster())

    def test_normalization_clamps_ram_and_vram(self):
        plan = ClusterCoordinator.plan_cluster([make_node(ram_mb=0, vram_mb=-5)])
        node = plan["nodes"][0]
        self.assertEqual(node["ram_mb"], 512)
        self.assertEqual(node["vram_mb"], 0)
        self.assertEqual(node["port"], 50052)

    def test_alternate_field_names(self):
        plan = ClusterCoordinator.plan_cluster([{"id": "x", "ram": 2048, "vram": 0}])
        self.assertEqual(plan["nodes"][0]["ram_mb"], 2048)


class TestTierUnlocking(unittest.TestCase):
    def test_empty_nodes_local_fallback(self):
        plan = ClusterCoordinator.plan_cluster([])
        self.assertEqual(plan["unlocked_tier"], 0)
        self.assertIn("0.5B", plan["unlocked_model"])
        self.assertEqual(plan["layer_split"], [])

    def test_all_nodes_offline_local_fallback(self):
        plan = ClusterCoordinator.plan_cluster([make_node(online=False)])
        self.assertEqual(plan["unlocked_tier"], 0)
        self.assertEqual(plan["layer_split"], [])

    def test_tier2_below_10gb(self):
        plan = ClusterCoordinator.plan_cluster([make_node(ram_mb=4096, vram_mb=4096)])
        self.assertEqual(plan["unlocked_tier"], 2)

    def test_tier3_below_42gb(self):
        plan = ClusterCoordinator.plan_cluster([make_node(ram_mb=16384, vram_mb=16384)])
        self.assertEqual(plan["unlocked_tier"], 3)

    def test_tier4_above_42gb(self):
        plan = ClusterCoordinator.plan_cluster([make_node(ram_mb=32768, vram_mb=16384)])
        self.assertEqual(plan["unlocked_tier"], 4)

    def test_metal_unified_memory_counts_vram_differently(self):
        # metal arch: effective pool = ram only; vram excluded
        plan_metal = ClusterCoordinator.plan_cluster([make_node(ram_mb=8192, vram_mb=6144, arch="macos_arm64_metal")])
        plan_x86 = ClusterCoordinator.plan_cluster([make_node(ram_mb=8192, vram_mb=6144, arch="x86_64_cuda")])
        self.assertEqual(plan_metal["effective_pool_mb"], 8192)
        self.assertEqual(plan_x86["effective_pool_mb"], 8192 + 6144)


class TestLayerSplitting(unittest.TestCase):
    def test_layers_sum_to_total(self):
        plan = ClusterCoordinator.plan_cluster(DEFAULT_SWARM_NODES)
        total = plan["exo_config"]["total_layers"]
        self.assertEqual(sum(s["layers"] for s in plan["layer_split"]), total)

    def test_layers_are_contiguous_from_zero(self):
        plan = ClusterCoordinator.plan_cluster(DEFAULT_SWARM_NODES)
        start = 0
        for s in plan["layer_split"]:
            self.assertEqual(s["start_layer"], start)
            self.assertEqual(s["end_layer"], start + s["layers"] - 1)
            self.assertEqual(s["layer_range"], f"L{start}-L{s['end_layer']}")
            start = s["end_layer"] + 1

    def test_bigger_node_gets_more_layers(self):
        plan = ClusterCoordinator.plan_cluster([make_node(id="a", ram_mb=8192),
                                                make_node(id="b", ram_mb=32768)])
        split = {s["node_id"]: s["layers"] for s in plan["layer_split"]}
        self.assertGreater(split["b"], split["a"])

    def test_offline_nodes_excluded_from_split(self):
        plan = ClusterCoordinator.plan_cluster([make_node(id="a"), make_node(id="b", online=False)])
        self.assertEqual([s["node_id"] for s in plan["layer_split"]], ["a"])

    def test_shares_sum_to_about_100(self):
        plan = ClusterCoordinator.plan_cluster(DEFAULT_SWARM_NODES)
        total_pct = sum(s["tensor_share_pct"] for s in plan["layer_split"])
        self.assertAlmostEqual(total_pct, 100.0, delta=0.5)


class TestRpcCommandGeneration(unittest.TestCase):
    def test_multi_node_rpc_lists_worker_endpoints(self):
        plan = ClusterCoordinator.plan_cluster([make_node(ip="10.0.0.1", port=50052),
                                                make_node(id="b", ip="10.0.0.2", port=50053)])
        cmd = plan["rpc_command"]
        self.assertIn("--rpc 10.0.0.2:50053", cmd)
        self.assertIn("--tensor-split", cmd)
        self.assertIn("--host 0.0.0.0", cmd)

    def test_single_node_rpc_uses_loopback(self):
        plan = ClusterCoordinator.plan_cluster([make_node()])
        self.assertIn("--host 127.0.0.1", plan["rpc_command"])
        self.assertNotIn("--rpc", plan["rpc_command"])

    def test_rpc_command_matches_layer_split(self):
        plan = ClusterCoordinator.plan_cluster(DEFAULT_SWARM_NODES)
        ratios = ",".join(str(s["layers"]) for s in plan["layer_split"])
        self.assertIn(f"--tensor-split {ratios}", plan["rpc_command"])


class TestDropFallback(unittest.TestCase):
    def test_simulate_drop_drops_last_node(self):
        plan = ClusterCoordinator.plan_cluster(DEFAULT_SWARM_NODES, simulate_drop=True)
        dropped = plan["fallback_status"]["dropped_node"]
        self.assertEqual(dropped["id"], "node-4-desktop")
        self.assertEqual(plan["fallback_status"]["state"], "DEGRADED_AUTO_RECOVERED")
        self.assertEqual(len(plan["layer_split"]), 3)
        self.assertEqual(len(plan["nodes"]), 4)  # original nodes still listed

    def test_simulate_drop_last_node_means_total_fallback(self):
        plan = ClusterCoordinator.plan_cluster([make_node(id="only")], simulate_drop=True)
        self.assertEqual(plan["fallback_status"]["state"], "LOCAL_MICRO_FALLBACK")
        self.assertEqual(plan["unlocked_tier"], 0)
        self.assertEqual(plan["layer_split"], [])


if __name__ == "__main__":
    unittest.main()
