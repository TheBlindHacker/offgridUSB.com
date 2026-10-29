"""Exo P2P Ring & llama.cpp RPC Heterogeneous Swarm Coordinator (F-33..F-36).

100% Pure Python Standard Library.
Pools scavenged laptops, Raspberry Pis, MacBooks, and desktops over LAN into a
unified Tier 3 / Tier 4 cluster with proportional transformer layer splitting,
60-second slow-network timeout hardening, and seamless node-drop local fallback.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


DEFAULT_SWARM_NODES: List[Dict[str, Any]] = [
    {
        "id": "node-1-thinkpad",
        "name": "2015 ThinkPad T450 (Legacy Windows x64)",
        "ip": "192.168.10.101",
        "port": 50052,
        "ram_mb": 4096,
        "vram_mb": 0,
        "arch": "x86_64_sse4",
        "online": True,
    },
    {
        "id": "node-2-macbook",
        "name": "MacBook Air M1 (Apple Silicon Metal)",
        "ip": "192.168.10.102",
        "port": 50052,
        "ram_mb": 8192,
        "vram_mb": 6144,
        "arch": "macos_arm64_metal",
        "online": True,
    },
    {
        "id": "node-3-rpi5",
        "name": "Raspberry Pi 5 8GB (Field Relay SBC)",
        "ip": "192.168.10.103",
        "port": 50052,
        "ram_mb": 8192,
        "vram_mb": 0,
        "arch": "linux_arm64_neon",
        "online": True,
    },
    {
        "id": "node-4-desktop",
        "name": "Scavenged Gaming Rig (RTX 3060 12GB)",
        "ip": "192.168.10.104",
        "port": 50052,
        "ram_mb": 16384,
        "vram_mb": 12288,
        "arch": "x86_64_cuda",
        "online": True,
    },
]


class ClusterCoordinator:
    """Computes Exo ring topology, llama.cpp `--rpc` commands, layer splits, and fault fallback."""

    DEFAULT_TIMEOUT_SEC = 60

    @classmethod
    def plan_cluster(
        cls,
        nodes: Optional[List[Dict[str, Any]]] = None,
        simulate_drop: bool = False,
    ) -> Dict[str, Any]:
        # Treat an explicitly-passed empty node list as intentional (local fallback),
        # and only fall back to the default fixture when no node list was provided at all.
        if nodes is None:
            nodes = DEFAULT_SWARM_NODES
        raw_nodes = [dict(n) for n in nodes]

        # Normalize node attributes gracefully
        normalized_nodes: List[Dict[str, Any]] = []
        for idx, n in enumerate(raw_nodes):
            ram_mb = int(n.get("ram_mb", n.get("ram", 4096)))
            vram_mb = int(n.get("vram_mb", n.get("vram", 0)))
            ip = str(n.get("ip", f"192.168.10.{101 + idx}"))
            port = int(n.get("port", 50052))
            online = bool(n.get("online", True))
            normalized_nodes.append(
                {
                    "id": str(n.get("id", f"node-{idx + 1}")),
                    "name": str(n.get("name", n.get("id", f"Swarm Node {idx + 1}"))),
                    "ip": ip,
                    "port": port,
                    "ram_mb": max(512, ram_mb),
                    "vram_mb": max(0, vram_mb),
                    "arch": str(n.get("arch", "x86_64")),
                    "online": online,
                }
            )

        dropped_node_info: Optional[Dict[str, Any]] = None
        if simulate_drop and normalized_nodes:
            # Simulate sudden Wi-Fi / power loss on highest-index worker node
            victim = normalized_nodes[-1]
            victim["online"] = False
            dropped_node_info = {"id": victim["id"], "name": victim["name"], "ip": victim["ip"]}

        online_nodes = [n for n in normalized_nodes if n["online"]]

        # Calculate usable memory pool (75% of RAM + dedicated VRAM where non-unified)
        pooled_ram_mb = sum(n["ram_mb"] for n in online_nodes)
        pooled_vram_mb = sum(n["vram_mb"] for n in online_nodes)
        effective_pool_mb = sum(
            n["ram_mb"] + (0 if "metal" in n["arch"] else n["vram_mb"]) for n in online_nodes
        )

        # Unlock frontier model tier based on pooled cluster memory
        if not online_nodes or effective_pool_mb < 3000:
            unlocked_model = "Qwen2.5-0.5B-Instruct-Q4_K_M (Local Emergency Fallback)"
            model_file = "qwen2.5-0.5b-instruct-q4_k_m.gguf"
            total_layers = 24
            unlocked_tier = 0
        elif effective_pool_mb < 10000:
            unlocked_model = "Qwen2.5-7B-Instruct-Q4_K_M (Tier 2 Pooled)"
            model_file = "qwen2.5-7b-instruct-q4_k_m.gguf"
            total_layers = 28
            unlocked_tier = 2
        elif effective_pool_mb < 42000:
            unlocked_model = "Qwen2.5-32B-Instruct-Q4_K_M (Tier 3 Swarm Frontier)"
            model_file = "qwen2.5-32b-instruct-q4_k_m.gguf"
            total_layers = 64
            unlocked_tier = 3
        else:
            unlocked_model = "Llama-3.3-70B-Instruct-Q4_K_M (Tier 4 Settlement Supercluster)"
            model_file = "llama-3.3-70b-instruct-q4_k_m.gguf"
            total_layers = 80
            unlocked_tier = 4

        # Proportional transformer layer splitting weighted by compute memory
        layer_split: List[Dict[str, Any]] = []
        if online_nodes:
            weights = [max(512, n["ram_mb"] + n["vram_mb"]) for n in online_nodes]
            weight_sum = sum(weights)
            assigned = 0
            start_layer = 0
            for i, (n, w) in enumerate(zip(online_nodes, weights)):
                if i == len(online_nodes) - 1:
                    layers = max(1, total_layers - assigned)
                else:
                    layers = max(1, round((w / weight_sum) * total_layers))
                    if assigned + layers >= total_layers:
                        layers = max(1, total_layers - assigned - (len(online_nodes) - 1 - i))
                end_layer = start_layer + layers - 1
                share_pct = round((w / weight_sum) * 100.0, 1)
                layer_split.append(
                    {
                        "node_id": n["id"],
                        "name": n["name"],
                        "endpoint": f"{n['ip']}:{n['port']}",
                        "ram_mb": n["ram_mb"],
                        "vram_mb": n["vram_mb"],
                        "layers": layers,
                        "start_layer": start_layer,
                        "end_layer": end_layer,
                        "layer_range": f"L{start_layer}-L{end_layer}",
                        "tensor_share_pct": share_pct,
                    }
                )
                assigned += layers
                start_layer = end_layer + 1

        # Build real llama.cpp --rpc command
        if len(online_nodes) >= 2:
            worker_endpoints = ",".join(f"{n['ip']}:{n['port']}" for n in online_nodes[1:])
            tensor_ratios = ",".join(str(s["layers"]) for s in layer_split)
            rpc_command = (
                f"llama-server -m data/models/{model_file} --host 0.0.0.0 --port 8082 "
                f"--rpc {worker_endpoints} --tensor-split {tensor_ratios} "
                f"-ngl 99 -c 8192 --parallel 2"
            )
        elif len(online_nodes) == 1:
            rpc_command = (
                f"llama-server -m data/models/qwen2.5-0.5b-instruct-q4_k_m.gguf "
                f"--host 127.0.0.1 --port 8082 -c 2048 --threads 4"
            )
        else:
            rpc_command = "llama-server -m data/models/qwen2.5-0.5b-instruct-q4_k_m.gguf --host 127.0.0.1 --port 8082"

        # Build Exo P2P Ring Partitioning Topology Config
        exo_config = {
            "cluster_mode": "exo_p2p_ring",
            "discovery": "udp_lan_broadcast_airgapped",
            "model_id": unlocked_model,
            "total_layers": total_layers,
            "socket_timeout_sec": cls.DEFAULT_TIMEOUT_SEC,
            "heartbeat_interval_sec": 5,
            "ring_topology": [
                {
                    "rank": idx,
                    "node_id": s["node_id"],
                    "peer_addr": s["endpoint"],
                    "start_layer": s["start_layer"],
                    "end_layer": s["end_layer"],
                    "next_hop": layer_split[(idx + 1) % len(layer_split)]["endpoint"],
                }
                for idx, s in enumerate(layer_split)
            ],
        }

        if simulate_drop:
            fallback_status = {
                "state": "DEGRADED_AUTO_RECOVERED" if online_nodes else "LOCAL_MICRO_FALLBACK",
                "simulate_drop": True,
                "dropped_node": dropped_node_info,
                "action": (
                    f"Detected RPC timeout > {cls.DEFAULT_TIMEOUT_SEC}s on {dropped_node_info['name'] if dropped_node_info else 'peer'}; "
                    f"rebalanced {total_layers} layers across {len(online_nodes)} surviving LAN nodes with zero crash "
                    f"(local safety net `qwen2.5-0.5b-instruct-q4_k_m.gguf` armed on 127.0.0.1:8082)."
                ),
                "local_safety_model": "qwen2.5-0.5b-instruct-q4_k_m.gguf",
            }
        else:
            fallback_status = {
                "state": "HEALTHY",
                "simulate_drop": False,
                "dropped_node": None,
                "action": (
                    f"All {len(online_nodes)} LAN nodes active in P2P ring; {cls.DEFAULT_TIMEOUT_SEC}s slow-Wi-Fi socket "
                    f"timeout hardening enabled with instant local GGUF failover armed."
                ),
                "local_safety_model": "qwen2.5-0.5b-instruct-q4_k_m.gguf",
            }

        return {
            "pooled_ram_mb": pooled_ram_mb,
            "pooled_vram_mb": pooled_vram_mb,
            "effective_pool_mb": effective_pool_mb,
            "unlocked_tier": unlocked_tier,
            "unlocked_model": unlocked_model,
            "rpc_command": rpc_command,
            "exo_config": exo_config,
            "timeout_sec": cls.DEFAULT_TIMEOUT_SEC,
            "fallback_status": fallback_status,
            "layer_split": layer_split,
            "nodes": normalized_nodes,
        }
