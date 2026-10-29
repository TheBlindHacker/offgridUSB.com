"""Zero-Dependency Air-Gapped Web Server & REST API for Project eMyrge.

100% Pure Python Standard Library (`http.server.ThreadingHTTPServer`).
Compatible with Windows Embeddable Python 3.12 (`python-3.12.8-embed-amd64`),
Linux, and macOS with zero pip packages installed.

Run via:
    python -m emyrge.web.app --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import mimetypes
import os
from pathlib import Path
import platform
import socket
import sys
import threading
import traceback
from typing import Any, Dict, List, Optional, Tuple
import urllib.parse

from emyrge.ai.model_runner import KiwixRunner, ModelRunner, probe_usb_platforms
from emyrge.calculators.electrical_formulas import ElectricalCalculator
from emyrge.calculators.medical_rehydration import MedicalCalculator
from emyrge.calculators.solar_battery import SolarCalculator
from emyrge.calculators.source_audit import CalculatorRouter, SourceAudit
from emyrge.calculators.water_purification import WaterCalculator
from emyrge.core.config import EmyrgeConfig, HardwareTier
from emyrge.core.hardware_probe import HardwareProbe
from emyrge.knowledge.grounding_harness import (
    Citation,
    CitationType,
    GroundedSource,
    GroundingHarness,
)
from emyrge.knowledge.khan_curriculum import KhanCurriculum
from emyrge.knowledge.seed_corpus import DEFAULT_KHAN_LESSONS, DEFAULT_ZIM_ARTICLES
from emyrge.knowledge.zim_reader import ZimReader
from emyrge.memory.memory_vault import MemoryVault
from emyrge.mesh.packet_chunker import PacketChunker
from emyrge.swarm.cluster_sim import ClusterCoordinator
from emyrge.vision.visual_vault import VisualVault


TIER_NAMES: Dict[int, str] = {
    -1: "Tier -1: Thin-Client / MCU Relay (<=200B Frames)",
    0: "Tier 0: Ultra-Low Spec / Browser Wasm (135M-500M Q4)",
    1: "Tier 1: Legacy 4GB SSE4.2 PC / SBC (0.5B-1.5B Q4)",
    2: "Tier 2: Modern AVX2 / Metal / CUDA PC (3B-8B Q4)",
    3: "Tier 3: Exo / llama.cpp RPC Scavenged LAN Swarm (32B)",
    4: "Tier 4: Settlement Workstation / Multi-GPU Hub (70B+)",
}

SIMULATED_PROFILES: Dict[str, Dict[str, Any]] = {
    "esp32": {
        "cpu_model": "Espressif ESP32-S3 Xtensa LX7 @ 240MHz",
        "mock": {
            "platform": "freertos",
            "os_version": "ESP-IDF v5.2",
            "arch": "unknown",
            "cpu_flags": [],
            "cpu_cores_physical": 2,
            "cpu_cores_logical": 2,
            "ram_total_mb": 8,
            "ram_free_mb": 4,
            "gpu_name": None,
            "vram_total_mb": 0,
            "is_thin_client": True,
        },
    },
    "pi_zero": {
        "cpu_model": "Broadcom BCM2710A1 Cortex-A53 ARM64 @ 1.0GHz (Pi Zero 2 W)",
        "mock": {
            "platform": "linux",
            "os_version": "Debian Bookworm Lite 6.6",
            "arch": "arm64",
            "cpu_flags": ["neon", "asimd", "crc32"],
            "cpu_cores_physical": 4,
            "cpu_cores_logical": 4,
            "ram_total_mb": 512,
            "ram_free_mb": 290,
            "gpu_name": "VideoCore IV",
            "vram_total_mb": 0,
        },
    },
    "old_laptop": {
        "cpu_model": "Intel(R) Core(TM) i3-380M @ 2.53GHz (2011 Legacy SSE4.2 — No AVX)",
        "mock": {
            "platform": "windows",
            "os_version": "Windows 10 LTSC",
            "arch": "x86_64",
            "cpu_flags": ["sse4_1", "sse4_2"],
            "cpu_cores_physical": 2,
            "cpu_cores_logical": 4,
            "ram_total_mb": 4096,
            "ram_free_mb": 2150,
            "gpu_name": "Intel HD Graphics (Ironlake)",
            "vram_total_mb": 0,
        },
    },
    "chromebook": {
        "cpu_model": "Locked School Chromebook (Air-Gapped WebAssembly Sandbox)",
        "mock": {
            "platform": "browser_wasm",
            "os_version": "ChromeOS 130 Wasm32-SIMD",
            "arch": "unknown",
            "cpu_flags": ["wasm_simd128"],
            "cpu_cores_physical": 2,
            "cpu_cores_logical": 4,
            "ram_total_mb": 2048,
            "ram_free_mb": 900,
            "gpu_name": "WebGPU / WebGL Sandbox",
            "vram_total_mb": 256,
            "is_wasm": True,
        },
    },
    "swarm": {
        "cpu_model": "4-Node Heterogeneous Exo + llama.cpp RPC LAN Cluster",
        "mock": {
            "platform": "lan_swarm",
            "os_version": "Exo P2P Ring + llama.cpp RPC",
            "arch": "x86_64",
            "cpu_flags": ["sse4_2", "avx2", "neon", "cuda", "metal"],
            "cpu_cores_physical": 18,
            "cpu_cores_logical": 32,
            "ram_total_mb": 36864,
            "ram_free_mb": 28400,
            "gpu_name": "Pooled RTX 3060 12GB + Apple M1 Metal",
            "vram_total_mb": 18432,
            "cuda_available": True,
            "metal_available": True,
            "is_swarm": True,
        },
    },
    "supercomputer": {
        "cpu_model": "AMD EPYC 9354P 32-Core + 4x NVIDIA RTX 4090 Settlement Hub",
        "mock": {
            "platform": "linux",
            "os_version": "Ubuntu 24.04 LTS Server",
            "arch": "x86_64",
            "cpu_flags": ["sse4_1", "sse4_2", "avx", "avx2", "avx512"],
            "cpu_cores_physical": 32,
            "cpu_cores_logical": 64,
            "ram_total_mb": 131072,
            "ram_free_mb": 108500,
            "gpu_name": "4x NVIDIA GeForce RTX 4090 (NVLink)",
            "vram_total_mb": 98304,
            "cuda_available": True,
        },
    },
}


def _detect_host_cpu_model() -> str:
    """Detects human-readable CPU brand string using pure stdlib."""
    if sys.platform == "win32":
        try:
            import winreg

            key_path = r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                name, _ = winreg.QueryValueEx(key, "ProcessorNameString")
                if name and str(name).strip():
                    return str(name).strip()
        except Exception:
            pass
    elif sys.platform.startswith("linux"):
        try:
            with open("/proc/cpuinfo", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.lower().startswith("model name"):
                        return line.split(":", 1)[1].strip()
        except Exception:
            pass
    proc = platform.processor()
    return proc.strip() if proc and proc.strip() else f"{platform.machine()} Processor"


def _to_float(val: Any, default: Optional[float] = None) -> Optional[float]:
    if val is None or val == "":
        return default
    try:
        return float(val)
    except (TypeError, ValueError):
        return default


def _to_bool(val: Any, default: bool = False) -> bool:
    if val is None or val == "":
        return default
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    return str(val).strip().lower() in ("1", "true", "yes", "on", "turbid", "cloudy")


# ---------------------------------------------------------------------------
# Shared Application Runtime State
# ---------------------------------------------------------------------------

class EmyrgeRuntime:
    """Centralized thread-safe orchestrator holding all eMyrge subsystems."""

    def __init__(self, config: EmyrgeConfig) -> None:
        self.config = config
        self.config.ensure_directories()

        self._lock = threading.RLock()
        self.simulated_tier: str = "auto"
        self.host_cpu_model: str = _detect_host_cpu_model()

        # Initialize Memory & Visual Vaults
        self.memory_vault = MemoryVault(db_path=self.config.vault_dir / "memory.sqlite", seed_if_empty=True)
        self.visual_vault = VisualVault(
            conn=self.memory_vault.conn,
            uploads_dir=self.config.uploads_dir,
            seed_if_empty=True,
        )

        # Initialize Offline Knowledge Readers with built-in survival & STEM seed corpus
        self.zim_reader = ZimReader(
            data_dir=self.config.zim_dir,
            fallback_articles=DEFAULT_ZIM_ARTICLES,
        )
        self.khan_curriculum = KhanCurriculum(
            db_path=self.config.data_dir / "khan_curriculum.sqlite",
            fallback_lessons=DEFAULT_KHAN_LESSONS,
        )

        # Initialize Background Kiwix (8081) and llama-server (8082) Runners
        self.kiwix_runner = KiwixRunner(project_root=self.config.project_root, host="127.0.0.1", port=8081)
        self.model_runner = ModelRunner(project_root=self.config.project_root, host="127.0.0.1", port=8082)

        # Kick off non-blocking background server discovery
        threading.Thread(target=self._background_warmup, daemon=True).start()

        # Initialize Grounding Harness
        self.harness = GroundingHarness(
            zim_reader=self.zim_reader,
            khan_curriculum=self.khan_curriculum,
            model_runner=self.model_runner,
            source_audit=SourceAudit,
            memory_db=self.memory_vault.conn,
        )

    def _background_warmup(self) -> None:
        try:
            self.kiwix_runner.ensure_started()
        except Exception:
            pass
        try:
            self.model_runner.ensure_started()
        except Exception:
            pass

    def get_active_hardware(self) -> Dict[str, Any]:
        with self._lock:
            sim = self.simulated_tier

        if sim != "auto" and sim in SIMULATED_PROFILES:
            preset = SIMULATED_PROFILES[sim]
            profile = HardwareProbe.probe_system(mock_data=preset["mock"])
            cpu_model = preset["cpu_model"]
        else:
            profile = HardwareProbe.probe_system()
            if self.config.tier_override is not None:
                profile.tier = self.config.tier_override
            cpu_model = self.host_cpu_model

        tier_int = int(profile.tier)
        flags_list = list(profile.cpu_flags.raw_flags) if profile.cpu_flags.raw_flags else [
            k for k, v in profile.cpu_flags.to_dict().items() if k != "raw_flags" and v
        ]
        strategy = HardwareProbe.get_prompting_strategy(tier_int)

        return {
            "os": f"{profile.platform} ({profile.os_version})" if profile.os_version else profile.platform,
            "platform": profile.platform,
            "arch": profile.arch.value,
            "cpu_model": cpu_model,
            "cpu_flags": flags_list,
            "cpu_cores_physical": profile.cpu_cores_physical,
            "cpu_cores_logical": profile.cpu_cores_logical,
            "ram_total_mb": profile.ram_total_mb,
            "ram_free_mb": profile.ram_free_mb,
            "gpu_name": profile.gpu_name or "CPU Vector Execution (No Discrete GPU)",
            "vram_mb": profile.vram_total_mb,
            "tier": tier_int,
            "tier_name": TIER_NAMES.get(tier_int, f"Tier {tier_int}"),
            "strategy": strategy,
            "execution_engine": profile.execution_engine.value,
            "recommended_model": profile.recommended_model_id,
            "context_window_tokens": profile.context_window_tokens,
        }

    def get_status_payload(self) -> Dict[str, Any]:
        hw = self.get_active_hardware()
        llm_st = self.model_runner.get_status()
        kiwix_st = self.kiwix_runner.get_status()
        platforms_ready = llm_st.get("platforms_ready") or probe_usb_platforms(self.config.project_root)

        return {
            "ok": True,
            "status": "ready" if (llm_st.get("llm_ready") or llm_st.get("llm_running")) else "standby",
            "hardware": hw,
            "services": {
                "llm_running": llm_st["llm_running"],
                "llm_ready": llm_st["llm_ready"],
                "llm_port": llm_st["llm_port"],
                "llm_model": llm_st["llm_model"],
                "llm_engine": llm_st["llm_engine"],
                "kiwix_running": kiwix_st["kiwix_running"],
                "kiwix_port": kiwix_st["kiwix_port"],
                "kiwix_url": kiwix_st["kiwix_url"],
                "zim_files": kiwix_st["zim_files"],
            },
            "platforms_ready": platforms_ready,
            "simulated_tier": self.simulated_tier,
        }

    def set_simulated_hardware(self, profile_name: str) -> Dict[str, Any]:
        norm = (profile_name or "auto").strip().lower()
        alias_map = {
            "auto": "auto",
            "host": "auto",
            "real": "auto",
            "esp32": "esp32",
            "mcu": "esp32",
            "thin_client": "esp32",
            "pi_zero": "pi_zero",
            "pi_zero2": "pi_zero",
            "old_laptop": "old_laptop",
            "laptop_sse4": "old_laptop",
            "legacy": "old_laptop",
            "chromebook": "chromebook",
            "wasm": "chromebook",
            "swarm": "swarm",
            "exo": "swarm",
            "supercomputer": "supercomputer",
            "workstation": "supercomputer",
        }
        chosen = alias_map.get(norm, "auto")
        with self._lock:
            self.simulated_tier = chosen
        return self.get_status_payload()

    def run_calculator(self, calc_type: str, params: Dict[str, Any]) -> Dict[str, Any]:
        ctype = (calc_type or "").strip().lower()
        p = params or {}

        if ctype == "water":
            if p.get("volume_gallons") not in (None, ""):
                try:
                    vol_gal = float(p["volume_gallons"])
                except (TypeError, ValueError):
                    raise ValueError("Water volume must be strictly positive")
                if vol_gal <= 0.0:
                    raise ValueError("Water volume must be strictly positive")
                vol = WaterCalculator.gallons_to_liters(vol_gal)
            else:
                raw_vol = p.get("volume_liters", p.get("liters", p.get("volume")))
                if raw_vol is None or raw_vol == "":
                    vol = 5.0
                else:
                    vol = _to_float(raw_vol)
                    if vol is None or vol <= 0.0:
                        raise ValueError("Water volume must be strictly positive")
            turbid = _to_bool(p.get("is_turbid", p.get("turbid", p.get("clarity"))), False)
            cloudy = _to_bool(p.get("is_cloudy", p.get("cloudy")), False)
            method = str(p.get("method") or "bleach").strip().lower()
            conc_raw = p.get("concentration_pct", p.get("concentration"))
            if conc_raw is None or conc_raw == "":
                conc = 6.0
            else:
                conc = _to_float(conc_raw)
                if conc is None or conc <= 0.0 or conc > 15.0:
                    raise ValueError("Concentration must be between 1% and 15%")
            elev = _to_float(p.get("elevation_meters", p.get("elevation")), 0.0) or 0.0
            res = WaterCalculator.calculate(
                {
                    "volume_liters": vol,
                    "is_turbid": turbid,
                    "method": method,
                    "concentration_pct": conc,
                    "elevation_meters": max(0.0, elev),
                    "is_cloudy": cloudy,
                }
            )
            res["summary"] = WaterCalculator.format_mesh_summary(res)
            return res

        if ctype == "solar":
            wh = _to_float(p.get("daily_wh", p.get("wh", p.get("load_wh"))), 600.0) or 600.0
            sys_v = _to_float(p.get("system_voltage", p.get("voltage")), 12.0) or 12.0
            dod = _to_float(p.get("dod", p.get("depth_of_discharge")), 0.8) or 0.8
            if dod > 1.0:  # Handle UI percentage input e.g. 80 -> 0.80
                dod = dod / 100.0
            days = _to_float(p.get("autonomy_days", p.get("days")), 1.0) or 1.0
            inv_eff = _to_float(p.get("inverter_eff", p.get("efficiency")), 0.90) or 0.90
            if inv_eff > 1.0:
                inv_eff = inv_eff / 100.0
            sun_h = _to_float(p.get("peak_sun_hours", p.get("sun_hours")), 4.5) or 4.5
            derate = _to_float(p.get("system_derating", p.get("derating")), 0.77) or 0.77
            if derate > 1.0:
                derate = derate / 100.0

            res = SolarCalculator.calculate_system(
                daily_wh=max(1.0, wh),
                system_voltage=max(6.0, sys_v),
                dod=min(1.0, max(0.1, dod)),
                autonomy_days=max(0.5, days),
                inverter_eff=min(1.0, max(0.1, inv_eff)),
                peak_sun_hours=max(0.5, sun_h),
                system_derating=min(1.0, max(0.1, derate)),
            )
            res["equipment"] = SolarCalculator.get_equipment_recommendations(res)
            res["summary"] = SolarCalculator.format_mesh_summary(res)
            return res

        if ctype == "medical":
            wt = _to_float(p.get("weight_kg", p.get("weight")), 15.0) or 15.0
            if p.get("weight_lbs") not in (None, ""):
                wt = MedicalCalculator.lbs_to_kg(float(p["weight_lbs"]))
            wt = min(250.0, max(2.0, wt))
            med = str(p.get("medication", p.get("drug", p.get("regimen", "ors")))).strip().lower()
            res = MedicalCalculator.calculate({"weight_kg": wt, "medication": med})
            res["summary"] = MedicalCalculator.format_mesh_summary(res)
            return res

        if ctype == "electrical":
            mode = str(p.get("mode") or "ohms_law").strip().lower()
            if mode in ("voltage_drop", "drop") or p.get("one_way_length_meters") is not None or p.get("length_meters") is not None:
                src_v = _to_float(p.get("source_voltage", p.get("voltage", p.get("v"))), 12.0) or 12.0
                curr = _to_float(p.get("current_a", p.get("current", p.get("i"))), 10.0) or 10.0
                length_m = _to_float(p.get("one_way_length_meters", p.get("length_meters", p.get("length"))), 15.0) or 15.0
                awg = str(p.get("wire_awg", p.get("awg", "10"))).strip()
                if awg:
                    res = ElectricalCalculator.calculate_voltage_drop_by_awg(
                        source_voltage=max(1.0, src_v),
                        current_a=max(0.0, curr),
                        one_way_length_meters=max(0.1, length_m),
                        wire_awg=awg if awg in ("14", "12", "10", "8", "6", "4", "2", "1/0", "2/0", "4/0") else "10",
                    )
                else:
                    r_km = _to_float(p.get("wire_resistance_ohm_per_km"), 3.277) or 3.277
                    res = ElectricalCalculator.calculate_dc_voltage_drop(
                        source_voltage=max(1.0, src_v),
                        current_a=max(0.0, curr),
                        one_way_length_meters=max(0.1, length_m),
                        wire_resistance_ohm_per_km=max(0.01, r_km),
                    )
                res["summary"] = ElectricalCalculator.format_mesh_summary(res)
                return res

            # Ohm's Law solver: ensure at least 2 parameters have safe defaults if user submits partial form
            v = _to_float(p.get("v", p.get("voltage")))
            i = _to_float(p.get("i", p.get("current", p.get("current_a"))))
            r = _to_float(p.get("r", p.get("resistance", p.get("resistance_ohm"))))
            pw = _to_float(p.get("p", p.get("power", p.get("watts"))))
            provided = [x for x in (v, i, r, pw) if x is not None and x > 0]
            if len(provided) < 2:
                if v is None:
                    v = 12.0
                if i is None and r is None and pw is None:
                    r = 4.0
                elif r is None and i is None:
                    i = 3.0
            res = ElectricalCalculator.solve_ohms_law(v=v, i=i, r=r, p=pw)
            res["summary"] = ElectricalCalculator.format_mesh_summary(res)
            return res

        raise ValueError(f"Unsupported calculator type '{calc_type}'. Expected water, solar, medical, or electrical.")

    def handle_ask(self, query: str, mode: str = "harness") -> Dict[str, Any]:
        q = (query or "").strip()
        if not q:
            return {
                "ok": False,
                "error": "Query must not be empty.",
                "answer": "Please enter a survival, medical, engineering, or STEM question.",
                "mode": mode,
            }

        hw = self.get_active_hardware()
        tier = hw["tier"]
        strategy = hw["strategy"]
        norm_mode = (mode or "harness").strip().lower()

        # 1. Retrieve GroundingHarness sources (Vault Master Notes + built-in ZIM + Khan Curriculum)
        ctx = self.harness.retrieve_context(q, limit=5)
        combined_sources: List[GroundedSource] = list(ctx.sources)

        # 2. Query Live Kiwix Server (Port 8081) for real ZIM passages (`wikipedia_en_medicine_mini`, `zimgit-water`, `zimgit-medicine`)
        live_kiwix = self.kiwix_runner.search_live(q, limit=3, fetch_body=True)
        seen_titles = {s.title.lower() for s in combined_sources}
        for k_hit in live_kiwix:
            t_low = k_hit["title"].lower()
            if t_low not in seen_titles:
                seen_titles.add(t_low)
                combined_sources.append(
                    GroundedSource(
                        source_type="zim",
                        title=k_hit["title"],
                        url_or_id=k_hit["url"],
                        snippet=k_hit["snippet"],
                        section_or_topic=k_hit["book"],
                        full_text=k_hit["full_text"],
                        score=k_hit["score"],
                    )
                )

        combined_sources.sort(key=lambda s: s.score, reverse=True)
        top_sources = combined_sources[:5]

        # 3. Auto-run Deterministic Safety Calculator if safety-critical intent detected
        calc_result: Optional[Dict[str, Any]] = None
        calc_summary: Optional[str] = None
        route_info = CalculatorRouter.analyze_query(q)
        if route_info.route != "general":
            try:
                calc_result = self.run_calculator(route_info.route, route_info.extracted_parameters)
                calc_result["calculator_type"] = route_info.route
                calc_summary = self.harness._format_calculator_context(route_info.route, calc_result)
            except Exception:
                calc_result = None

        citations = self.harness.format_citations(top_sources)
        source_dicts = [s.to_dict() for s in top_sources]
        for sd, s_obj in zip(source_dicts, top_sources):
            sd["full_text"] = s_obj.full_text or s_obj.snippet

        # 4. Direct (Zero-AI) Mode
        if norm_mode in ("direct", "non_harness"):
            if top_sources:
                lead = top_sources[0]
                cit_tag = citations[0].raw_tag if citations else ""
                ans = f"{lead.full_text or lead.snippet} {cit_tag}".strip()
                if calc_summary:
                    ans = f"{calc_summary}\n\n{ans}"
            elif calc_summary:
                ans = calc_summary
            else:
                ans = "No matching offline articles or curriculum lessons found for this query."

            audit_dict = {"is_clean": True, "flagged_claims": [], "annotated_text": ans}
            mem_id = self.memory_vault.store_interaction(
                query=q,
                answer=ans,
                citations=[c.to_dict() for c in citations],
                mode="direct",
                model_tier=tier,
                verified=True,
                needs_distillation=False,
            )
            return {
                "ok": True,
                "answer": ans,
                "annotated_answer": ans,
                "mode": "direct",
                "engine_used": "direct-zim-khan-index (0 LLM tokens)",
                "strategy": "direct_lookup",
                "citations": [c.to_dict() for c in citations],
                "sources": source_dicts,
                "calculator_result": calc_result,
                "audit": audit_dict,
                "memory_id": mem_id,
                "queued_for_distillation": False,
            }

        # 5. Grounded AI Harness Mode
        ctx_blocks: List[str] = []
        if calc_summary:
            ctx_blocks.append(f"[DETERMINISTIC SAFETY ORACLE]\n{calc_summary}")
        for s in top_sources:
            sec_str = f"#{s.section_or_topic}" if s.section_or_topic else ""
            ctx_blocks.append(f"[Source: {s.title}{sec_str}]\n{(s.full_text or s.snippet)[:600]}")
        context_blob = "\n\n".join(ctx_blocks)

        if strategy == "search_then_summarize":
            sys_prompt = (
                "You are OffGridUSB (offgridusb.com) running in SEARCH_THEN_SUMMARIZE mode for compact hardware. "
                "Summarize ONLY the verified facts and exact dosages from the Grounding Passages in 3-5 clear sentences. "
                "Include clickable citations exactly like [Source: Title#Section] or [Lesson: Subject/Topic]. Never invent numbers."
            )
        else:
            sys_prompt = (
                "You are OffGridUSB (offgridusb.com) running in multi-source TOOL_CALLING synthesis mode. "
                "Cross-reference the Deterministic Calculator Oracle, Master Field Notes, and OpenZIM / Khan passages "
                "to deliver an authoritative, step-by-step protocol with inline citations [Source: Title#Section]."
            )

        user_prompt = f"Grounding Passages:\n{context_blob}\n\nField Question: {q}\nGrounded Response:"

        # Thin-client MCU mode simulates compact packet-ready synthesis directly
        if tier == int(HardwareTier.THIN_CLIENT):
            gen_res = {
                "text": ModelRunner._deterministic_synthesis(
                    user_prompt=user_prompt,
                    fallback_sources=source_dicts,
                    calculator_summary=calc_summary,
                )[:360],
                "engine": "esp32-gateway-compact-relay",
                "live_llm": False,
            }
        else:
            gen_res = self.model_runner.complete_chat(
                system_prompt=sys_prompt,
                user_prompt=user_prompt,
                max_tokens=320,
                fallback_sources=source_dicts,
                calculator_summary=calc_summary,
            )

        draft_answer = gen_res["text"]

        # Ensure at least one verified clickable citation tag is attached
        parsed_cits = self.harness.parse_citations(draft_answer)
        if not parsed_cits and citations:
            draft_answer = f"{draft_answer.rstrip()} {citations[0].raw_tag}"
            parsed_cits = [citations[0]]
        final_cits = parsed_cits if parsed_cits else citations

        # 6. Two-Pass Numerical Safety Verification (SourceAudit)
        audit_sources = [s.full_text or s.snippet for s in top_sources]
        if calc_summary:
            audit_sources.append(calc_summary)
        audit_report = SourceAudit.audit(draft_answer, audit_sources)

        # Queue for 70B Distillation-on-Dock if running on low-spec hardware (Tier <= 1) or audit flagged discrepancy
        queue_distill = bool(
            (not audit_report.is_clean)
            or (tier <= 1 and len(q.split()) >= 6 and route_info.route in ("medical", "general"))
        )

        mem_id = self.memory_vault.store_interaction(
            query=q,
            answer=audit_report.annotated_text,
            citations=[c.to_dict() for c in final_cits],
            mode="harness",
            model_tier=tier,
            verified=audit_report.is_clean and not queue_distill,
            needs_distillation=queue_distill,
        )

        return {
            "ok": True,
            "answer": draft_answer,
            "annotated_answer": audit_report.annotated_text,
            "mode": "harness",
            "engine_used": gen_res["engine"],
            "strategy": strategy,
            "citations": [c.to_dict() for c in final_cits],
            "sources": source_dicts,
            "calculator_result": calc_result,
            "audit": audit_report.to_dict(),
            "memory_id": mem_id,
            "queued_for_distillation": queue_distill,
        }

    def handle_knowledge_search(self, query: str) -> Dict[str, Any]:
        q = (query or "").strip()
        kiwix_st = self.kiwix_runner.get_status()
        kiwix_url = kiwix_st["kiwix_url"]

        if not q:
            zim_list = [z.to_dict() for z in self.zim_reader.list_articles(limit=12)]
            khan_list = [
                {
                    "lesson_id": les.lesson_id,
                    "subject": les.subject,
                    "topic": les.topic,
                    "title": les.title,
                    "snippet": les.content[:200],
                }
                for les in self.khan_curriculum._lessons.values()
            ]
            return {
                "ok": True,
                "query": "",
                "total": len(zim_list) + len(khan_list),
                "zim_results": zim_list,
                "khan_results": khan_list,
                "kiwix_url": kiwix_url,
                "kiwix_running": kiwix_st["kiwix_running"],
            }

        # Combine live Kiwix search + built-in ZIM corpus
        zim_out: List[Dict[str, Any]] = []
        seen_titles: set[str] = set()

        for kh in self.kiwix_runner.search_live(q, limit=6, fetch_body=False):
            zim_out.append(
                {
                    "title": kh["title"],
                    "url": kh["url"],
                    "snippet": kh["snippet"],
                    "section": kh["book"],
                    "score": kh["score"],
                    "live_kiwix": True,
                }
            )
            seen_titles.add(kh["title"].lower())

        for zs in self.zim_reader.search(q, limit=6):
            if zs.title.lower() not in seen_titles:
                d = zs.to_dict()
                art = self.zim_reader.get_article(zs.url)
                if art:
                    d["full_text"] = art.text_content
                d["live_kiwix"] = False
                zim_out.append(d)

        khan_out = [ks.to_dict() for ks in self.khan_curriculum.search(q, limit=6)]
        return {
            "ok": True,
            "query": q,
            "total": len(zim_out) + len(khan_out),
            "zim_results": zim_out,
            "khan_results": khan_out,
            "kiwix_url": kiwix_url,
            "kiwix_running": kiwix_st["kiwix_running"],
        }

    def handle_mesh_command(self, command: str) -> Dict[str, Any]:
        cmd = (command or "").strip()
        if not cmd:
            cmd = "@ai emergency water bleach dose"

        lower = cmd.lower()
        if lower.startswith("@log "):
            note = cmd[5:].strip()
            self.memory_vault.store_interaction(
                query=f"[MESH FIELD LOG] {note}",
                answer=f"Logged via Tactical Relay: {note}",
                citations=[],
                mode="mesh_log",
                model_tier=-1,
                verified=True,
                needs_distillation=False,
            )
            reply = f"LOG SAVED: {note}"
        elif lower.startswith("@calc "):
            rest = cmd[6:].strip()
            kv_params: Dict[str, Any] = {}
            tokens = rest.split()
            cmd_type = tokens[0].lower() if tokens else "water"
            for t in tokens[1:]:
                if "=" in t:
                    k, v = t.split("=", 1)
                    k = k.strip().lower()
                    v = v.strip().lower()
                    if v in ("true", "yes", "1"):
                        kv_params[k] = True
                    elif v in ("false", "no", "0"):
                        kv_params[k] = False
                    else:
                        try:
                            kv_params[k] = float(v) if "." in v else int(v)
                        except ValueError:
                            kv_params[k] = v
            route_info = CalculatorRouter.analyze_query(rest)
            merged_params = dict(route_info.extracted_parameters)
            merged_params.update(kv_params)
            ctype = cmd_type if (cmd_type in ("water", "medicine", "solar", "electrical", "telecom", "structural")) else (route_info.route if route_info.route != "general" else "water")
            try:
                res = self.run_calculator(ctype, merged_params)
                reply = res.get("summary") or res.get("mesh_summary") or str(res)
            except Exception as e:
                reply = f"CALC ERR: {e}"
        else:
            q_body = cmd[4:].strip() if lower.startswith("@ai ") else cmd
            ask_res = self.handle_ask(q_body, mode="direct")
            reply = ask_res.get("answer", "")[:380]

        packets = PacketChunker.chunk_reply(reply, max_bytes=200)
        return {
            "ok": True,
            "command": cmd,
            "raw_reply": reply,
            "message": reply,
            "packets": packets,
        }


# ---------------------------------------------------------------------------
# Multi-Threaded Stdlib HTTP Request Handler
# ---------------------------------------------------------------------------

MIME_OVERRIDES: Dict[str, str] = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".mjs": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".wasm": "application/wasm",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".ico": "image/x-icon",
}


class EmyrgeHTTPHandler(BaseHTTPRequestHandler):
    """Handles REST JSON endpoints and static SPA assets with zero third-party deps."""

    runtime: EmyrgeRuntime  # Attached dynamically on server creation

    def log_message(self, format: str, *args: Any) -> None:
        # Quiet clean single-line logging; suppress noisy polling logs
        if args and isinstance(args[0], str) and "/api/status" in args[0]:
            return
        sys.stderr.write(f"[OffGridUSB HTTP] {self.address_string()} - {format % args}\n")

    def _send_cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept")
        self.send_header("Cache-Control", "no-store")

    def _send_json(self, status_code: int, payload: Dict[str, Any]) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(raw)

    def _read_json_body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(min(length, 25 * 1024 * 1024))
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8", errors="ignore"))

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        try:
            if path in ("/api/status", "/api/health", "/api/telemetry"):
                self._send_json(200, self.runtime.get_status_payload())
                return

            if path == "/api/knowledge/search":
                q = (qs.get("q") or qs.get("query") or [""])[0]
                self._send_json(200, self.runtime.handle_knowledge_search(q))
                return

            if path == "/api/knowledge/article":
                art_id = (qs.get("id") or qs.get("url") or [""])[0]
                ctype = (qs.get("type") or ["zim"])[0]
                dc = self.runtime.harness.get_direct_content(ctype, art_id)
                if dc:
                    self._send_json(200, {"ok": True, "article": dc.to_dict()})
                else:
                    self._send_json(404, {"ok": False, "error": f"Article '{art_id}' not found"})
                return

            if path == "/api/knowledge/khan":
                subjects = self.runtime.khan_curriculum.get_subjects()
                topics = [t.to_dict() for t in self.runtime.khan_curriculum.get_topics()]
                lessons = [les.to_dict() for les in self.runtime.khan_curriculum._lessons.values()]
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "subjects": subjects,
                        "topics": topics,
                        "lessons": lessons,
                    },
                )
                return

            if path in ("/api/memory", "/api/vault/search"):
                q = (qs.get("q") or qs.get("query") or [""])[0]
                search_res = self.runtime.memory_vault.search(q)
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "entries": search_res["entries"],
                        "master_notes": search_res["master_notes"],
                        "pending_count": self.runtime.memory_vault.pending_count(),
                        "fts5_enabled": self.runtime.memory_vault.fts5_available,
                    },
                )
                return

            if path == "/api/vision":
                self._send_json(200, {"ok": True, "photos": self.runtime.visual_vault.list_photos()})
                return

            if path == "/api/swarm/plan":
                plan = ClusterCoordinator.plan_cluster(simulate_drop=False)
                self._send_json(200, {"ok": True, **plan})
                return

            # Static File & Uploaded Asset Serving
            self._serve_static(path)

        except Exception as exc:
            self._send_json(500, {"ok": False, "error": str(exc), "trace": traceback.format_exc()[-400:]})

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        try:
            body = self._read_json_body()
        except Exception as exc:
            self._send_json(400, {"ok": False, "error": f"Invalid JSON request body: {exc}"})
            return

        try:
            if path == "/api/simulate-hardware":
                prof = str(body.get("profile", body.get("preset", body.get("hardware", "auto"))))
                status_payload = self.runtime.set_simulated_hardware(prof)
                self._send_json(200, status_payload)
                return

            if path in ("/api/ask", "/api/query"):
                q = str(body.get("query", body.get("q", "")))
                mode = str(body.get("mode", "harness"))
                res = self.runtime.handle_ask(q, mode=mode)
                self._send_json(200, res)
                return

            clean_path = path.rstrip("/")
            if clean_path in ("/api/calc", "/api/calculators", "/api/calculator/water_purification"):
                ctype = str(body.get("type", body.get("calculator", "water")))
                params = body.get("params") if isinstance(body.get("params"), dict) else {
                    k: v for k, v in body.items() if k not in ("type", "calculator")
                }
                try:
                    calc_res = self.runtime.run_calculator(ctype, params)
                    self._send_json(200, {"ok": True, "type": ctype, "result": calc_res})
                except ValueError as ve:
                    self._send_json(400, {"ok": False, "type": ctype, "error": str(ve)})
                return

            if path == "/api/knowledge/khan/evaluate":
                lesson_id = str(body.get("lesson_id", ""))
                ex_id = str(body.get("exercise_id", ""))
                ans = str(body.get("answer", ""))
                eval_res = self.runtime.khan_curriculum.evaluate_exercise(lesson_id, ex_id, ans)
                self._send_json(200, {"ok": True, "result": eval_res.to_dict()})
                return

            if path == "/api/memory/distill":
                distilled = self.runtime.memory_vault.run_distillation_on_dock()
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "upgraded_count": distilled["upgraded_count"],
                        "upgraded_notes": distilled["upgraded_notes"],
                        "master_notes": distilled["master_notes"],
                        "pending_count": self.runtime.memory_vault.pending_count(),
                    },
                )
                return

            if path == "/api/vision/upload":
                fname = str(body.get("filename", "field_capture.jpg"))
                b64_data = str(body.get("data_base64", body.get("data", "")))
                notes = str(body.get("notes", ""))
                if not b64_data:
                    self._send_json(400, {"ok": False, "error": "Missing 'data_base64' image payload"})
                    return
                photo = self.runtime.visual_vault.upload_base64_photo(fname, b64_data, notes=notes)
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "photo": photo,
                        "photos": self.runtime.visual_vault.list_photos(),
                    },
                )
                return

            if path == "/api/mesh/send":
                cmd = str(body.get("command", ""))
                self._send_json(200, self.runtime.handle_mesh_command(cmd))
                return

            if path == "/api/swarm/plan":
                nodes = body.get("nodes") if isinstance(body.get("nodes"), list) else None
                sim_drop = _to_bool(body.get("simulate_drop"), False)
                plan = ClusterCoordinator.plan_cluster(nodes=nodes, simulate_drop=sim_drop)
                self._send_json(200, {"ok": True, **plan})
                return

            self._send_json(404, {"ok": False, "error": f"Unknown POST endpoint: {path}"})

        except Exception as exc:
            self._send_json(500, {"ok": False, "error": str(exc), "trace": traceback.format_exc()[-400:]})

    def _serve_static(self, req_path: str) -> None:
        static_root = self.runtime.config.static_dir.resolve()
        uploads_root = self.runtime.config.uploads_dir.resolve()

        # Uploaded visual vault images (`/uploads/<name>`)
        if req_path.startswith("/uploads/"):
            rel_up = req_path[len("/uploads/"):].lstrip("/")
            candidate = (uploads_root / rel_up).resolve()
            if str(candidate).startswith(str(uploads_root)) and candidate.is_file():
                self._stream_file(candidate)
                return
            self._send_json(404, {"ok": False, "error": "Uploaded file not found"})
            return

        # Normalize `/` -> `index.html` (or fallback to `wasm/chromebook.html` if index.html isn't staged yet)
        clean_rel = req_path.lstrip("/")
        if clean_rel.startswith("static/"):
            clean_rel = clean_rel[len("static/"):]

        if clean_rel == "" or clean_rel == "index.html":
            idx_file = static_root / "index.html"
            if idx_file.is_file():
                self._stream_file(idx_file)
                return
            wasm_fallback = static_root / "wasm" / "chromebook.html"
            if wasm_fallback.is_file():
                self._stream_file(wasm_fallback)
                return

        candidate = (static_root / clean_rel).resolve()
        if str(candidate).startswith(str(static_root)) and candidate.is_file():
            self._stream_file(candidate)
            return

        self._send_json(404, {"ok": False, "error": f"Path not found: {req_path}"})

    def _stream_file(self, file_path: Path) -> None:
        ext = file_path.suffix.lower()
        mime = MIME_OVERRIDES.get(ext) or mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
        data = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(data)


class ReusableThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def create_server(config: Optional[EmyrgeConfig] = None) -> Tuple[ReusableThreadingHTTPServer, EmyrgeRuntime]:
    cfg = config or EmyrgeConfig.from_env()
    runtime = EmyrgeRuntime(cfg)

    class BoundHandler(EmyrgeHTTPHandler):
        pass

    BoundHandler.runtime = runtime
    server = ReusableThreadingHTTPServer((cfg.host, cfg.port), BoundHandler)
    return server, runtime


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="OffGridUSB (offgridusb.com) Zero-Dependency HTTP Backend")
    parser.add_argument("--host", default=os.environ.get("EMYRGE_HOST", "127.0.0.1"), help="Bind host address")
    parser.add_argument("--port", type=int, default=int(os.environ.get("EMYRGE_PORT", "8000")), help="Bind TCP port")
    parser.add_argument("--headless", action="store_true", help="Headless server mode")
    parser.add_argument("--tier", type=int, default=None, help="Optional hardware tier override (-1..4)")
    args, _ = parser.parse_known_args(argv)

    base_cfg = EmyrgeConfig.from_env()
    base_cfg.host = args.host
    base_cfg.port = args.port
    if args.headless:
        base_cfg.headless = True
    if args.tier is not None:
        base_cfg.tier_override = HardwareTier(args.tier)

    try:
        server, runtime = create_server(base_cfg)
    except OSError as e:
        sys.stderr.write(
            f"[ERROR] Failed to bind {base_cfg.host}:{base_cfg.port} ({e}). "
            f"Try specifying a free port with --port <PORT>.\n"
        )
        return 1

    st = runtime.get_status_payload()
    hw = st["hardware"]
    print(f"[OffGridUSB] Air-Gapped Backend Ready -> http://{base_cfg.host}:{base_cfg.port}")
    print(f"[OffGridUSB] Detected Hardware: {hw['cpu_model']} | RAM: {hw['ram_total_mb']} MB | {hw['tier_name']}")
    print(f"[OffGridUSB] Kiwix (8081): {'ONLINE' if st['services']['kiwix_running'] else 'STANDBY'} | LLM (8082): {st['services']['llm_model']}")
    sys.stdout.flush()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[OffGridUSB] Shutting down cleanly...")
    finally:
        server.server_close()
        runtime.model_runner.stop()
        runtime.kiwix_runner.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
