#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import argparse
import csv
import json
import math
import re
import statistics
import subprocess
import time
from pathlib import Path


FIELD_BYTES = 16  # uint128_t payload width
NUM_SERVERS = 3

MODE_ALIASES = {
    "dcf": "dcf",
    "dpf-vb-non-fss": "vb-non-fss-point",
    "dpf-vb-non-fss-point": "vb-non-fss-point",
    "dpf-vb-non-fss-range": "vb-non-fss-range",
    "dpf-vb-fss": "vb-fss-point",
    "dpf-vb-fss-point": "vb-fss-point",
    "dpf-vb-fss-range": "vb-fss-range",
}
VB_NON_FSS_POINT_MODES = {"vb-non-fss-point"}
VB_NON_FSS_RANGE_MODES = {"vb-non-fss-range"}
VB_FSS_POINT_MODES = {"vb-fss-point"}
VB_FSS_RANGE_MODES = {"vb-fss-range"}
BO_NON_FSS_POINT_MODES = {"bo-non-fss-point"}
BO_NON_FSS_RANGE_MODES = {"bo-non-fss-range"}
BO_FSS_POINT_MODES = {"bo-fss-point"}
BO_FSS_RANGE_MODES = {"bo-fss-range"}
VB_MODES = VB_NON_FSS_POINT_MODES | VB_NON_FSS_RANGE_MODES | VB_FSS_POINT_MODES | VB_FSS_RANGE_MODES
BO_MODES = BO_NON_FSS_POINT_MODES | BO_NON_FSS_RANGE_MODES | BO_FSS_POINT_MODES | BO_FSS_RANGE_MODES
BLOCKNUM_MODES = VB_FSS_POINT_MODES | VB_FSS_RANGE_MODES | BO_MODES


def resolve_log_block_num(mode, log_num_buckets, log_block_num):
    if mode in BLOCKNUM_MODES:
        return log_num_buckets // 2 if log_block_num is None else log_block_num
    return None


def percentile(values, p):
    if not values:
        return float("nan")
    arr = sorted(values)
    if len(arr) == 1:
        return arr[0]
    k = (len(arr) - 1) * p
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return arr[int(k)]
    return arr[f] * (c - k) + arr[c] * (k - f)


def parse_point_output(text):
    mret = re.search(r"(?:bo\s+)?agg\s*=\s*([0-9]+)", text)
    if not mret:
        mret = re.search(r"ret\s*=\s*([0-9]+)", text)
    lines = [ln.strip() for ln in text.splitlines() if re.match(r"^\d+\s+\d+$", ln.strip())]
    ms = int(lines[-1].split()[1]) if lines else None
    ret = mret.group(1) if mret else "NA"
    m_send = re.search(r"predicate_send_ms\s*=\s*([0-9]+)", text)
    send_ms = int(m_send.group(1)) if m_send else None
    return ms, ret, None, send_ms


def parse_dcf_output(text):
    mret = re.search(r"ret\s*=\s*([0-9]+)", text)
    if not mret:
        mret = re.search(r"(?:bo\s+)?agg\s*=\s*([0-9]+)", text)
    lines = [ln.strip() for ln in text.splitlines() if re.match(r"^\d+\s+\d+$", ln.strip())]
    ms = int(lines[-1].split()[1]) if lines else None
    ret = mret.group(1) if mret else "NA"
    m_send = re.search(r"predicate_send_ms\s*=\s*([0-9]+)", text)
    send_ms = int(m_send.group(1)) if m_send else None
    return ms, ret, None, send_ms


def parse_vb_output(text):
    mret = re.search(r"ret\s*=\s*([0-9]+)", text)
    # Prefer bench-level per-run timer from results.dat printout to match DPF exactly.
    lines = [ln.strip() for ln in text.splitlines() if re.match(r"^\d+\s+\d+$", ln.strip())]
    m_full = re.search(r"VBAggQuery full RTT finish:\s*([0-9]+) millisec", text)
    m_seq = re.search(r"VBAggQuery sequential test finish:\s*([0-9]+) millisec", text)
    full = int(lines[-1].split()[1]) if lines else (int(m_full.group(1)) if m_full else None)
    seq = int(m_seq.group(1)) if m_seq else None
    ret = mret.group(1) if mret else "NA"
    m_send = re.search(r"predicate_send_ms\s*=\s*([0-9]+)", text)
    send_ms = int(m_send.group(1)) if m_send else None
    return full, ret, seq, send_ms


def table_meta_signature(mode, log_window_sz, log_num_buckets, log_block_num, malicious):
    """
    Return per-table signatures used to decide whether table re-upload is required.
    Key: logical table id used in bench.cpp.
    Val: tuple describing table features that impact server-side table layout/content.
    """
    sig = {}
    window_size = 1 << log_window_sz
    num_buckets = 1 << log_num_buckets

    def add_val(table_id):
        # benchmark payload is deterministic all-ones vector sized by window_size
        sig[table_id] = ("vallist", window_size, "all_ones_u128", bool(malicious))

    if mode in VB_NON_FSS_POINT_MODES or mode in VB_NON_FSS_RANGE_MODES:
        add_val("test_vb_vals")
        sig["test_vb_dpf"] = ("onehot", window_size, num_buckets, "all_ones_u32", bool(malicious))
    elif mode in VB_FSS_POINT_MODES or mode in VB_FSS_RANGE_MODES:
        add_val("test_vbfss_vals")
        sig["test_vbfss_tbl"] = ("onehot", window_size, num_buckets, "all_ones_u32", bool(malicious))
    elif mode in BO_NON_FSS_POINT_MODES or mode in BO_NON_FSS_RANGE_MODES:
        add_val("test_bo_vals")
        sig["test_bo_tbl"] = (
            "bo",
            window_size,
            num_buckets,
            resolve_log_block_num(mode, log_num_buckets, log_block_num),
            "all_ones_u32",
            bool(malicious),
        )
    elif mode in BO_FSS_POINT_MODES or mode in BO_FSS_RANGE_MODES:
        add_val("test_bofss_vals")
        sig["test_bofss_tbl"] = (
            "bo",
            window_size,
            num_buckets,
            resolve_log_block_num(mode, log_num_buckets, log_block_num),
            "all_ones_u32",
            bool(malicious),
        )
    elif mode == "point":
        add_val("test_vals")
        sig["test_dpf"] = ("dpf", window_size, num_buckets, "all_ones_u32", bool(malicious))
    elif mode == "dcf":
        add_val("test_vals")
        sig["test_dcf"] = ("dcf", window_size, num_buckets, "all_ones_u32", bool(malicious))
    return sig


def theoretical_query_comm_bytes(mode, num_ands, log_window_sz, log_num_buckets, log_block_num):
    """
    Query-only theoretical payload (excluding gRPC metadata/framing).
    Returned dict fields:
      c2s_tx: client -> servers bytes
      s2c_tx: servers -> client bytes
      cs_total_txrx: (c2s_tx + s2c_tx), i.e., both directions for client<->server
      s2s_tx: server -> server bytes (sum over all servers, one-way)
      s2s_rx: server <- server bytes (sum over all servers, one-way)
      s2s_total_txrx: (s2s_tx + s2s_rx)
    """
    window_size = 1 << log_window_sz
    num_buckets = 1 << log_num_buckets

    if mode in ("point", "dcf"):
        # DPF key size (non-malicious):
        # key_bytes = (depth + 1) * sizeof(block) + sizeof(uint128_t) = 16 * (depth + 2)
        key_bytes = FIELD_BYTES * (log_num_buckets + 2)
        c2s_tx = NUM_SERVERS * num_ands * (2 * key_bytes)
        s2c_tx = NUM_SERVERS * (4 * FIELD_BYTES)  # res/mac/lin_comb/lin_comb_mac
        # Per server SendMult payload:
        # RSSReshare once: num_ands * window_size elements
        # + predicate combine Multiply (num_ands - 1) times, each window_size elements
        per_server_s2s = FIELD_BYTES * window_size * (2 * num_ands - 1)
    elif mode in VB_NON_FSS_POINT_MODES or mode in VB_NON_FSS_RANGE_MODES:
        c2s_tx = NUM_SERVERS * num_ands * (2 * num_buckets * FIELD_BYTES)
        s2c_tx = NUM_SERVERS * FIELD_BYTES  # one uint128_t result per server
        # Same multiplicative structure as point path.
        per_server_s2s = FIELD_BYTES * window_size * (2 * num_ands - 1)
    elif mode in VB_FSS_POINT_MODES or mode in VB_FSS_RANGE_MODES:
        # vDPF upload follows DPF-like key transport with depth-derived key size.
        key_bytes = FIELD_BYTES * (log_num_buckets + 2)
        c2s_tx = NUM_SERVERS * num_ands * (2 * key_bytes)
        s2c_tx = NUM_SERVERS * FIELD_BYTES
        per_server_s2s = FIELD_BYTES * window_size * (2 * num_ands - 1)
    elif mode in BO_NON_FSS_POINT_MODES or mode in BO_NON_FSS_RANGE_MODES:
        log_block_num = resolve_log_block_num(mode, log_num_buckets, log_block_num)
        block_num = 1 << log_block_num
        block_size = num_buckets // block_num
        c2s_tx = NUM_SERVERS * num_ands * (2 * (block_num + block_size) * FIELD_BYTES)
        s2c_tx = NUM_SERVERS * FIELD_BYTES
        # BO path:
        #   RSSReshare for block + offset => 2 * num_ands * window_size
        #   AND(block, offset) per predicate => num_ands * window_size
        #   combine predicates => (num_ands - 1) * window_size
        per_server_s2s = FIELD_BYTES * window_size * (4 * num_ands - 1)
    elif mode in BO_FSS_POINT_MODES or mode in BO_FSS_RANGE_MODES:
        log_block_num = resolve_log_block_num(mode, log_num_buckets, log_block_num)
        # BO-FSS uploads two vDPF domains per predicate: block + offset.
        # Reuse existing DPF-like key size model used by this script.
        key_block_bytes = FIELD_BYTES * (log_block_num + 2)
        key_offset_bytes = FIELD_BYTES * ((log_num_buckets - log_block_num) + 2)
        c2s_tx = NUM_SERVERS * num_ands * (2 * (key_block_bytes + key_offset_bytes))
        s2c_tx = NUM_SERVERS * FIELD_BYTES
        per_server_s2s = FIELD_BYTES * window_size * (4 * num_ands - 1)
    else:
        return {
            "c2s_tx": None,
            "s2c_tx": None,
            "cs_total_txrx": None,
            "s2s_tx": None,
            "s2s_rx": None,
            "s2s_total_txrx": None,
        }

    s2s_tx = NUM_SERVERS * per_server_s2s
    s2s_rx = s2s_tx
    return {
        "c2s_tx": int(c2s_tx),
        "s2c_tx": int(s2c_tx),
        "cs_total_txrx": int(c2s_tx + s2c_tx),
        "s2s_tx": int(s2s_tx),
        "s2s_rx": int(s2s_rx),
        "s2s_total_txrx": int(s2s_tx + s2s_rx),
    }


def in_cyclic_range(x, left, right, n):
    if left <= right:
        return left <= x <= right
    return (left <= x < n) or (0 <= x <= right)


def in_single_sided_range(x, left, right, n):
    if n <= 0:
        return False
    last = n - 1
    if left == 0:
        return 0 <= x <= right
    if right == last:
        return left <= x <= last
    return None


def sanitize_tag(tag):
    tag = re.sub(r"[^A-Za-z0-9_-]+", "_", tag.strip())
    return tag if tag else "untagged"


def expected_ret_for_mode(
    mode,
    log_window_sz,
    log_num_buckets,
    dcf_range_left,
    dcf_range_right,
    vb_point_x,
    vb_range_left,
    vb_range_right,
    bo_point_x,
    bo_range_left,
    bo_range_right,
):
    window_size = 1 << log_window_sz
    num_buckets = 1 << log_num_buckets
    if mode == "dcf":
        # bench.cpp range condition semantics match half-open interval [left, right):
        # when left >= right, interval is empty under current path.
        selected = (dcf_range_left <= 1 < dcf_range_right)
        return str(window_size if selected else 0)
    if mode in VB_NON_FSS_POINT_MODES or mode in VB_FSS_POINT_MODES:
        selected = (vb_point_x == 1)
        return str(window_size if selected else 0)
    if mode in VB_NON_FSS_RANGE_MODES or mode in VB_FSS_RANGE_MODES:
        selected = in_single_sided_range(1, vb_range_left, vb_range_right, num_buckets)
        return str(window_size if selected is True else 0)
    if mode in BO_NON_FSS_POINT_MODES or mode in BO_FSS_POINT_MODES:
        selected = (bo_point_x == 1)
        return str(window_size if selected else 0)
    if mode in BO_NON_FSS_RANGE_MODES or mode in BO_FSS_RANGE_MODES:
        selected = in_single_sided_range(1, bo_range_left, bo_range_right, num_buckets)
        return str(window_size if selected is True else 0)
    return str(window_size)


def main():
    parser = argparse.ArgumentParser(description="Small benchmark compare for point/range query modes.")
    parser.add_argument("--root", default="/home/zhh/waldo_ex/waldo", help="Repo root path.")
    parser.add_argument("--result-root", default=None, help="Root directory for experiment outputs. Defaults to <root>/result.")
    parser.add_argument("--exp-tag", default="untagged", help="Experiment tag used in output folder name.")
    parser.add_argument(
        "--modes",
        nargs="+",
        default=["point", "dcf", "vb-non-fss-point", "vb-fss-point", "bo-non-fss-point", "bo-fss-point"],
        help="Modes to run.",
    )
    parser.add_argument("--ands", nargs="+", type=int, default=[1, 2, 4, 8], help="num_ands list.")
    parser.add_argument("--log-window-sz", nargs="+", type=int, default=[10], help="log_window_sz list.")
    parser.add_argument("--log-num-buckets", nargs="+", type=int, default=[10], help="log_num_buckets list.")
    parser.add_argument("--log-block-num", nargs="+", type=int, default=[None], help="log_block_num list (for vb-fss-* / bo-*).")
    parser.add_argument("--reps", type=int, default=5, help="Repetitions per mode/ands.")
    parser.add_argument("--timeout-sec", type=int, default=7200, help="Timeout for each bench run.")
    parser.add_argument("--warmup-runs", type=int, default=0, help="Warmup runs per mode/ands (not included in stats).")
    parser.add_argument("--vb-point-x", type=int, default=1, help="Point bucket for vb-*-point modes.")
    parser.add_argument("--dcf-range-left", type=int, default=8, help="Left boundary for dcf mode.")
    parser.add_argument("--dcf-range-right", type=int, default=4, help="Right boundary for dcf mode.")
    parser.add_argument("--vb-range-left", type=int, default=0, help="Left boundary for vb-*-range modes.")
    parser.add_argument("--vb-range-right", type=int, default=3, help="Right boundary for vb-*-range modes.")
    parser.add_argument("--bo-point-x", type=int, default=1, help="Point bucket for bo-*-point modes.")
    parser.add_argument("--bo-range-left", type=int, default=0, help="Left boundary for bo-*-range modes.")
    parser.add_argument("--bo-range-right", type=int, default=3, help="Right boundary for bo-*-range modes.")
    parser.add_argument(
        "--restart-per-run",
        action="store_true",
        help="Restart 3 servers before each warmup/measured run (cold-start style).",
    )
    parser.add_argument(
        "--restart-per-mode",
        action="store_true",
        help="Restart servers between different modes.",
    )
    parser.add_argument(
        "--resend-table-per-rep",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Force resend table for every rep/warmup. Default false: auto-resend only when table features change.",
    )
    args = parser.parse_args()
    args.modes = [MODE_ALIASES.get(m, m) for m in args.modes]

    root = Path(args.root)
    bin_dir = root / "build" / "bin"
    result_root = Path(args.result_root) if args.result_root else (root / "result")
    result_root.mkdir(exist_ok=True)
    ts = time.strftime("%Y-%m-%d_%H-%M-%S")
    exp_tag = sanitize_tag(args.exp_tag)
    run_dir = result_root / f"{ts}__{exp_tag}"
    logs = run_dir / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    raw_path = run_dir / "raw.csv"
    stats_path = run_dir / "stats.csv"
    meta_path = run_dir / "run_meta.json"
    run_start_ts = time.strftime("%Y-%m-%dT%H:%M:%S")

    base_cfg = {
        "addrs": ["127.0.0.1:12345", "127.0.0.1:12346", "127.0.0.1:12347"],
        "log_window_sz": 10,
        "log_num_buckets": 10,
        "depth": 8,
        "malicious": False,
        "reps": 1,
        "run_name": "small-compare",
        "num_searches": 0,
        "num_appends": 0,
        "seconds": 0,
        "experiment_dir": str(run_dir),
    }

    rows = []
    servers = []
    table_state = {}

    def stop_servers(active_servers):
        for p, f in active_servers:
            try:
                p.terminate()
            except Exception:
                pass
        time.sleep(1)
        for p, f in active_servers:
            if p.poll() is None:
                try:
                    p.kill()
                except Exception:
                    pass
            try:
                f.close()
            except Exception:
                pass

    def start_servers(run_tag):
        active_servers = []
        server_logs = [logs / f"small_compare_server{i}_{run_tag}.log" for i in range(3)]
        cfgs = [root / "config" / "server0.config", root / "config" / "server1.config", root / "config" / "server2.config"]
        for i, cfg in enumerate(cfgs):
            f = open(server_logs[i], "w")
            p = subprocess.Popen([str(bin_dir / "query_server"), str(cfg)], cwd=root, stdout=f, stderr=subprocess.STDOUT)
            active_servers.append((p, f))
            time.sleep(0.8)

        ready = [False, False, False]
        t0 = time.time()
        while time.time() - t0 < 60:
            for i, (p, _) in enumerate(active_servers):
                if p.poll() is not None:
                    stop_servers(active_servers)
                    raise RuntimeError(f"server_{i}_exited_early")
            for i, lf in enumerate(server_logs):
                if not ready[i] and lf.exists() and ("DONE WITH SETUP" in lf.read_text(errors="ignore")):
                    ready[i] = True
            if all(ready):
                break
            time.sleep(0.4)
        if not all(ready):
            stop_servers(active_servers)
            raise RuntimeError(f"servers_not_ready: {ready}")
        return active_servers

    def start_servers_retry(run_tag, retries=1):
        last_err = None
        for attempt in range(retries + 1):
            try:
                tag = run_tag if attempt == 0 else f"{run_tag}_retry{attempt}"
                return start_servers(tag)
            except RuntimeError as e:
                last_err = e
                time.sleep(1)
        raise last_err

    def cleanup_query_servers():
        patterns = [
            str(bin_dir / "query_server"),
            "query_server config/server",
        ]
        for pat in patterns:
            subprocess.run(["pkill", "-f", pat], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def run_one(mode, ands, log_window_sz, log_num_buckets, log_block_num, rep_tag, send_table):
        cfg = dict(base_cfg)
        # mode is script-facing label; query_type must match bench.cpp dispatch keys.
        if mode == "dcf":
            cfg["query_type"] = "range"
            cfg["dcf_range_left"] = args.dcf_range_left
            cfg["dcf_range_right"] = args.dcf_range_right
        else:
            cfg["query_type"] = mode
        cfg["num_ands"] = ands
        cfg["log_window_sz"] = log_window_sz
        cfg["log_num_buckets"] = log_num_buckets
        cfg["send_table"] = bool(send_table)
        effective_log_block_num = resolve_log_block_num(mode, log_num_buckets, log_block_num)
        if effective_log_block_num is not None:
            cfg["log_block_num"] = effective_log_block_num
        if mode in VB_NON_FSS_POINT_MODES or mode in VB_FSS_POINT_MODES:
            cfg["vb_is_point"] = True
            cfg["vb_point_x"] = args.vb_point_x
        if mode in VB_NON_FSS_RANGE_MODES or mode in VB_FSS_RANGE_MODES:
            cfg["vb_is_point"] = False
            cfg["vb_range_left"] = args.vb_range_left
            cfg["vb_range_right"] = args.vb_range_right
        if mode in BO_NON_FSS_POINT_MODES or mode in BO_FSS_POINT_MODES:
            cfg["bo_is_point"] = True
            cfg["bo_point_x"] = args.bo_point_x
        if mode in BO_NON_FSS_RANGE_MODES or mode in BO_FSS_RANGE_MODES:
            cfg["bo_is_point"] = False
            cfg["bo_range_left"] = args.bo_range_left
            cfg["bo_range_right"] = args.bo_range_right
        cfg_path = Path("/tmp") / f"waldo_small_compare_{mode}_{ands}_{rep_tag}.json"
        cfg_path.write_text(json.dumps(cfg))

        status = "ok"
        text = ""
        try:
            proc = subprocess.run(
                [str(bin_dir / "bench"), str(cfg_path)],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=args.timeout_sec,
            )
            text = proc.stdout + "\n" + proc.stderr
            if proc.returncode != 0:
                status = f"error({proc.returncode})"
        except subprocess.TimeoutExpired:
            status = "timeout"
            text = ""

        if mode == "dcf":
            ms, ret, seq_ms, pred_send_ms = parse_dcf_output(text)
        elif mode == "point" or mode in BO_MODES:
            ms, ret, seq_ms, pred_send_ms = parse_point_output(text)
        else:
            ms, ret, seq_ms, pred_send_ms = parse_vb_output(text)
        return ms, ret, seq_ms, pred_send_ms, status

    try:
        cleanup_query_servers()

        print("mode\tlog_window_sz\tlog_num_buckets\tnum_ands\trep\tsend_table\tms\tret\tseq_ms\tpred_send_ms\tstatus")
        for mode in args.modes:
            if not args.restart_per_run and args.restart_per_mode:
                if servers:
                    stop_servers(servers)
                    servers = []
                servers = start_servers_retry(f"{ts}_mode_{mode}")
                table_state.clear()
            elif not args.restart_per_run and not servers:
                servers = start_servers_retry(ts)
                table_state.clear()
            for log_window_sz in args.log_window_sz:
                for log_num_buckets in args.log_num_buckets:
                    for ands in args.ands:
                        for warmup in range(1, args.warmup_runs + 1):
                            if args.restart_per_run:
                                run_tag = f"{ts}_w_{mode}_w{log_window_sz}_b{log_num_buckets}_{ands}_{warmup}"
                                servers = start_servers_retry(run_tag)
                                table_state.clear()
                            log_block_num_list = args.log_block_num if mode in BLOCKNUM_MODES else [None]
                            for raw_log_block_num in log_block_num_list:
                                effective_log_block_num = resolve_log_block_num(mode, log_num_buckets, raw_log_block_num)
                                if args.restart_per_run or args.resend_table_per_rep:
                                    send_table = True
                                else:
                                    cur_sig = table_meta_signature(
                                        mode, log_window_sz, log_num_buckets, effective_log_block_num, base_cfg.get("malicious", False)
                                    )
                                    send_table = any(table_state.get(k) != v for k, v in cur_sig.items())
                                ms, ret, seq_ms, pred_send_ms, status = run_one(
                                    mode, ands, log_window_sz, log_num_buckets, effective_log_block_num, f"w{warmup}", send_table
                                )
                                if send_table:
                                    for k, v in table_meta_signature(
                                        mode, log_window_sz, log_num_buckets, effective_log_block_num, base_cfg.get("malicious", False)
                                    ).items():
                                        table_state[k] = v
                                print(
                                    f"{mode}\t{log_window_sz}\t{log_num_buckets}\t{ands}\twarmup-{warmup}\t{int(bool(send_table))}\t"
                                    f"{ms}\t{ret}\t{seq_ms}\t{pred_send_ms}\t{status}"
                                )
                            if args.restart_per_run:
                                stop_servers(servers)
                                servers = []
                        for rep in range(1, args.reps + 1):
                            if args.restart_per_run:
                                run_tag = f"{ts}_r_{mode}_w{log_window_sz}_b{log_num_buckets}_{ands}_{rep}"
                                servers = start_servers_retry(run_tag)
                                table_state.clear()

                            log_block_num_list = args.log_block_num if mode in BLOCKNUM_MODES else [None]
                            for raw_log_block_num in log_block_num_list:
                                effective_log_block_num = resolve_log_block_num(mode, log_num_buckets, raw_log_block_num)
                                if args.restart_per_run or args.resend_table_per_rep:
                                    send_table = True
                                else:
                                    cur_sig = table_meta_signature(
                                        mode, log_window_sz, log_num_buckets, effective_log_block_num, base_cfg.get("malicious", False)
                                    )
                                    send_table = any(table_state.get(k) != v for k, v in cur_sig.items())
                                ms, ret, seq_ms, pred_send_ms, status = run_one(
                                    mode, ands, log_window_sz, log_num_buckets, effective_log_block_num, rep, send_table
                                )
                                if send_table:
                                    for k, v in table_meta_signature(
                                        mode, log_window_sz, log_num_buckets, effective_log_block_num, base_cfg.get("malicious", False)
                                    ).items():
                                        table_state[k] = v

                                theo = theoretical_query_comm_bytes(
                                    mode=mode,
                                    num_ands=ands,
                                    log_window_sz=log_window_sz,
                                    log_num_buckets=log_num_buckets,
                                    log_block_num=effective_log_block_num,
                                )
                                rows.append(
                                    (
                                        mode,
                                        log_window_sz,
                                        log_num_buckets,
                                        effective_log_block_num,
                                        ands,
                                        rep,
                                        int(bool(send_table)),
                                        ms,
                                        ret,
                                        seq_ms,
                                        pred_send_ms,
                                        status,
                                        theo["c2s_tx"],
                                        theo["s2c_tx"],
                                        theo["cs_total_txrx"],
                                        theo["s2s_tx"],
                                        theo["s2s_rx"],
                                        theo["s2s_total_txrx"],
                                    )
                                )
                                print(
                                    f"{mode}\t{log_window_sz}\t{log_num_buckets}\t{ands}\t{rep}\t{int(bool(send_table))}\t"
                                    f"{ms}\t{ret}\t{seq_ms}\t{pred_send_ms}\t{status}"
                                )

                            if args.restart_per_run:
                                stop_servers(servers)
                                servers = []
            if not args.restart_per_run and args.restart_per_mode and servers:
                stop_servers(servers)
                servers = []
                table_state.clear()

        raw_header = [
            "mode",
            "log_window_sz",
            "log_num_buckets",
            "log_block_num",
            "num_ands",
            "rep",
            "send_table",
            "ms",
            "ret",
            "seq_ms",
            "pred_send_ms",
            "status",
            "theory_c2s_tx_B",
            "theory_s2c_tx_B",
            "theory_cs_total_txrx_B",
            "theory_s2s_tx_B",
            "theory_s2s_rx_B",
            "theory_s2s_total_txrx_B",
        ]
        with open(raw_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(raw_header)
            for row in rows:
                w.writerow(row)

        print("--- summary ---")
        print(
            "mode\tlog_window_sz\tlog_num_buckets\tlog_block_num\tnum_ands\tn_ok\tn_timeout\tn_error\terror_types\tmean\tmedian\tp95\tstd\tcv\tmin\tmax\tpred_send_mean\tpred_send_median\tpred_send_p95\tret_all_expected_on_ok\trange_semantics\t"
            "theory_c2s_tx_B\ttheory_s2c_tx_B\ttheory_cs_total_txrx_B\ttheory_s2s_tx_B\ttheory_s2s_rx_B\ttheory_s2s_total_txrx_B"
        )
        stats_header = [
            "mode",
            "log_window_sz",
            "log_num_buckets",
            "log_block_num",
            "num_ands",
            "n_ok",
            "n_timeout",
            "n_error",
            "error_types",
            "mean_ms",
            "median_ms",
            "p95_ms",
            "std_ms",
            "cv",
            "min_ms",
            "max_ms",
            "pred_send_mean_ms",
            "pred_send_median_ms",
            "pred_send_p95_ms",
            "ret_all_expected_on_ok",
            "range_semantics",
            "theory_c2s_tx_B",
            "theory_s2c_tx_B",
            "theory_cs_total_txrx_B",
            "theory_s2s_tx_B",
            "theory_s2s_rx_B",
            "theory_s2s_total_txrx_B",
        ]
        with open(stats_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(stats_header)
            for mode in args.modes:
                for log_window_sz in args.log_window_sz:
                    for log_num_buckets in args.log_num_buckets:
                        log_block_num_list = args.log_block_num if mode in BLOCKNUM_MODES else [None]
                        for raw_log_block_num in log_block_num_list:
                            effective_log_block_num = resolve_log_block_num(mode, log_num_buckets, raw_log_block_num)
                            for ands in args.ands:
                                subset = [
                                    r
                                    for r in rows
                                    if r[0] == mode
                                    and r[1] == log_window_sz
                                    and r[2] == log_num_buckets
                                    and r[3] == effective_log_block_num
                                    and r[4] == ands
                                ]
                                ts = [r[7] for r in subset if isinstance(r[7], int)]
                                n_timeout = sum(1 for r in subset if r[11] == "timeout")
                                error_statuses = [r[11] for r in subset if isinstance(r[11], str) and r[11].startswith("error(")]
                                n_error = len(error_statuses)
                                error_types_map = {}
                                for es in error_statuses:
                                    error_types_map[es] = error_types_map.get(es, 0) + 1
                                error_types = ";".join(f"{k}:{v}" for k, v in sorted(error_types_map.items())) if error_types_map else ""
                                ok_vals = [r[8] for r in subset if r[11] == "ok" and r[8] != "NA"]
                                pred_send_vals = [r[10] for r in subset if isinstance(r[10], int)]
                                expected_ret = expected_ret_for_mode(
                                    mode=mode,
                                    log_window_sz=log_window_sz,
                                    log_num_buckets=log_num_buckets,
                                    dcf_range_left=args.dcf_range_left,
                                    dcf_range_right=args.dcf_range_right,
                                    vb_point_x=args.vb_point_x,
                                    vb_range_left=args.vb_range_left,
                                    vb_range_right=args.vb_range_right,
                                    bo_point_x=args.bo_point_x,
                                    bo_range_left=args.bo_range_left,
                                    bo_range_right=args.bo_range_right,
                                )
                                ok = "YES" if ok_vals and all(v == expected_ret for v in ok_vals) else "NO"
                                theo = theoretical_query_comm_bytes(
                                    mode=mode,
                                    num_ands=ands,
                                    log_window_sz=log_window_sz,
                                    log_num_buckets=log_num_buckets,
                                    log_block_num=effective_log_block_num,
                                )
                                range_semantics = "single-sided" if (mode in VB_NON_FSS_RANGE_MODES or mode in VB_FSS_RANGE_MODES or mode in BO_NON_FSS_RANGE_MODES or mode in BO_FSS_RANGE_MODES) else ("dcf-half-open" if mode == "dcf" else "point")

                                if ts:
                                    mean = statistics.mean(ts)
                                    median = statistics.median(ts)
                                    p95 = percentile(ts, 0.95)
                                    std = statistics.pstdev(ts)
                                    cv = std / mean if mean > 0 else float("nan")
                                    mn = min(ts)
                                    mx = max(ts)
                                    if pred_send_vals:
                                        pred_send_mean = statistics.mean(pred_send_vals)
                                        pred_send_median = statistics.median(pred_send_vals)
                                        pred_send_p95 = percentile(pred_send_vals, 0.95)
                                        pred_send_mean_str = f"{pred_send_mean:.2f}"
                                        pred_send_median_str = f"{pred_send_median:.2f}"
                                        pred_send_p95_str = f"{pred_send_p95:.2f}"
                                    else:
                                        pred_send_mean_str = "NA"
                                        pred_send_median_str = "NA"
                                        pred_send_p95_str = "NA"
                                    line = (
                                        f"{mode}\t{log_window_sz}\t{log_num_buckets}\t{effective_log_block_num}\t{ands}\t{len(ts)}\t{n_timeout}\t{n_error}\t{error_types}\t"
                                        f"{mean:.2f}\t{median:.2f}\t{p95:.2f}\t{std:.2f}\t{cv:.3f}\t{mn}\t{mx}\t{pred_send_mean_str}\t{pred_send_median_str}\t{pred_send_p95_str}\t{ok}\t{range_semantics}"
                                        f"\t{theo['c2s_tx']}\t{theo['s2c_tx']}\t{theo['cs_total_txrx']}"
                                        f"\t{theo['s2s_tx']}\t{theo['s2s_rx']}\t{theo['s2s_total_txrx']}"
                                    )
                                    csv_row = [
                                        mode, log_window_sz, log_num_buckets, effective_log_block_num, ands, len(ts), n_timeout, n_error, error_types,
                                        f"{mean:.2f}", f"{median:.2f}", f"{p95:.2f}", f"{std:.2f}", f"{cv:.3f}", mn, mx,
                                        pred_send_mean_str, pred_send_median_str, pred_send_p95_str, ok, range_semantics,
                                        theo["c2s_tx"], theo["s2c_tx"], theo["cs_total_txrx"], theo["s2s_tx"], theo["s2s_rx"], theo["s2s_total_txrx"],
                                    ]
                                else:
                                    line = (
                                        f"{mode}\t{log_window_sz}\t{log_num_buckets}\t{effective_log_block_num}\t{ands}\t0\t{n_timeout}\t{n_error}\t{error_types}\t"
                                        "NA\tNA\tNA\tNA\tNA\tNA\tNA\t"
                                        f"NA\tNA\tNA\t{ok}\t{range_semantics}\t{theo['c2s_tx']}\t{theo['s2c_tx']}\t{theo['cs_total_txrx']}"
                                        f"\t{theo['s2s_tx']}\t{theo['s2s_rx']}\t{theo['s2s_total_txrx']}"
                                    )
                                    csv_row = [
                                        mode, log_window_sz, log_num_buckets, effective_log_block_num, ands, 0, n_timeout, n_error, error_types,
                                        "NA", "NA", "NA", "NA", "NA", "NA", "NA", "NA", "NA", "NA", ok, range_semantics,
                                        theo["c2s_tx"], theo["s2c_tx"], theo["cs_total_txrx"], theo["s2s_tx"], theo["s2s_rx"], theo["s2s_total_txrx"],
                                    ]

                                print(line)
                                w.writerow(csv_row)

        git_rev = "unknown"
        try:
            p = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, check=False)
            if p.returncode == 0:
                git_rev = p.stdout.strip()
        except Exception:
            pass
        meta = {
            "experiment_tag": exp_tag,
            "run_dir": str(run_dir),
            "raw_csv": str(raw_path),
            "stats_csv": str(stats_path),
            "start_time": run_start_ts,
            "end_time": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "root": str(root),
            "git_commit": git_rev,
            "args": vars(args),
            "range_semantics": {
                "vb_range": "single-sided: [0,r] or [l,N-1]",
                "bo_range": "single-sided: [0,r] or [l,N-1]",
                "dcf_range": "half-open check used in expected_ret_for_mode",
            },
        }
        meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True))

        print(f"RUN_DIR={run_dir}")
        print(f"RAW_CSV={raw_path}")
        print(f"STATS_CSV={stats_path}")
        print(f"META_JSON={meta_path}")
    finally:
        stop_servers(servers)
        cleanup_query_servers()


if __name__ == "__main__":
    main()
