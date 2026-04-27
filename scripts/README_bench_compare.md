# Small Benchmark Compare

Script: `scripts/bench_compare.py`

Purpose: run unified small-scale comparison experiments for `point / dcf / VB / BO`,
and output latency statistics plus theoretical communication cost.

## Document Convention

- This file is the single source of truth for benchmark usage.
<!-- - `scripts/benchmark_protocol.md` has been deprecated to a redirect note and is no longer maintained separately. -->

## Supported Modes

- `point`
- `dcf` (mapped internally to `query_type=range`)
- `vb-non-fss-point`
- `vb-non-fss-range`
- `vb-fss-point`
- `vb-fss-range`
- `bo-non-fss-point`
- `bo-non-fss-range`
- `bo-fss-point`
- `bo-fss-range`

Compatible aliases (auto-mapped):

- `dpf-vb-non-fss` -> `vb-non-fss-point`
- `dpf-vb-non-fss-point` -> `vb-non-fss-point`
- `dpf-vb-non-fss-range` -> `vb-non-fss-range`
- `dpf-vb-fss` -> `vb-fss-point`
- `dpf-vb-fss-point` -> `vb-fss-point`
- `dpf-vb-fss-range` -> `vb-fss-range`

## Key Parameters

- `--exp-tag`: experiment tag used in output directory naming.
- `--result-root`: root directory for outputs (default: `<root>/result`).
- `--modes`: mode list.
- `--ands`: list of predicate counts.
- `--log-window-sz`, `--log-num-buckets`, `--log-block-num`: scale parameters.
- `--reps`, `--warmup-runs`: measurement repetitions and warmup rounds.
- `--restart-per-mode` / `--restart-per-run`: server restart strategy.

## Range Query Semantics

- For `vb-*-range` and `bo-*-range`, current implementation is single-sided range only:
- `[0, r]` (`x <= r`)
- `[l, N-1]` (`x >= l`)
- `dcf` correctness uses the half-open interval logic implemented in the script.

## Output Structure (CSV)

Each complete run creates a separate directory:

- `<result-root>/<timestamp>__<exp-tag>/`

Files in that directory:

- `raw.csv`: per-run raw records.
- `stats.csv`: grouped summary statistics.
- `run_meta.json`: parameters, timestamps, git commit, and semantics notes.
- `logs/`: server logs for this run.

Important columns in `stats.csv`:

- `n_ok`, `n_timeout`, `n_error`
- `error_types` (for example: `error(1):3;error(134):1`)
- `ret_all_expected_on_ok`
- `range_semantics`
- `theory_*` (theoretical communication metrics)

## Theoretical Communication Formulas (Query Phase)

Note: payload-only accounting; gRPC metadata/framing overhead is excluded.

Shared notation:

- `FIELD_BYTES = 16`
- `NUM_SERVERS = 3`
- `window_size = 2^log_window_sz`
- `num_buckets = 2^log_num_buckets`
- `block_num = 2^log_block_num`
- `block_size = num_buckets / block_num`
- `leaves_per_pred = 1` for point modes.
- `leaves_per_pred = 2` for single-sided range in `vb-fss-range / bo-non-fss-range / bo-fss-range`.

Shared aggregates:

- `s2s_tx = NUM_SERVERS * per_server_s2s`
- `s2s_rx = s2s_tx`
- `cs_total_txrx = c2s_tx + s2c_tx`
- `s2s_total_txrx = s2s_tx + s2s_rx`

1) `point` / `dcf`

- `key_bytes = FIELD_BYTES * (log_num_buckets + 2)`
- `c2s_tx = NUM_SERVERS * num_ands * (2 * key_bytes)`
- `s2c_tx = NUM_SERVERS * (4 * FIELD_BYTES)`
- `per_server_s2s = FIELD_BYTES * window_size * (2 * num_ands - 1)`

2) `vb-non-fss-point` / `vb-non-fss-range`

- `c2s_tx = NUM_SERVERS * num_ands * (2 * num_buckets * FIELD_BYTES)`
- `s2c_tx = NUM_SERVERS * FIELD_BYTES`
- `per_server_s2s = FIELD_BYTES * window_size * (2 * num_ands - 1)`

3) `vb-fss-point` / `vb-fss-range`

- `key_bytes = FIELD_BYTES * (log_num_buckets + 2)`
- `c2s_tx = NUM_SERVERS * num_ands * leaves_per_pred * (2 * key_bytes)`
- `s2c_tx = NUM_SERVERS * FIELD_BYTES`
- `per_server_s2s = FIELD_BYTES * window_size * (2 * num_ands - 1)`

4) `bo-non-fss-point` / `bo-non-fss-range`

- `c2s_tx = NUM_SERVERS * num_ands * leaves_per_pred * (2 * (block_num + block_size) * FIELD_BYTES)`
- `s2c_tx = NUM_SERVERS * FIELD_BYTES`
- `per_server_s2s = FIELD_BYTES * window_size * (4 * num_ands * leaves_per_pred - 1)`

5) `bo-fss-point` / `bo-fss-range`

- `key_block_bytes = FIELD_BYTES * (log_block_num + 2)`
- `key_offset_bytes = FIELD_BYTES * ((log_num_buckets - log_block_num) + 2)`
- `c2s_tx = NUM_SERVERS * num_ands * leaves_per_pred * (2 * (key_block_bytes + key_offset_bytes))`
- `s2c_tx = NUM_SERVERS * FIELD_BYTES`
- `per_server_s2s = FIELD_BYTES * window_size * (4 * num_ands * leaves_per_pred - 1)`

## Run Examples

Run from repository root:

```bash
python3 scripts/bench_compare.py \
  --exp-tag point_vb_bo_v1 \
  --modes point vb-non-fss-point vb-fss-point bo-non-fss-point bo-fss-point \
  --ands 1 2 4 8 \
  --reps 5 \
  --warmup-runs 1
```

Single-sided range comparison:

```bash
python3 scripts/bench_compare.py \
  --exp-tag singlesided_range_v1 \
  --modes dcf vb-non-fss-range vb-fss-range bo-non-fss-range bo-fss-range \
  --ands 2 4 8 \
  --vb-range-left 0 --vb-range-right 3 \
  --bo-range-left 0 --bo-range-right 3 \
  --reps 5 \
  --warmup-runs 1
```

## Notes

- Latency `ms` is primarily parsed from per-run bench timing lines (`^\d+\s+\d+$`).
- `vb-*` keeps `seq_ms` when that field is present in logs.
- The theoretical communication values estimate query-phase payload only, excluding
  gRPC metadata/framing overhead.
