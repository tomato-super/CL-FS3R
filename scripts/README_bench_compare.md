# Small Benchmark Compare

Script: `scripts/bench_compare.py`

用途：统一跑 `point / dcf / VB / BO` 的小规模对照实验，输出时延统计与理论通信量。

## 文档约定

- 本文件是唯一主文档。
<!-- - `scripts/benchmark_protocol.md` 已降级为跳转说明，不再单独维护。 -->

## 支持模式

- `point`
- `dcf`（脚本内映射到 `query_type=range`）
- `vb-non-fss-point`
- `vb-non-fss-range`
- `vb-fss-point`
- `vb-fss-range`
- `bo-non-fss-point`
- `bo-non-fss-range`
- `bo-fss-point`
- `bo-fss-range`

兼容别名（自动映射）：

- `dpf-vb-non-fss` -> `vb-non-fss-point`
- `dpf-vb-non-fss-point` -> `vb-non-fss-point`
- `dpf-vb-non-fss-range` -> `vb-non-fss-range`
- `dpf-vb-fss` -> `vb-fss-point`
- `dpf-vb-fss-point` -> `vb-fss-point`
- `dpf-vb-fss-range` -> `vb-fss-range`

## 关键参数

- `--exp-tag`：实验标签，参与输出目录命名。
- `--result-root`：结果根目录（默认 `<root>/result`）。
- `--modes`：模式列表。
- `--ands`：谓词个数列表。
- `--log-window-sz`、`--log-num-buckets`、`--log-block-num`：规模参数。
- `--reps`、`--warmup-runs`：测量轮次与预热轮次。
- `--restart-per-mode` / `--restart-per-run`：server 重启策略。

## 范围查询语义

- `vb-*-range` 与 `bo-*-range`：当前实现是单边范围，只支持：
- `[0, r]`（`x <= r`）
- `[l, N-1]`（`x >= l`）
- `dcf` correctness 采用脚本中的半开区间判定逻辑。

## 输出结构（CSV）

每次完整运行会创建独立目录：

- `<result-root>/<timestamp>__<exp-tag>/`

目录内文件：

- `raw.csv`：逐轮原始记录。
- `stats.csv`：分组统计汇总。
- `run_meta.json`：参数、时间、git commit、语义说明。
- `logs/`：本轮 server 日志。

`stats.csv` 重要字段：

- `n_ok`、`n_timeout`、`n_error`
- `error_types`（如 `error(1):3;error(134):1`）
- `ret_all_expected_on_ok`
- `range_semantics`
- `theory_*`（理论通信量）

## 理论通信量公式（查询阶段）

说明：仅统计 payload，不包含 gRPC 元数据与分帧开销。

统一记号：

- `FIELD_BYTES = 16`
- `NUM_SERVERS = 3`
- `window_size = 2^log_window_sz`
- `num_buckets = 2^log_num_buckets`
- `block_num = 2^log_block_num`
- `block_size = num_buckets / block_num`

统一汇总：

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
- `c2s_tx = NUM_SERVERS * num_ands * (2 * key_bytes)`
- `s2c_tx = NUM_SERVERS * FIELD_BYTES`
- `per_server_s2s = FIELD_BYTES * window_size * (2 * num_ands - 1)`

4) `bo-non-fss-point` / `bo-non-fss-range`

- `c2s_tx = NUM_SERVERS * num_ands * (2 * (block_num + block_size) * FIELD_BYTES)`
- `s2c_tx = NUM_SERVERS * FIELD_BYTES`
- `per_server_s2s = FIELD_BYTES * window_size * (4 * num_ands - 1)`

5) `bo-fss-point` / `bo-fss-range`

- `key_block_bytes = FIELD_BYTES * (log_block_num + 2)`
- `key_offset_bytes = FIELD_BYTES * ((log_num_buckets - log_block_num) + 2)`
- `c2s_tx = NUM_SERVERS * num_ands * (2 * (key_block_bytes + key_offset_bytes))`
- `s2c_tx = NUM_SERVERS * FIELD_BYTES`
- `per_server_s2s = FIELD_BYTES * window_size * (4 * num_ands - 1)`

## 运行示例

在仓库根目录执行：

```bash
python3 scripts/bench_compare.py \
  --exp-tag point_vb_bo_v1 \
  --modes point vb-non-fss-point vb-fss-point bo-non-fss-point bo-fss-point \
  --ands 1 2 4 8 \
  --reps 5 \
  --warmup-runs 1
```

单边 range 对照：

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

## 备注

- 时延 `ms` 优先解析 bench 的每轮计时行（`^\d+\s+\d+$`）。
- `vb-*` 额外保留 `seq_ms`（若日志包含对应字段）。
- 理论通信量是查询阶段 payload 估算，不包含 gRPC 元数据/分帧开销。
