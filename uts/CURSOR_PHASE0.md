# TASK: Implement Phase 0 (NS-3 topology + normal-traffic baseline dataset)

You are working inside a local NS-3 workspace on Ubuntu. Implement everything below end to end: write the code, build it, run it, fix errors, and verify. Do not stop to ask questions. When something is ambiguous, choose the simplest option and record the assumption in `README.md`.

## 0. Project context

Research project: AI-driven adaptive security for secure data dissemination (ML risk scoring in later phases, RL decision engine after that). **Phase 0 only** builds a validated topology and a baseline dataset of **normal traffic**.

Out of scope (do NOT implement): attacks, ML, RL, mitigation, ns3-gym. But keep the design extensible so Phase 1 can add an `AttackerApp` without modifying the sender/receiver classes.

## 1. Before writing code

1. Locate the NS-3 root (directory containing `ns3` or `waf`, and `scratch/`). Run `./ns3 --version` (or equivalent) and record the version in `README.md`.
2. Use only APIs that exist in the detected version. Use `./ns3 build` if the `ns3` script exists, otherwise `./waf`.
3. Python deps: `pandas`, `numpy`, `matplotlib`. Install into a venv if missing.

## 2. Topology (must match exactly)

Star topology with a switch in the middle, 7 NS-3 nodes in total:

| Node | Role | Phase 0 behavior |
|---|---|---|
| 0 | Sender | Sends data |
| 1-4 | Receivers | Receive and log data |
| 5 | Attacker | Created, has IP, **sends nothing** |
| 6 | Switch | `BridgeNetDevice`, no IP |

- Each of nodes 0-5 has its own `CsmaHelper` link to the bridge (six point-to-switch links, NOT one shared CSMA channel).
- Nodes 0-5 share subnet `10.1.1.0/24`.
- Link `DataRate` default `100Mbps`, `Delay` default `2us`, MTU 1500. Both must be CLI parameters (the final link capacity for attack phases is still undecided).
- All traffic uses UDP port **9000**.

## 3. Application layer (custom, do not use OnOff/UdpEcho)

### 3.1 `DissHeader` (subclass of `ns3::Header`)

| Field | Type | Meaning |
|---|---|---|
| `seq` | uint32 | Packet sequence number |
| `txTimeNs` | uint64 | Send time in ns (`Simulator::Now()`) |
| `claimedId` | uint16 | Claimed sender ID (Phase 0: always 0) |
| `authTag` | uint32 | `fnv1a32(seq | claimedId | SECRET)` with a shared constant `SECRET` |

Implement `GetTypeId`, `GetSerializedSize`, `Serialize`, `Deserialize`, `Print`. Pad the rest so that **total UDP payload (header + padding) equals the configured payload size** (400/800/1200 bytes). The tag is not real cryptography; it exists so later phases can count authentication failures and spoofing.

### 3.2 `DisseminationSender` (node 0)

- Send to subnet broadcast `10.1.1.255:9000`, with `SetAllowBroadcast(true)`.
- Base interval = `payloadBytes * 8 / offeredRateBps`, multiplied by a uniform random factor in [0.9, 1.1] (`UniformRandomVariable`) so that different seeds yield different traces.
- `seq` starts at 0 and increments per packet. Start at `appStart`, stop at `simTime`.
- Write every sent packet to `packets_tx.csv`.

### 3.3 `DisseminationReceiver` (nodes 1-4)

- Bind to port 9000, deserialize `DissHeader`.
- Per packet compute `delay = Now - txTimeNs`, verify `authTag` (`auth_ok`), and set `is_duplicate` if this node has already received that `seq`.
- Write every received packet to `packets_rx.csv`.
- Do not install a receiver on node 5.

## 4. CLI arguments (use `ns3::CommandLine`)

| Arg | Default | Notes |
|---|---|---|
| `--payload` | 800 | 400 / 800 / 1200 |
| `--rateMbps` | 5 | 2 / 5 / 10 |
| `--linkRate` | 100Mbps | CSMA DataRate |
| `--linkDelay` | 2us | CSMA delay |
| `--simTime` | 60 | seconds |
| `--appStart` | 2.0 | seconds |
| `--seed` | 1 | `RngSeedManager::SetSeed` |
| `--run` | 1 | `RngSeedManager::SetRun` |
| `--outDir` | `out/phase0` | output root |
| `--tag` | `normal` | scenario label |

## 5. Outputs

Per run, write to `<outDir>/<runId>/` where `runId = <tag>_p<payload>_r<rate>_s<seed>`:

- `packets_tx.csv`: `run_id,seq,claimed_id,size_bytes,tx_time_s`
- `packets_rx.csv`: `run_id,node_id,seq,claimed_id,size_bytes,tx_time_s,rx_time_s,delay_s,auth_ok,is_duplicate`
- `meta.json`: all parameters, NS-3 version, number of packets sent.

Use buffered writes (no flush per line) and close files at the end of the simulation. No absolute paths.

## 6. Aggregation: `scripts/aggregate.py`

Read all runs under `outDir`, produce `windows.csv` with a 1-second window (window width is an argument). One row per (run, receiver node, window):

```
run_id,tag,payload,rate_mbps,seed,node_id,window_start_s,
tx_packets,rx_packets,pkt_rate_pps,throughput_mbps,pdr,plr,
delay_mean_s,delay_p95_s,delay_max_s,jitter_s,
duplicate_count,duplicate_ratio,auth_fail_count,label
```

- `tx_packets`: packets sent by the sender whose `tx_time` falls in the window (same for every receiver).
- `rx_packets`: unique (non-duplicate) packets received by that node in the window.
- `pdr = rx_packets / tx_packets` (NaN if `tx_packets == 0`), `plr = 1 - pdr`.
- `throughput_mbps`: bytes received (duplicates included) divided by window width.
- `jitter_s`: mean of |delay_i - delay_(i-1)| over consecutive packets in the window.
- `duplicate_ratio = duplicate_count / (rx_packets + duplicate_count)`.
- `label = 0` for tag `normal`.
- Drop windows before `appStart` and the final partial window.

## 7. Experiment runner: `scripts/run_phase0.sh`

Run all combinations: payload {400, 800, 1200} × rate {2, 5, 10} × seed {1..5} = **45 runs**, 60 s each. Allow a configurable max parallel jobs (default 4). Afterwards call `aggregate.py` then `validate_phase0.py`.

## 8. Validation: `scripts/validate_phase0.py`

Print PASS/FAIL per run and per criterion, then a summary:

1. All 4 receivers received packets.
2. Mean `pdr >= 0.999`.
3. Mean throughput within ±3% of the offered rate (unique packets).
4. `duplicate_count == 0` and `auth_fail_count == 0` in every window.
5. `seq` strictly increasing per receiver.
6. Delay is plausible (microseconds to milliseconds; p95 never reaches seconds).
7. Reproducibility: same (seed, run) gives an identical `packets_rx.csv` (add an option that automatically reruns one config twice and compares hashes).
8. Different seeds give different `tx_time` sequences.

Also save one PNG with throughput and delay over time for a sample run.

## 9. Required file layout

```
scratch/phase0/phase0.cc
scripts/run_phase0.sh
scripts/aggregate.py
scripts/validate_phase0.py
README.md
```

## 10. Code quality rules

- Must compile with no extra NS-3 modules beyond the standard ones (core, network, internet, csma, bridge, applications).
- Comment every spot that depends on the NS-3 version.
- Define `NS_LOG_COMPONENT_DEFINE`; logging off by default.
- Class structure must allow adding an `AttackerApp` (flooding / replay / spoofing) later without touching `DisseminationSender` or `DisseminationReceiver`.
- Keep C++ simple and readable; no external libraries.

## 11. Workflow you must follow

1. Create the files, then build. Fix all compile errors yourself.
2. Do a smoke test: one run with `--simTime 10`. Inspect the CSVs.
3. Run the full 45-run matrix, then aggregation, then validation.
4. If any validation criterion fails, find the root cause and fix the code (do not loosen the criterion).
5. Finish with a short report: NS-3 version used, the validation summary, assumptions made, and the exact commands to reproduce.

## 12. Definition of done

All 45 runs complete, `windows.csv` matches the schema in section 6, and every check in section 8 is PASS.
