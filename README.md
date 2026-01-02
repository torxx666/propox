# Propox 🛡️🚀

**Propox** is a high-performance, secure, and observable HTTP/HTTPS proxy written in Rust. It is designed to handle high-throughput traffic while actively defending against abusive clients using advanced security mechanisms.

![Rust](https://img.shields.io/badge/built_with-Rust-dca282.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## ✨ Key Features

### 🚀 Extreme Performance
- **Optimized Concurrency**: Built on **Tokio** and **Hyper** for non-blocking I/O.
- **Lock-Free State**: Uses **DashMap** to eliminate lock contention on hot paths.
- **Connection Pooling**:reuses TCP connections to the backend (Keep-Alive), achieving **~28,000 RPS** on local benchmarks.

### 🛡️ Active Defense System
Propox doesn't just pass traffic; it protects your backend:
1.  **Dynamic IP Blocking**: Automatically bans IPs generating excessive errors (>10 non-2xx responses).
2.  **Rate Limiting (Flood Protection)**: Detects and blocks IPs exceeding **100 requests/second**, even if requests are valid.
3.  **Tarpit Defense**: 🐌 Intentionally delays responses to blocked IPs by **10 seconds**, exhausting attacker resources (threads/sockets) and neutralizing scanners.

### 📊 Real-Time Observability (TUI)
Includes a professional **Terminal User Interface** (built with Ratatui) displaying:
- Real-time Throughput (RPS) & Bandwidth.
- Status Code Distribution (2xx, 4xx, 5xx).
- Active IPs & Blocked IPs History.
- Live Traffic Logs.

---

## 🛠️ Installation & Usage

### 1. Start the Proxy
Run the proxy server from the project root. It listens on `127.0.0.1:8100`.

```bash
# Standard Mode (With Security & TUI)
cargo run --release

# View Full Traffic Logs
cargo run --release -- --full

# View Only Error Logs
cargo run --release -- --errors

# 🏎️ Benchmark Mode (Disables Security for Raw Performance Testing)
cargo run --release -- --benchmark

# 👻 Daemon Mode (No TUI, Logs to Syslog)
cargo run --release -- --daemon
```

### 2. Run the Load Tester (Propox Client)
Included is a powerful load testing tool capable of simulating distributed attacks.

```bash
cd propox-client

# Standard Load Test (100k requests, 400 concurrency)
cargo run --release -- nb=100000 cc=400 rq=ok ip=127.0.0.1

# ⚔️ Simulate Attack (Split-Test)
# Terminal 1: "Bad Actors" (90% Errors, 50 IPs) -> WILL BE BLOCKED/TARPITTED
cargo run --release -- ip=127.0.0.10 pool=50 ratio=0.9 nb=5000

# Terminal 2: "Good User" (100% Success) -> SHOULD BE UNAFFECTED
cargo run --release -- ip=127.0.0.200 pool=1 ratio=0.0 nb=5000
```

### Client Arguments:
- `nb=N`: Number of requests to send (total).
- `cc=N`: Concurrency level (simultaneous threads).
- `ip=X.X.X.X`: Starting Source IP (simulated via local bind).
- `pool=N`: Size of IP pool (simulates N distinct clients).
- `ratio=0.X`: Error ratio (0.0 = 100% OK, 1.0 = 100% Errors).
- `rq=ok|nok`: Quick preset for Success or 404s.

---

## 🏗️ Architecture

- **Core**: `src/main.rs` (TUI & Event Loop) + `src/proxy.rs` (Traffic Logic).
- **State**: Shared `Arc<Stats>` struct using Atomics and DashMaps for thread-safety.
- **TUI**: Renders on the main thread, receiving logs via an `mpsc` channel to avoid blocking the proxy data plane.
- **Security Check**: Performed at the start of `handle_client`. If blocked, the request enters the `tokio::sleep` Tarpit.

---
*Built with ❤️ in Rust.*
