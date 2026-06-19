# ipcap

Durable, resumable PCAP-over-IP transport for attack/defense CTF traffic
capture. A persistent **agent** on the vulnbox spools every packet to disk and
assigns it a monotonic per-source index (`gpidx`); a **collector** on the tulip
host drains the agent over a mutually-authenticated, encrypted **Noise** channel,
dedupes and durably mirrors the stream, and re-serves a standard, uncompressed
PCAP-over-IP feed to the tulip assembler, suricata, and tshark — unchanged.

Within the spool retention window, every captured packet is delivered to the
collector **exactly once** across link drops, network partitions, collector
restarts, listener crashes, and agent-capturer restarts. See
[DESIGN.md](DESIGN.md) for the architecture, wire format, resume protocol, and
milestones.

## Transport

The link is the Noise Protocol (`IK` pattern, Curve25519 + ChaCha20-Poly1305 +
SHA-256) over TCP — no SSH, no certificates, no PKI. Each node has one static
keypair (`ipcap keygen`). The **static-IP vulnbox** runs the listener; the
**dynamic-IP collector** dials it, pins the agent's public key, and proves its
own identity in one round trip. The agent allowlists collector public keys.

## Status — milestone 1 (zero-loss core)

Implemented and tested end to end (incl. against a live vulnbox):

- `agent capture` — AF_PACKET (TPACKETv3, large ring) or offline pcap replay,
  bounded panic-proof SSH/mgmt exclusion, gpidx assignment, rotating libpcap
  spool with whole-record append + fdatasync + manifest + dir-fsync, crash
  recovery (forward-scan, truncate torn tail, verify contiguity, never reissue a
  gpidx), byte-cap retention.
- `agent listen` — persistent, read-only Noise responder, crash-isolated from
  capture; authenticates collectors by static key, seeks to the requested resume
  gpidx, streams typed frames (PKT_BATCH / HEARTBEAT / GAP), tails live, never
  reads past the durable head.
- `collector` — flock-guarded Noise supervisor: dial + reconnect + resume from
  the durable commit point, frame demux with gpidx dedupe, strict-order commit
  (append → fdatasync → resume.json fsync) into a durable mirror, and a
  per-client non-blocking PCAP-over-IP re-serve.
- `keygen` / `recover` — keypair generation, offline spool repair.

Not yet (later milestones): zstd link compression (M2), full retention/GAP
hardening and the crash-injection test matrix (M2), metrics / systemd watchdog /
ansible (M3), multi-source (M4), eCapture TLS (M5). The wire format reserves it.

## Build

```sh
# Single static binary, no libpcap / cgo.
CGO_ENABLED=0 go build -o ipcap ./cmd/ipcap
go test ./... -race
```

## Run

```sh
# Once, per node:
ipcap keygen --out agent.key      # on the vulnbox  -> prints AGENT_PUB
ipcap keygen --out collector.key  # on the tulip host -> prints COLLECTOR_PUB

# Vulnbox (deploy/ipcap-agent.service + ipcap-agent-listen.service):
ipcap agent capture --iface eth0 --spool-dir /var/lib/ipcap/spool --ssh-port 22
ipcap agent listen  --spool-dir /var/lib/ipcap/spool --listen :7878 \
    --key agent.key --peer COLLECTOR_PUB

# Tulip host (deploy/Dockerfile + compose snippet):
ipcap collector --config-dir /config --mirror-dir /traffic --listen :4242 \
    --key collector.key

# tulip assembler / suricata then connect to the collector's :4242 unchanged.
```

`vulnbox.yml` provides the dial target and pinned key: `ip`, `noise_port`
(default 7878), and `noise_pubkey` (the agent's AGENT_PUB). `infra.yml` provides
`pcap_dir`. The config is read from `--config-dir` (default `/config`), like
`trafficsync`.
