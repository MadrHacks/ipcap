# ipcap

Durable, resumable PCAP-over-IP transport for attack/defense CTF traffic
capture. A persistent capture **agent** on the vulnbox spools every packet to
disk and assigns it a monotonic per-source index (`gpidx`); a **collector** on
the tulip host drains the agent over SSH, dedupes and durably mirrors the
stream, and re-serves a standard, uncompressed PCAP-over-IP feed to the tulip
assembler, suricata, and tshark — unchanged.

Within the spool retention window, every captured packet is delivered to the
collector **exactly once** across SSH drops, network partitions, collector
restarts, serve crashes, and agent-capturer restarts. See
[DESIGN.md](DESIGN.md) for the full architecture, wire format, resume protocol,
and milestones.

## Status — milestone 1 (zero-loss core)

Implemented and tested end to end:

- `agent capture` — AF_PACKET (TPACKETv3, large ring) or offline pcap replay,
  SSH/mgmt userspace exclusion, gpidx assignment, rotating libpcap spool with
  whole-record append + fdatasync + manifest, crash recovery (forward-scan and
  truncate the torn tail with no gpidx reissue), byte-cap retention.
- `agent serve` — read-only, short-lived; seeks to a resume gpidx, streams typed
  frames (PKT_BATCH / HEARTBEAT / GAP), tails live, never reads past the durable
  head. Killing it cannot affect capture.
- `collector` — flock-guarded; SSH supervisor reusing trafficsync's options,
  frame demux with gpidx dedupe, strict-order commit (append → fdatasync →
  resume.json fsync) into a durable mirror, and a per-client non-blocking
  PCAP-over-IP re-serve.
- `recover` — offline spool repair.

Not yet (later milestones): zstd link compression + CRC resync (M2), full
retention/GAP hardening and the crash-injection test matrix (M2), metrics /
systemd watchdog / ansible (M3), multi-source (M4), eCapture TLS (M5). The wire
format already reserves all of it.

## Build

```sh
# Single static binary, no libpcap / cgo.
CGO_ENABLED=0 go build -o ipcap ./cmd/ipcap
go test ./... -race
```

## Run

```sh
# Vulnbox (systemd unit in deploy/ipcap-agent.service):
ipcap agent capture --iface eth0 --spool-dir /var/lib/ipcap/spool --ssh-port 22

# Tulip host (collector container in deploy/Dockerfile + compose snippet):
ipcap collector --config-dir /config --mirror-dir /traffic --listen :4242

# tulip assembler / suricata then connect to the collector's :4242 unchanged.
```

The collector reads `vulnbox.yml` (`ip`, `ssh_user`, `ssh_password`) and
`infra.yml` (`pcap_dir`) from `--config-dir`, exactly like `trafficsync`.
