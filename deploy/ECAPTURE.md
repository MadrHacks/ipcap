# TLS decryption keys (auto-hooked eCapture → ipcap → SSLKEYLOGFILE)

ipcap carries TLS session keys alongside the packets so a TLS-aware tulip pass
can decrypt captured traffic. `ipcap agent tls` is the orchestrator: it
auto-discovers TLS-using docker containers, targets the right crypto library per
container, drives eCapture (isolated subprocess) to extract NSS keylog, survives
container restarts, and accepts a live operator override when auto-detection is
wrong.

```
ipcap agent tls   ── discovers containers, drives one eCapture per (container,library) ──┐
   │  reconciles every --interval (picks up restarts + live --config edits)              │
   ▼                                                                                      ▼
 per-target keylog files  ──(deduped merge)──►  --keylog-file (relay)            eCapture (eBPF uprobes)
                                                      │
ipcap agent listen --keylog-file <same>  ──(TLS_KEYLOG frames over Noise)──►  ipcap collector --sslkeylog-file
                                                                                      │
                                                                          SSLKEYLOGFILE → future tulip TLS pass
```

The keys are completely independent of packet capture (separate process, separate
eBPF, separate frame type 0xA0 — high-bit *skippable*). A missing or failed hook
only costs decryptability of that one flow; it can never disrupt capture or a
vulnservice.

## How it works

- **Discovery** scans `/proc/*/cgroup` + `/proc/*/maps`: any process in a docker
  cgroup that maps `libssl`/`libcrypto` (OpenSSL/BoringSSL) or `libgnutls`
  (GnuTLS) becomes a target, deduplicated to one hook per (container, library).
  The library is taken at its host-visible path (`/proc/<pid>/root/...`) and the
  hook is scoped to the container via eCapture's `--cgroup_path`.
- **Targeting** picks the eCapture probe per library: `tls`/`--libssl` (OpenSSL),
  `gnutls`/`--gnutls`, `gotls`/`--elfpath`.
- **Reconcile** runs every `--interval`: starts hooks for new containers, stops
  hooks for gone ones, restarts a crashed eCapture with backoff. Container
  restarts (new pid/cgroup) are picked up automatically.
- **Override** (`--config /etc/ipcap/tls_targets.yml`, hot-reloaded) lets the
  operator fix targeting live (see the example file): disable auto-discovery,
  exclude a fragile service, or add a manual target (e.g. a statically-linked Go
  service that auto-detection can't see).

## Run

```sh
# Verify what WOULD be hooked first (no eBPF touched):
ipcap agent tls --dry-run

# Then, with the eCapture binary present:
ipcap agent tls --ecapture-bin /usr/local/bin/ecapture \
    --keylog-file /var/lib/ipcap/ssl_keys.log \
    --config /etc/ipcap/tls_targets.yml
# Point the listener at the same relay file:
ipcap agent listen ... --keylog-file /var/lib/ipcap/ssl_keys.log
# And the collector at where to write the merged SSLKEYLOGFILE:
ipcap collector ... --sslkeylog-file /traffic/sslkeylog.txt
```

`deploy/ipcap-tls.service` runs the orchestrator; install eCapture from
https://github.com/MadrHacks/ecapture (a single static binary — its eBPF uses
CO-RE, so the **kernel needs BTF**: `/sys/kernel/btf/vmlinux` present; most
amd64 game boxes have it, minimal RPi kernels often don't).

## Safety

eBPF uprobes are non-invasive read-only breakpoints — they do not modify or pause
the target. If eCapture can't attach (no BTF, stripped library, unsupported
version) it just captures no keys; the service keeps running and ipcap keeps
capturing packets. **In doubt, favor leaving a service untouched**: run
`--dry-run`, then exclude anything fragile in `tls_targets.yml`, then widen.
Never co-locate a new hook with a flaky service mid-round.
