# ipcap — design specification

> **Naming:** this tool is **`ipcap`** (binary `ipcap`; subcommands `ipcap agent capture`, `ipcap agent serve`, `ipcap collector`, `ipcap recover`; Go module `ipcap`; systemd unit `ipcap-agent.service`). The design was produced by a multi-agent design+red-team workflow whose synthesis used the working name **`pcapmux`** — read every `pcapmux` (as tool/module/binary/unit name) as `ipcap`. References like `pcapmux#2`, `durablecap#1`, `pcapwire#9` are **red-team findings** from the three competing proposals (durablecap / pcapwire / pcapmux), preserved here as provenance for *why* a given mechanism exists.

> A custom Go PCAP-over-IP relay for the MadrHacks A/D infra, replacing UlisseLab pcap-broker. Persistent capture agent on the vulnbox + collector on the tulip host, SSH-drained, zstd-compressed on the link, exactly-once within the spool retention window.


## 1. Architecture

## pcapmux — unified durable SSH-drained PCAP transport (agent + collector)

ONE Go binary, two subcommands, in its own repo/submodule. Synthesizes the three proposals and FIXES every data-losing red-team hole. Unifying principle from all three: capture is a PERSISTENT systemd writer fully decoupled from any client; durability is plain rotating .pcap on BOTH ends; resume is keyed on a **stable, deterministic LOGICAL coordinate the agent controls** — NOT post-compression wire bytes (fixes pcapmux#2) and NOT a fragile WAL sidecar (fixes durablecap#1).

### The load-bearing coordinate (fixes durablecap#1/#3, pcapmux#2/#6/#9, pcapwire#9)
Resume/ack/dedupe use ONE coordinate per source: **gpidx = per-source monotonic uint64 packet index** (0,1,2,…), assigned by the capturer at capture time and persisted to disk. It is NOT a byte offset and NOT a wire-byte count, so it is invariant to zstd nondeterminism, re-framing, segment rotation, and global-header repetition. Every durable artifact (agent spool, collector mirror, ack) records "highest contiguous gpidx durably fsynced." Because dedupe is per-packet, an ack boundary landing mid-batch can never dup-or-drop (fixes pcapwire#6: collector keeps packets with gpidx > last_committed, drops <=, regardless of batch grouping).

### AGENT — two crash-isolated OS processes
**(A) capturer** = `pcapmux agent capture`, persistent systemd unit `pcapmux-agent.service` (Type=notify, Restart=always, WatchdogSec=30, watchdog pinged only from the capture loop). Owns the AF_PACKET handle (TPACKETv3, ~256 MiB mmap ring) with a BPF excluding the SSH/mgmt path (`not (tcp port <sshport>) and not (host <mgmt_ip>)`, derived from vulnbox.ip/ssh). Assigns each packet a gpidx and appends to the durable spool. No socket, no knowledge of the collector. Zero-loss anchor.

**(B) server** = `pcapmux agent serve` — thin, READ-ONLY, short-lived process spawned by sshd per collector connect. Opens spool read-only, seeks to requested resume gpidx, streams frames forward tailing the live spool (poll manifest head). Holds an advisory **read-lock/refcount on the segment it is replaying** so the janitor cannot reap bytes out from under it (fixes durablecap#4 / pcapwire#4/#5 / pcapmux#4). NEVER writes durable state; reaper keys ONLY off the collector ack (fixes durablecap#2). Killing it cannot touch (A).

Interface-flap (fixes pcapmux#11/durablecap#11): on AF_PACKET read error the capture loop logs, increments a metric, re-opens with backoff WITHOUT exiting (avoids Restart-induced replay storms). Liveness = **capture progress** (gpidx advancing while iface admin-up via netlink), not process heartbeat, so a silent half-flap alarms. Linktype is **immutable per source**: a linktype change allocates a NEW SourceID/SRCINFO rather than mixing linktypes in one global-header'd stream (fixes pcapmux#11).

### COLLECTOR — docker-compose service on the tulip host
`pcapmux collector`. Loads `vulnbox.yml` (ip, ssh_user, ssh_password) + `infra.yml` (pcap_dir) from `/config` with mtime-reload exactly like trafficsync/sync.py. Takes an **exclusive flock on its mirror dir + resume.json** at startup, refuses to run if held (fixes durablecap#10 / pcapwire#10 / pcapmux#10 — no double-collector corruption).

Supervised loop (mirrors assembler `connectToPCAPOverIP` retry shape): spawn `sshpass -e ssh -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=5 -o ServerAliveCountMax=2 -o Compression=no user@ip -- pcapmux agent serve --resume <gpidx-map>` (sshpass+SSHPASS when password set, key-only otherwise — identical to sync.py `_build_ssh_cmd`). Remote stdout = frame stream; stdin = authoritative resume map at startup + periodic ACK frames. On exit: log, jittered 2s backoff, re-read config, re-spawn with latest persisted gpidx map. A 20s watchdog tears down a silently-wedged pipe (no DATA/HEARTBEAT) and reconnects.

Per frame the collector: (1) verify header CRC, drop packets with gpidx <= committed (dedupe), (2) write surviving packets to a temp mirror segment, (3) **fdatasync segment, THEN fsync resume.json {committedGpidx,lastSeq}, THEN rename/publish the segment into the tulip-visible dir** — strict ordering so a crash never exposes unacked data; recovery is from the last fsynced gpidx (fixes pcapmux#3, durablecap#3). Only then are bytes handed to fan-out.

### Both-end durability
Agent spool AND collector mirror are plain rotating libpcap files (`src<ID>-<seq>.pcap`, seq = monotonic counter, NOT wall-clock — fixes pcapmux#7/pcapwire#7 clock-skew reaping/ordering), directly Wireshark-openable. A durable per-source **manifest** (append-only, fsynced) records each segment's {seq,startGpidx,endGpidx,validatedLen,filename} so ordering/seek never depend on filenames/mtime. Crash recovery (fixes durablecap#1, pcapwire#1, pcapmux#1): on startup scan the newest segment forward validating each pcap record (caplen<=snaplen, header+body present), TRUNCATE to the last valid record boundary, rebuild manifest end — self-recovering, no head.offset sidecar to disagree. fdatasync every 64 KiB OR 500 ms; writes only ever land at whole-record granularity (partials buffered in userspace).

### Compression & fan-out (unchanged-consumer guarantees)
zstd (klauspost/compress, SpeedFastest/level configurable) ONLY on PKT_BATCH/TLS payloads on the SSH link, flag-bit gated; each batch is a self-contained zstd frame (EncodeAll) so resume needs no decoder replay. Collector fully decompresses before any durable write, so re-served PCAP-over-IP and mirror files are always raw libpcap. Collector re-serves STANDARD uncompressed PCAP-over-IP per source on local TCP (default :4242,:4243,…), 24-byte global header + records — byte-identical to what `pcap.OpenOfflineFile` (assembler), `socat|suricata -r /dev/stdin`, and `tshark -i TCP@host:port` expect. Fan-out reads the mirror via per-client disk cursors + bounded ring + dedicated goroutine — no shared channel, no HOL blocking. CRITICAL fix (pcapwire#5/pcapmux#5): the suricata-facing client is NEVER closed on slow-write (its `-r /dev/stdin` cannot reconnect); slow non-reconnecting clients **block-with-large-buffer**, only assembler-class clients (auto-reconnect every 5s) may be dropped; recommended ops change is wrapping suricata in `while true; do socat...|suricata -r /dev/stdin; done`.

## 2. Wire frame format

All multi-byte integers BIG-ENDIAN. Stream = one PREAMBLE then a sequence of self-delimiting FRAMES.

=== STREAM PREAMBLE (once, after connect) ===
  Magic     [4]  = "PMX1"
  Version   u16  = 1
  HdrCRC    u32  = CRC32C over following HeaderLen+CBOR bytes
  HeaderLen u16
  Header    [HeaderLen] = CBOR { compression:"zstd"|"none",
              sources:[{id:u16,name:str,linktype:u16,snaplen:u32}...],
              resumeAck:{<srcID>:<gpidx>...} }

=== FRAME (fixed 32-byte header + payload + 4-byte payload CRC) ===
  off 0  : Magic      u16  = 0xD0CA   (resync sentinel)
  off 2  : Version    u8   = 1
  off 3  : FrameType  u8   (enum below)
  off 4  : Flags      u16  (bit0 COMPRESSED=payload is one zstd frame, bit1 KEYFRAME=safe resync, bit2 GAP, rest 0)
  off 6  : SourceID   u16  (0 = control/global)
  off 8  : BaseGpidx  u64  (gpidx of first packet in payload for PKT/PKT_BATCH; else 0)
  off 16 : Seq        u64  (monotonic per (SourceID,FrameType); gap/replay detect)
  off 24 : PayloadLen u32  (payload byte count, post-compression on wire; capped 8 MiB)
  off 28 : HdrCRC     u32  (CRC32C over bytes [0..28))
  off 32 : Payload    [PayloadLen]
  off 32+len : PayCRC u32  (CRC32C over payload bytes)
Frame total = 36 + PayloadLen. Two CRCs fix pcapmux#8: HdrCRC lets the collector reject an absurd PayloadLen BEFORE allocating; PayCRC catches body/zstd corruption even though SSH provides a MAC (defends intra-process framing bugs + future non-SSH transports).

PKT body (standalone or repeated in PKT_BATCH): [TsSec u64 | TsNsec u32 | OrigLen u32 | CapLen u32 | bytes[CapLen]]. In PKT_BATCH the i-th packet's gpidx = BaseGpidx + i (contiguous), so packet-granular dedupe needs no per-packet index on the wire.

=== FRAME TYPE ENUM ===
  0x01 PKT          one packet
  0x02 PKT_BATCH    u16 count + N PKT bodies (the zstd unit when COMPRESSED)
  0x03 ACK          collector->agent: {srcID u16, committedGpidx u64, lastSeq u64}
  0x10 SRCINFO      CBOR {id,name,linktype,snaplen,kind} announce/update source
  0x11 HEARTBEAT    {tsNsec u64, headGpidx u64} every 1s even idle (liveness + lag)
  0x12 STATS        CBOR {captured,dropped_kernel,ifdrop,spool_bytes,oldest_gpidx}
  0x13 GAP          {srcID u16, fromGpidx u64, toGpidx u64} — agent could NOT satisfy resume (reaped); explicit bounded logged loss marker (fixes silent skips durablecap#4/pcapwire#4/pcapmux#4)
  -- RESERVED (forward-compatible, no redesign) — high-bit so old collectors skip --
  0xA0 TLS_KEYLOG     NSS keylog lines, tagged SourceID (eCapture master-secret)
  0xA1 TLS_PLAINTEXT  [StreamID u64|Dir u8|TsNsec u64|Len u32|bytes] decrypted app-data
  0xA2 TLS_META       CBOR {sni,cipher,5tuple,tls_version} correlate TLS->PKT flow
  0x14..0x7F reserved (non-skippable); 0xA3..0xFF reserved (skippable)
FrameType high bit 0x80 = "experimental/skippable": collector MUST silently skip unknown skippable types (PayloadLen-delimited), MUST hard-error+reconnect on unknown NON-skippable types (never silently drop load-bearing data).

RESYNC RULE: on any read error/EOF/CRC failure the collector DISCARDS its entire parser buffer and re-parses from the next connection's preamble at the resume gpidx — partial bytes are NEVER carried across connections (fixes pcapmux#8 desync).

## 3. Resume / ack / no-loss protocol

COORDINATE: per-source monotonic uint64 packet index `gpidx`, assigned at capture, persisted in the manifest (segment start/end gpidx), recoverable after crash by record-scan. NOT byte offset, NOT wire bytes — invariant to zstd/reframing/rotation.

ACK = COLLECTOR-LOCAL DURABLE STATE, not per-frame round-trips. Per source: committedGpidx = highest gpidx G such that every packet index <= G has been fsynced into the collector mirror AND resume.json fsynced. COMMIT ORDER (strict): write packets to temp mirror segment -> fdatasync segment -> write+fdatasync resume.json{committedGpidx,lastSeq} -> rename segment into tulip-visible dir -> push to fan-out. A crash anywhere leaves committedGpidx pointing only at fully-durable, idempotently-replayable data.
ACK cadence: coalesced on stdin every 1s OR every 256 packets committed, plus once at handshake. Only latest matters; ACK loss harmless.

NEGOTIATION ON (RE)CONNECT:
1. Collector recovers committedGpidx per source from resume.json, validated against actual mirror sizes (truncate mirror to committedGpidx record boundary on startup so re-sent packets append with no dup in the durable file).
2. Collector spawns `agent serve --resume {<srcID>:committedGpidx...}` AND re-sends the same map on stdin (authoritative; argv is a hint).
3. Agent serve per source:
   - resumeGpidx within retained spool -> manifest binary-search to owning segment, scan to packet index==resumeGpidx, replay forward from the NEXT packet (gpidx > committed). Zero skip, zero dup.
   - resumeGpidx older than oldest retained gpidx (collector down past retention — the ONLY lossy case) -> emit GAP{from=resumeGpidx,to=oldestRetainedGpidx}, replay from oldestRetainedGpidx. Collector logs exact lost range and CLOSES+reopens downstream consumers so they restart with a fresh global header and a NEW sourceName/timestamp (assembler keys Position per ip:timestamp, so reconnect is clean — fixes durablecap#4 silent mid-connection discontinuity into pcap.OpenOfflineFile).
   - resumeGpidx newer than spool head (impossible from a correct agent) -> clamp to head, warn.

DEDUPE: collector keeps a packet iff gpidx > committedGpidx for that source, else drops. Because gpidx is per-packet and contiguous within a batch, an ack boundary mid-batch is handled exactly (keep suffix, drop prefix) — no batch all-or-nothing hazard (fixes pcapwire#6). Seq is a secondary monotonic guard per (SourceID,FrameType) to detect reordered/duplicate frames.

EXACT NO-LOSS GUARANTEE: For every captured packet that reaches the agent spool, the packet is delivered EXACTLY ONCE into the collector mirror and the re-served stream, across ALL of: SSH drop, network partition, collector crash/restart, agent serve crash, agent capturer restart, slow consumer, on-wire/zstd corruption. Formally: zero loss provided the packet's owning spool segment has NOT been reaped by retention at the moment the collector next reconnects — i.e. provided (collector_downtime + replay_drain_time) x ingest_rate < spool_retention_bytes for that source.
THE ONLY LOSS MODES, each explicit/bounded/counted:
 (a) outage longer than the retention window -> spool wraps -> exact lost gpidx range emitted as a GAP frame and logged (NEVER silent, NEVER a mid-stream discontinuity into a live consumer).
 (b) kernel AF_PACKET ring drop BEFORE the spool under CPU starvation -> counted via ps_drop/ps_ifdrop, surfaced in STATS (transport-independent; mitigated by big ring + tight BPF + dedicated capture goroutine).
 (c) <=500 ms / <=64 KiB of the capturer's own un-fsynced tail on a HARD power-cut (clean reboots lose nothing; torn tail truncated to last valid record on recovery).
RETENTION INVARIANT: the janitor advances an authoritative oldestRetainedGpidx ATOMICALLY before unlinking, refuses to delete any segment referenced by an active serve read-lock, and NEVER deletes a segment whose endGpidx > min(committedGpidx, activeServeCursor) UNLESS disk-full last-resort forces it — in which case it drops OLDEST first and the resulting GAP is the explicit (a) above. Retention sized from REALISTIC scored-traffic rate (A/D typically <50 Mbit/s ~= 6.25 MB/s); default cap 48 GiB ~= 2.1 h at peak; binding constraint documented as max_bytes/rate, alert at 70% full BEFORE loss (fixes durablecap#4's over-optimistic "2h AND 8GiB" framing).

## 4. Go module layout

| path | purpose |
|---|---|
| `go.mod` | module pcapmux; deps: github.com/gopacket/gopacket v1.3.1 (match assembler fork), klauspost/compress/zstd, golang.org/x/crypto/ssh (or os/exec+sshpass), golang.org/x/sys/unix (AF_PACKET TPACKETv3 + netlink), spf13/cobra, fxamacker/cbor/v2, hash/crc32 (Castagnoli). |
| `cmd/pcapmux/main.go` | cobra root; subcommands agent capture, agent serve, collector, recover (offline spool repair), version. |
| `internal/capture/capture.go` | AF_PACKET TPACKETv3 handle, BPF attach, large ring, dedicated read goroutine, ps_drop/ifdrop stats, gpidx assignment, netlink iface-state watch, error-reopen-with-backoff (never exit), sd_notify watchdog ping. |
| `internal/capture/bpf.go` | derive BPF from vulnbox.ip/ssh_port + mgmt subnet; validate compile before atomic reload swap to avoid self-capture amplification. |
| `internal/spool/spool.go` | rotating pcapgo segment writer (64MiB/60s), whole-record append, fdatasync 64KiB/500ms + on rotate, gpidx tracking. |
| `internal/spool/manifest.go` | append-only fsynced per-source manifest {seq,startGpidx,endGpidx,validatedLen,filename}; monotonic-seq naming (NOT wall-clock); authoritative ordering + oldestRetainedGpidx. |
| `internal/spool/recover.go` | crash recovery: forward-scan newest segment, validate records (caplen<=snaplen), truncate torn tail, rebuild manifest end; mirror-side truncate-to-committedGpidx. |
| `internal/spool/janitor.go` | retention reaper: byte+age caps, atomic oldestRetainedGpidx advance before unlink, serve-cursor refcount, 70% alert, GAP on forced un-acked drop. |
| `internal/spool/reader.go` | seek-to-gpidx (manifest binary-search + record scan), tail live spool, advisory read-lock on active segment. |
| `internal/proto/frame.go` | frame header encode/decode, HdrCRC+PayCRC, PayloadLen cap, magic resync, skip-unknown-skippable rule, buffer-discard-on-error. |
| `internal/proto/types.go` | FrameType enum + reserved TLS constants, Flags bits, PKT/PKT_BATCH/ACK/GAP/SRCINFO/HEARTBEAT/STATS payload structs. |
| `internal/proto/preamble.go` | PMX1 preamble CBOR encode/decode + HdrCRC; resume-map negotiation. |
| `internal/proto/zstd.go` | per-batch EncodeAll/DecodeAll, level config, self-contained-frame guarantee. |
| `internal/agent/capture_cmd.go` | agent capture: wires capture->spool->manifest, STATS/HEARTBEAT bookkeeping, systemd Type=notify. |
| `internal/agent/serve_cmd.go` | agent serve: read resume map (stdin+argv), seek, batch+compress+frame from spool, tail, read ACK frames, GAP on reaped resume; read-only, never writes durable state. |
| `internal/collector/collector.go` | config load + mtime reload (vulnbox.yml/infra.yml from /config), flock mirror dir, SSH supervisor loop (ssh opts from sync.py), reconnect/backoff, 20s wedge watchdog. |
| `internal/collector/demux.go` | frame decode, CRC verify, gpidx dedupe, route by FrameType (PKT->mirror+fanout; GAP->log+consumer-recycle; TLS->reserved sinks); strict commit ordering + resume.json fsync. |
| `internal/collector/mirror.go` | per-source mirror writer into tulip-visible dir (temp+rename after ack), resume.json atomic persist, startup truncate-to-committed. |
| `internal/pcapoverip/server.go` | per-source TCP listener; on accept write 24B global header then records; per-client disk cursor + bounded ring + goroutine; non-blocking fan-out. |
| `internal/pcapoverip/client.go` | slow-client policy: block-with-large-buffer for non-reconnecting consumers (suricata), drop-only-reconnecting (assembler); never HOL-block ingest. |
| `internal/config/config.go` | vulnbox.yml/infra.yml parsing (ip,ssh_user,ssh_password,pcap_dir) + env knobs (RETENTION_BYTES/HOURS, ROTATE_*, ZSTD_LEVEL, ports, BPF, ring size, ack interval). |
| `internal/metrics/metrics.go` | Prometheus counters: captured, kernel_drops, ifdrops, spool_bytes, collector_lag_gpidx, gaps_total, reconnects, corrupt_frames. |
| `deploy/pcapmux-agent.service` | systemd unit (Type=notify, Restart=always, WatchdogSec=30, StartLimitIntervalSec=0). |
| `deploy/docker-compose.collector.yml + Dockerfile` | collector container mirroring trafficsync wiring, /config + mirror volume mounts. |
| `deploy/ansible/pcapmux.yml` | replaces setup_tulip_tcpdump.yml; installs binary+unit, keeps rsync as belt-and-suspenders. |
| `internal/.../*_test.go` | crash-injection at every record/segment/rollover boundary; resume idempotency (byte-identical mirror vs no-crash); kill-serve-mid-stream; mid-batch ack dedupe; corrupt-frame resync; janitor-vs-serve race; double-collector flock. |

## 5. Milestones

### Milestone 1: v1 core: capture+spool+resume+standard PCAP-over-IP (single source, no compression)
agent capture: AF_PACKET TPACKETv3 + BPF SSH/mgmt exclusion, gpidx assignment, rotating pcapgo spool with whole-record append + fdatasync(64KiB/500ms) + manifest + crash recovery (forward-scan/truncate). agent serve: seek-to-gpidx, frame stream (PKT_BATCH/HEARTBEAT/SRCINFO/ACK/GAP), tail. collector: config load+flock+SSH supervisor (reuse sync.py ssh opts), demux, gpidx dedupe, strict-order mirror+resume.json commit, per-source PCAP-over-IP listener. END-TO-END TEST against the live tulip assembler + suricata socat. Beats pcap-broker on durability/resume/fan-out. Frame format already reserves all later types.

### Milestone 2: zstd link compression + full no-loss hardening
Enable per-PKT_BATCH EncodeAll (self-contained frames), flag bit, collector decompress-before-durable. HdrCRC+PayloadLen-cap + PayCRC + buffer-discard-on-error resync. Janitor retention (byte+age, monotonic-seq, oldestRetainedGpidx atomic advance, serve refcount, 70% alert) with explicit GAP on forced drop. Slow-consumer policy: block-for-suricata, drop-only-reconnecting-assembler; recommend while-true socat|suricata wrapper. Crash-injection + resume-idempotency test matrix (every boundary, mid-batch ack, kill-serve, double-collector).

### Milestone 3: observability + ops integration
STATS frame -> Prometheus (kernel_drops, ifdrops, collector_lag_gpidx, gaps_total, reconnects, corrupt_frames). Capture-progress liveness via netlink (alert on wedged-capture-while-iface-up). systemd unit (Type=notify watchdog), docker-compose collector, ansible playbook replacing setup_tulip_tcpdump.yml, rsync kept belt-and-suspenders, collector config mtime-reload. recover offline spool-repair CLI.

### Milestone 4: multi-source capture
Multiple AF_PACKET sources (per-NIC/per-veth) each own SourceID+spool subdir+manifest+listener; collector re-serves per-source ports; tulip uses existing comma-separated PCAP_OVER_IP. One collector instance per vulnbox generalizes to multi-vulnbox. SourceID/linktype immutability already enforced (flap -> new SourceID).

### Milestone 5: eCapture TLS (gated on eCapture + tulip TLS landing)
pcapmux-tls.service runs eCapture; keylog->0x20 TLS_KEYLOG, plaintext->0x21 TLS_PLAINTEXT, 0x22 TLS_META, each as new SourceIDs with own gpidx/spool/resume (durable+resumable+compressed identically). Collector routes keylog to SSLKEYLOGFILE-format sink and plaintext to tulip's new TLS API. Old collectors skip these (high-bit/feature-gated). NO protocol or transport change.

## 6. Open risks

- **Sustained collector throughput < capture rate (zstd-decode + per-source fsync + fan-out on a busy tulip host): lag grows monotonically and guarantees retention-wrap loss after cap/(rate-collector_rate) seconds. Steady-state failure, not an edge case.**
  - *Mitigation:* Make the demux->mirror path a tight loop with BATCHED fdatasync (not per-frame), measured to exceed capture rate. Fan-out reads the mirror asynchronously (no lock/channel shared with ingest) so a slow consumer cannot backpressure ingest. Emit collector_lag_gpidx (from HEARTBEAT headGpidx) and ALERT when lag grows >N s; document min hardware + level=SpeedFastest fallback.
- **gpidx reconstruction across capturer restart: miscomputing the durable head (counting a repeated global header, trusting a torn segment's filename-implied length) could reuse/shift gpidx -> wrong collector dedupe -> silent dup/gap.**
  - *Mitigation:* head = manifest last-fsynced endGpidx after torn-tail truncation, cross-checked for contiguity (segment.startGpidx == prev.endGpidx+1); refuse to start + alert on non-contiguity rather than renumber. gpidx persisted per fsync; never reissue lower. Heavy crash-injection across rollover and global-header boundaries asserting byte-identical mirror.
- **zstd CPU on a vulnbox already under attack steals cycles from vulnerable services; AF_PACKET ring overflow during starvation drops packets pre-spool.**
  - *Mitigation:* Default ZSTD_LEVEL=SpeedFastest, tunable to none; capture on a dedicated goroutine doing only ring->spool; 256MiB ring; tight BPF dropping SSH/mgmt early; surface ps_drop/ifdrop in STATS so pre-spool loss is visible (not hidden in the no-loss claim).
- **Capturer restart window (OOM/segfault under attack, Restart=always): packets during process-down are physically uncaptured and uncounted (ps_drop lives in the dead handle).**
  - *Mitigation:* Do NOT restart capturer for config reload (reload only serve/collector); large ring survives sub-second restarts; on every (re)start log a counted capture-gap event with best-effort estimate; sd_notify watchdog catches hangs fast.
- **Downstream timestamp non-monotonicity from NTP steps confuses tulip time-based flush and suricata flow tables (resume itself is immune, being gpidx-keyed).**
  - *Mitigation:* Keep kernel per-packet timestamps as-is for pcap fidelity; drive ALL internal timers (retention age, heartbeat, watchdog, backoff, rotation) off CLOCK_MONOTONIC/BOOTTIME; make the ack/gpidx bound dominate age unconditionally for unacked segments; document downstream monotonicity as the host's NTP responsibility.
- **TLS_PLAINTEXT/KEYLOG frame types are scaffolding with no consumer until tulip TLS lands; risk of bit-rot in the seam.**
  - *Mitigation:* Keep them feature-gated (high-bit skippable + collector feature flag) and minimally exercised by a loopback test source emitting dummy 0x20/0x21 frames so the demux path stays alive; realize fully in milestone 5.

## 7. Effort

Medium-high. ~2200-3000 lines of Go in a new repo/submodule. v1 (milestone 1, the zero-loss core that already beats pcap-broker on all four axes and satisfies the hard requirements) reachable in ~3-4 focused days; v2 hardening (compression + CRC + retention/GAP + slow-consumer policy + the crash-injection/resume-idempotency test matrix, where most real rigor lives) ~2-3 days. Milestone 3 (metrics/systemd/compose/ansible) ~1-2 days. Multi-source (4) is incremental (~1 day) because SourceID space and per-source spool/listener are designed in. eCapture/TLS (5) is deferred and gated on external work but needs no protocol/transport change. All dependencies already in the tree ecosystem (gopacket v1.3.1 matching the assembler fork, klauspost/compress/zstd, x/crypto/ssh or os/exec+sshpass, x/sys/unix). Highest-risk areas to test hard: gpidx reconstruction across capturer restart + rollover, mid-batch ack dedupe, janitor-vs-serve reap race, and corrupt-frame resync — all covered by the milestone-2 crash-injection matrix.

## Appendix A — alternatives considered (provenance)

The synthesis above merges three independently-designed proposals, each red-teamed against the same failure-timeline matrix. Summaries kept for context:

### durablecap (durable PCAP drain: agent + collector)
**Red-team verdict:** fixable · effort: Medium-high. ~1500-2500 lines of Go total. Phase 1 (MVP zero-loss core, ~2-3 days): AF_PACKET capture + BPF, append-only segment spool with fdatasync + rotation/retention, agent --serve-stdio replay-from-offset, collector SSH dial + zstd + frame parse/CRC + collector spool + ack, and the standard uncompressed re-serve on :1337 with per-client spool cursors. This alone beats pcap-broker on all four axes and satisfies the hard requirements. Phase 2 (~1-2 days): config-reload watcher, retention safety-margin tuning, metrics/logging of all loss modes, crash-recovery torn-tail truncation, systemd unit + docker-compose wiring, optional rsync coexistence. Phase 3 (deferred, gated on eCapture + tulip TLS landing): wire up reserved TLS_KEYLOG/TLS_PLAINTEXT frame types and per-srcID multi-source re-serve ports. Dependencies are all already in the tree's ecosystem: github.com/gopacket/gopacket v1.3.1 (matches the assembler fork) for capture/pcapgo, github.com/klauspost/compress/zstd, golang.org/x/crypto/ssh. Main risk areas to test hard: resume idempotency across overlapping frames, segment-boundary seeking, and retention-vs-ack interaction (never reap un-acked bytes).

A single Go binary, two subcommands: `durablecap agent` (systemd unit on the vulnbox) and `durablecap collector` (docker-compose service on the tulip host). The agent captures continuously via AF_PACKET with a BPF excluding SSH/mgmt, and the FIRST action on every packet is an append to a durable, byte-addressable WAL spool (segment files) — capture/durability never depend on any client being connected. The collector dials OUT over SSH (sshpass + vulnbox.yml creds), execs `durablecap agent --serve-stdio` on the far side, and reads a typed/multiplexed/zstd-compressed framed stream over the SSH stdin/stdout pipe. The collector verifies per-frame CRC, persists every accepted DATA payload to its OWN durable spool, periodically ACKs the highest contiguous byte offset it has fsynced, and re-serves a STANDARD uncompressed libpcap stream on a local TCP port (default :1337) so tulip's assembler (pcap.OpenOfflineFile), suricata (socat | suricata -r /dev/stdin), and tshark (-i TCP@host:port) work unchanged. Resume is byte-exact: on every (re)connect the collector sends its acked spool offset, the agent seeks and replays forward, giving ZERO loss within the spool retention window across SSH drops, collector restarts, vulnbox network outages, or tulip downtime. Frame TYPE field reserves values for future eCapture TLS keylog/plaintext frames and multiple capture sources, so TLS decryption and per-service multi-source capture land with no protocol redesign. Strictly dominates UlisseLab pcap-broker on durability (WAL vs 100-pkt RAM channel), resume (byte-offset ack vs none), compression (zstd vs none), and fan-out (per-client spool cursor, no HOL blocking, no loss-causing eviction).

**High-severity holes the synthesis had to fix:**
- (1) Vulnbox hard power-loss mid-frame/mid-record. The capture goroutine has appended a 16B pcap record header claiming incl_len=1400 but only part of the body landed, OR the durable head.offset sideca — *fix:* Drop the separate head.offset sidecar. Make the segment self-recovering: on restart, scan records forward from byte 24, validate each (incl_len<=snaplen, header fully present, body fully present, optional per-segment running CRC), truncate 
- (3) Collector crashes AFTER appending+fdatasync'ing packets to its spool but BEFORE sending the ACK that advances collectorAckedOffset. On restart it recovers its resume point from its own spool head, — *fix:* Drive resume from ONE canonical logical offset space = concatenation of record bytes only (global header NOT counted), computed by an identical formula on both ends; convert to file offsets only at the edges. Resume point = the collector's 
- (4) Agent spool fills to spool.max_bytes while the collector is still behind (un-acked bytes exceed the cap). The retention rule 'never delete a segment whose end offset > collectorAckedOffset' DIRECT — *fix:* (a) Size max_bytes from the worst plausible outage at REALISTIC scored-traffic rate (A/D <50Mbit/s -> ~22GB/hr), document the binding constraint as max_bytes/rate (don't advertise '2h AND 8GiB' as if both hold), and alert at ~70% full so an
- (9) Agent capture-service process restart (OOM-kill, segfault, systemd restart for config reload) loses in-memory state: the in-memory head, the current segment handle, and un-fsynced ring->spool byte — *fix:* (a) Run capture with Restart=always plus a watchdog; do NOT restart capture for config reload (reload only serve-stdio/collector); use a large AF_PACKET ring to survive sub-second restarts; and explicitly log a counted capture-gap event wit
- (11) Capture interface flaps (NIC down/up during a network reconfig, iface reassignment, or a BPF reload to change the SSH-exclusion port). AF_PACKET on a flapping iface may error, EOF, or SILENTLY st — *fix:* (a) Base liveness on CAPTURE PROGRESS, not process heartbeat: alert if agentSpoolHead stops advancing for >N seconds WHILE the iface is administratively up (detect via netlink/iface state) to distinguish 'idle network' from 'wedged capture.

### pcapwire (agent | collector): rotating-pcap spool + SSH-drained typed frames
**Red-team verdict:** fixable · effort: Medium, roughly 1200-1700 lines of Go in a new repo/submodule, buildable in 2-4 focused days. Breakdown: (1) agent capture+rotating-pcap writer with fsync/retention janitor (~300 lines; gopacket AF_PACKET + pcapgo.Writer, mostly straight-line). (2) frame codec: header+subheader encode/decode, zstd wrap/unwrap, resync-on-magic (~250 lines, well-bounded, easy to unit-test with table tests). (3) streamer: spool tail from (file_id,offset), ROTATE detection, batching/flush bounds, ACK reader (~300 lines). (4) collector: ssh supervisor loop (reuse sync.py's sshpass/ssh option set), frame decode, mirror spool + cursor truncate/persist, PCAP-over-IP listener with per-client ring fan-out (~450 lines). (5) glue: cobra subcommands, env/config load from /config like trafficsync, systemd unit template + ansible playbook to replace setup_tulip_tcpdump.yml, a compose service mirroring trafficsync (~200 lines + yaml). Proven libraries (gopacket, pcapgo, klauspost/compress, golang.org/x/sys for AF_PACKET) carry the hard parts; the novel logic is the resume cursor and the non-blocking fan-out, both small and testable. Lowest-risk increment: ship without compression and without TLS frames first (SEGMENT/ACK/ROTATE/HELLO/HEARTBEAT only), verify end-to-end against the live assembler, then flip ZSTD_LEVEL on — the frame format already reserves all of it.

A single Go binary `pcapwire` with two subcommands. AGENT runs as a persistent systemd service on the vulnbox: AF_PACKET capture with a BPF that excludes SSH/mgmt, writing a continuous, DURABLE spool of ORDINARY rotating .pcap files. The spool IS the durability layer and the resume index, so there is no bespoke WAL to debug at 3am. COLLECTOR runs in the tulip docker compose; it spawns `ssh user@vulnbox pcapwire agent stream` (creds from vulnbox.yml), and that streamer child re-reads spool files from a requested (file,offset) cursor, zstd-compresses, and emits TYPED, length-prefixed frames over the SSH stdout pipe. The collector decompresses, writes its own mirror .pcap spool (durable on the tulip end too), and re-serves STANDARD uncompressed PCAP-over-IP on a local TCP port so tulip-assembler / suricata / tshark connect unchanged. Resume = the collector persists the last fully-decoded byte offset and replays it on every (re)connect; capture/spool never stop because the writer is a separate always-on process independent of any SSH session. Strictly beats UlisseLab pcap-broker on durability, resume, compression, and non-HOL-blocking fan-out, while keeping moving parts to "rotating files + ssh + systemd". The single shared frame layer is consumed three ways (agent->collector wire, collector mirror, and internally) so adding eCapture TLS keylog/plaintext later is a new frame TYPE, not a redesign.

**High-severity holes the synthesis had to fix:**
- (9) AGENT PROCESS RESTART (systemd Restart=always) generates a NEW spool_id but does NOT necessarily roll the spool DIRECTORY, so resume falls back to 'fresh stream' and silently re-ingests already-mi — *fix:* Decouple spool_id from process boot. Persist a stable spool_id in a SPOOL_DIR/.spool_id file created once and reused across agent restarts; only mint a NEW spool_id when the spool dir is genuinely empty/wiped (true cold start) or the linkty
- (4/5) SPOOL FILLS TO CAP / collector slower than capture for minutes -> retention janitor races the streamer and can delete a file the streamer has OPEN or is mid-replay. Timeline: collector is behind — *fix:* Make retention back-pressure-aware: the janitor must NOT delete files at or beyond the streamer's current read position; instead, when the spool is full and the unsent backlog itself exceeds the cap, the writer must drop NEWEST capture (or 

### pcapmux — durable SSH-drained, typed-frame PCAP transport for tulip
**Red-team verdict:** fixable · effort: High. Roughly 2500-3500 lines of Go across: AF_PACKET capture + BPF + spool writer with index/rotation/janitor (~600 LOC); frame serializer/deserializer with zstd batcher and the typed-frame registry (~500); `agent --serve` resume/seek/tail-replay (~400); collector SSH-exec supervisor with vulnbox.yml reload + retry (~300); demux + receive spool + resume.json durability (~400); disk-backed per-client PCAP-over-IP fan-out listeners (~400); plus systemd units, ansible wiring, Dockerfile/compose for the collector, and tests for the resume/no-loss invariant (~500). Estimate ~1.5-2.5 engineer-weeks to production-harden, with a thin MVP (single source, PKT only, resume, fan-out, no TLS) reachable in ~3-4 days. The TLS/eCapture and multi-vulnbox extensions are then incremental because the protocol already reserves their frame types and SourceID space.

One Go binary (pcapmux) with two subcommands. `pcapmux agent` runs as a persistent systemd unit ON the vulnbox: it captures via AF_PACKET (gopacket) with a BPF excluding SSH/mgmt, writes every packet into a durable on-disk segment spool (its own rotating .pcap files = Wireshark belt-and-suspenders), and re-emits the same packets as TYPED, MULTIPLEXED, length-prefixed frames into a per-source byte-offset stream. `pcapmux collector` runs on the tulip host (docker compose) and does NOT open a port on the vulnbox; it spawns `ssh user@ip pcapmux agent --serve --resume <off>` reusing creds from vulnbox.yml (sshpass, exactly like trafficsync/sync.py), so the framed stream returns over SSH stdout. The collector demultiplexes typed channels: PKT frames per source are zstd-decompressed (compression applied ONLY on the cross-network link), re-spooled to disk on the tulip end, and re-served as STANDARD uncompressed PCAP-over-IP on a local TCP port per (source,linktype) so tulip's assembler (pcap.OpenOfflineFile on the raw conn), suricata (socat|suricata -r /dev/stdin), and tshark (-i TCP@host:port) work unchanged. Resume is collector-driven: the collector persists the highest contiguous byte offset durably written per source and passes it as --resume on every (re)connect; the agent seeks its spool to that offset and replays forward, giving ZERO loss within the retention window across SSH/network/collector/agent-restart failures. The frame header carries Channel/FrameType + SourceID discriminators, so eCapture TLS keylog/plaintext and extra capture sources slot in as NEW frame types / NEW source IDs with NO protocol change and NO new connection. Strictly beats pcap-broker: disk durability both ends, byte-exact resume, link zstd, and per-client non-blocking fan-out vs 1s head-of-line blocking.

**High-severity holes the synthesis had to fix:**
- (1) Vulnbox hard power-loss mid-frame. The capturer is appending PKT bodies to the active spool segment .pcap and updating the .idx. The design fsyncs the active segment tail only on a 1s timer and on — *fix:* On capturer startup, run a recovery pass on the newest segment per source: scan forward validating each pcap record header (caplen<=snaplen, ts sane), truncate the .pcap to the last fully-valid record boundary, rebuild/truncate the .idx to 
- (2) SSH dies after the agent sent bytes but before the collector durably wrote/acked them. The design's happy path (collector re-requests --resume=A, agent replays [A,...)) is correct for loss. The re — *fix:* Do NOT define resume on post-compression wire bytes. Define it on a stable logical coordinate the agent controls deterministically: a per-source monotonic UNCOMPRESSED pcap record offset (or per-source packet index), persisted in the .idx. 
- (4) Spool fills to cap while collector is still behind, so the last-acked offset points into a segment the janitor is about to delete. Honest GAP handling is described, but a RACE is not: janitor and  — *fix:* Add explicit janitor/serve coordination: the agent keeps an authoritative 'oldest retained offset' that the janitor advances atomically BEFORE unlinking; serve clamps every resume to >= that value and ALWAYS emits an exact GAP record (reque
- (5) Collector is slower than capture for several minutes (tulip host CPU-bound on decompress+fan-out+disk while its own assembler/suricata saturate the box). Capture stays decoupled and keeps spooling — *fix:* Never close the suricata-facing client on slow-write; block-with-large-buffer instead, OR change the suricata integration to a reconnecting wrapper (`while true; do socat ... | suricata -r /dev/stdin; done`) and serve suricata from a durabl
- (6) Overlapping/duplicate data on resume (general case of #3). Acks are coarse (every 256 packets or 1s), so resume re-requests a window the collector partly saw. The Seq dedupe is per-(SourceID,Frame — *fix:* Align the durable ack boundary to the atomic replay unit. Either (a) ack only at whole-frame granularity so a replayed batch is always fully-before-ack (dropped wholesale) or fully-after (written wholesale), never split; or (b) give every P
