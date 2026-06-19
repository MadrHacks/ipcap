# TLS decryption keys (eCapture → ipcap → SSLKEYLOGFILE)

ipcap can carry TLS session keys alongside the packets so a TLS-aware tulip pass
can decrypt captured traffic. The pipeline is:

```
eCapture (uprobes on libssl)  ->  NSS keylog file
        │ (writes CLIENT_RANDOM ... lines)
        ▼
ipcap agent listen --keylog-file <file>   (relays each line as a TLS_KEYLOG frame)
        │ (over the existing Noise link, alongside packets)
        ▼
ipcap collector --sslkeylog-file <file>   (dedupes, appends to an SSLKEYLOGFILE)
        │
        ▼
future tulip TLS pass: pcap + SSLKEYLOGFILE -> plaintext
```

The keys ride the same Noise connection as the packets (TLS_KEYLOG, frame type
0xA0, high-bit *skippable* so a key-unaware collector ignores them). They carry
no resume state: the agent re-sends every key on each reconnect and the collector
dedupes, so a dropped key only costs decryptability of that one flow — it never
affects packet capture. **Capture and keys are independent; nothing here can
disrupt the vulnservices.**

## Running eCapture on the vulnbox

eCapture (https://github.com/MadrHacks/ecapture) hooks libssl via eBPF uprobes —
read-only kernel-side breakpoints that do **not** modify or pause the target
process. The keylog mode writes NSS keylog lines:

```sh
# Hook every process using the system libssl and stream keys to the file ipcap relays.
ecapture tls -m keylog -k /var/lib/ipcap/ssl_keys.log
# Then point the agent at it:
ipcap agent listen ... --keylog-file /var/lib/ipcap/ssl_keys.log
# And the collector:
ipcap collector ... --sslkeylog-file /traffic/sslkeylog.txt
```

Without `--pid`, eCapture attaches to all processes mapping the target libssl, so
no per-service setup is needed. For vulnservices that bundle their own libssl in
a container image, pass `--libssl=<path-inside-the-merged-rootfs>` (the host sees
container libraries under the container's overlay mount); run one eCapture per
distinct libssl. Go-TLS services need `ecapture gotls` instead (uprobe on the Go
runtime; requires the binary's `--elfpath`).

## Safety

eBPF uprobes are non-disruptive: if eCapture fails to attach (unsupported kernel,
missing BTF, stripped library) it simply captures no keys — the service keeps
running and ipcap keeps capturing packets. In doubt, **favor leaving services
untouched over capturing every key**: start eCapture against one service, confirm
the vulnservice is unaffected, then widen. Never co-locate eCapture with a flaky
service mid-round.
