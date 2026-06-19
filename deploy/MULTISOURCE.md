# Multi-source capture

A source is one capture point (a NIC, a veth, or a whole vulnbox). Each source
is a fully independent pipeline keyed by its `SourceID`, exactly as DESIGN.md §4
specifies ("each own SourceID + spool subdir + manifest + listener; collector
re-serves per-source ports"). There is no shared state between sources, so they
are deployed as independent instances rather than multiplexed onto one
connection — simpler and with no cross-source failure coupling.

## Per source, on the vulnbox

```sh
ipcap agent capture --iface <ifaceN> --src-id <N> --spool-dir /var/lib/ipcap/spool-<N> --exclude-port <portN>
ipcap agent listen  --src-id <N> --spool-dir /var/lib/ipcap/spool-<N> --listen :<portN> --key /etc/ipcap/agent.key --peer <COLLECTOR_PUB>
```

Each `--exclude-port` must include that source's own `--listen` port (the drain
that would otherwise self-capture).

## Per source, on the tulip host

```sh
ipcap collector --src-id <N> --noise-port <portN> --mirror-dir /traffic/src<N> --listen :<reserveN> --key /etc/ipcap/collector.key
```

Point tulip's assembler at every re-serve port via its existing comma-separated
`PCAP_OVER_IP` (e.g. `ipcap-collector:4242,ipcap-collector:4243`), and run one
suricata `socat` per port.

The autoconfig setup generates these per-source units/services from the infra
config; for a single game NIC (the common case) there is exactly one source.
