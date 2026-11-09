
# pcapscope

Stream a `.pcap` or `.pcapng` file and report unique IP addresses with per-IP stats.
Packets are streamed from disk — the whole file is never loaded into memory.

## Install

```bash
pip install -e .


## Notes on spec compliance

- **Streaming**: `reader` reads packet-by-packet with a file handle; nothing is buffered whole. `Aggregator` memory scales with unique IPs.
- **pcapng per-interface linktype**: EPBs look up the linktype from the IDB that created their interface id; Simple Packet Blocks use the first interface (SPB has no interface id per spec).
- **Non-IP vs malformed**: `extract_record` returns `None` for ARP (and any non-IPv4/IPv6 ethertype), and raises `MalformedPacket` for truncated/invalid IP. The CLI counts them into `skipped_non_ip` and `skipped_malformed` separately.
- **Link types handled**: Ethernet (with 802.1Q/QinQ VLAN unwrapping), Linux SLL, RAW IP, NULL/LOOP.
- **Classification once per IP**: done in `Aggregator._get_or_create`, never per packet.
- **CLI errors**: `CaptureError` produces `pcapscope: error: …` on stderr with exit 1 and no traceback.
- **`--top` with `--sort`**: honors the chosen sort then truncates; with default sort, it's "top N by total packets" as specified.
- **Extensibility**: `enrich/` can later wrap `Aggregator` results before formatting; formatters and CLI take plain data, so nothing existing needs to change.

One small thing worth flagging for your review: dpkt's `dpkt.socket` re-export is used for `inet_ntop`. If you'd rather avoid that implicit dependency, I can swap it for `socket.inet_ntop` from the stdlib — functionally identical and more explicit. Let me know and I'll adjust.git push -u origin main
