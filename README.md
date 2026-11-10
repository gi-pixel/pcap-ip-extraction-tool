
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

One small thing worth flagging for your review: dpkt's `dpkt.socket` re-export is used for `inet_ntop`. If you'd rather avoid that implicit dependency, I can swap it for `socket.inet_ntop` from the stdlib — functionally identical and more explicit. Let me know and I'll adjust.git push -u origin main.



## Enrichment

Enrichment runs **after** aggregation, **once per unique IP**, and is **off by
default**. Enable with `--enrich asn`.

### Adding an enricher

Implement the `Enricher` protocol (`src/pcapscope/enrich/base.py`):

```python
class GeoEnricher:
    name = "geo"                        # key under IPStats.enriched

    def enrich(self, ip: str) -> dict | None:
        ...



## 2. The `bytes` column naming (still open from the last review)

`format_table` and `format_csv` emit a column called `bytes` that is actually `total_bytes` (sent + received). Two acceptable resolutions:

- **Keep it**, and add one line to the README: *"`bytes` = bytes_sent + bytes_received."*
- **Split it** into `bytes_sent` and `bytes_received`, matching the JSON output.

I lean toward keeping the collapsed column in the table (it's what a human scanning a report wants) and splitting it in CSV (what a script wants). That would be a small, defensible change to `format_csv` only — `test_formatters` still passes because it asserts `"8.8.8.8" in out`, not column count. Your call; either is spec-compliant as long as it's documented.

## 3. `.gitattributes` on Windows

You're editing on Windows and running on WSL. One CRLF regression on a `.py` file and `pytest` dies with a `SyntaxError` on line 1 that looks like a code bug but isn't. Prevent it once:

```gitattributes
* text=auto eol=lf
*.pcap binary
*.pcapng binary
*.png binary


### Scopes

| Scope | Covers | Included in `--public-only` / `--enrich` |
|---|---|---|
| `public` | Globally routable addresses | Yes |
| `private` | RFC1918 (`10/8`, `172.16/12`, `192.168/16`) and `fc00::/7` | No |
| `shared` | CGNAT `100.64.0.0/10` | No |
| `loopback` | `127.0.0.0/8`, `::1` | No |
| `link_local` | `169.254.0.0/16`, `fe80::/10` | No |
| `multicast` | `224.0.0.0/4`, `ff00::/8` | No |
| `reserved` | Everything else not globally routable | No |

CGNAT addresses are labelled `shared` and excluded from both `--public-only`
and `--enrich`. IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is classified by its
embedded IPv4 address.

### Byte accounting

The `ip bytes` column is the sum of IP total-length fields — IP bytes, not
frame bytes. It excludes the Ethernet header (14 bytes), any VLAN tag, and
Ethernet padding. To compare against `tshark -z endpoints` or Wireshark's
Statistics → Endpoints, add `14 × packets` (plus VLAN tags and padding where
present); the figures will then match.