"""Streaming PCAP -> flow parser (with Phase-2 per-packet signals).

The space-saving trick: a ``.pcap.xz`` is decompressed *on the fly* with the
stdlib ``lzma`` module and fed straight into ``dpkt.pcap.Reader`` -- the 954 MB
plain ``.pcap`` is never written to disk. Already-extracted ``.pcap`` files are
also accepted.

``parse_file`` returns ``(flows, buckets, conns)``:

``flows[(src,dst,sport,dport,proto)]`` -> a mutable stats list
``[first_ts, last_ts, pkts, bytes, syn, synack, fin, rst,
   first_syn_ts, first_synack_ts, retrans, icmp_type, icmp_code, _last_seq]``
(the last entry is transient retransmission state, not persisted).

``buckets[(ip, bucket_ts)]`` -> per-host, per-time-bucket counters
``[pkts_in, pkts_out, bytes_in, bytes_out, syn_in, synack_out, rst, retrans]``
so true packet-rate-over-time survives the raw capture being deleted.

``conns[(ip_a, ip_b, close_type)]`` -> how many TCP connection ATTEMPTS between
that unordered host pair ended that way (see ``classify_close``). Unlike
``flows``, which keys each direction separately, this merges both halves of a
connection -- a close type is a property of the conversation, not of one
direction.

The unit is the ATTEMPT, not the 4-tuple: a retried SYN starts a new record, so a
host that SYNs three times without an answer contributes three
``incomplete_no_synack``. This deliberately matches the archived parquet shards,
which decoded the first 90 minutes the same way -- measured, their
``incomplete_no_synack`` count (1,014,196) tracks the number of SYN packets on
unanswered 4-tuples (1,001,045) to within 1.3%, not the number of such 4-tuples
(326,464). Counting per 4-tuple instead made the two halves of the capture
disagree by ~3x on exactly the signal that flags scanning, so the halves are now
counted the same way. It also makes the measure track connection PRESSURE (how
hard a host is trying) rather than distinct conversations.

The extra per-packet signals (handshake timestamps for RTT, TCP retransmissions,
ICMP type/code) are what Phase 2 needs and the original per-flow aggregates threw
away -- hence a re-parse is required to populate them.
"""
from __future__ import annotations

import argparse
import lzma
import socket
import sys
from pathlib import Path

import dpkt

# Flow stats list indices (a list, not a dict, for speed/memory). The first 13
# are persisted; ``_LAST_SEQ`` is transient state for retransmission detection.
(FIRST_TS, LAST_TS, PKTS, BYTES, SYN, SYNACK, FIN, RST,
 FIRST_SYN_TS, FIRST_SYNACK_TS, RETRANS, ICMP_TYPE, ICMP_CODE, _LAST_SEQ) = range(14)
FLOW_COLS = 13  # number of leading entries written to the DB

# Per-(host, bucket) counter indices.
(B_PKTS_IN, B_PKTS_OUT, B_BYTES_IN, B_BYTES_OUT,
 B_SYN_IN, B_SYNACK_OUT, B_RST, B_RETRANS) = range(8)

# Seconds per time bucket for the persisted host time-series. Coarse enough to
# bound the host_buckets table, fine enough to show a surge curve.
BUCKET_SECONDS = 10

# TCP flag bits.
_TH_FIN = 0x01
_TH_SYN = 0x02
_TH_RST = 0x04
_TH_ACK = 0x10

# Per-connection close-type state indices (a list, as with flows, for speed).
# ``C_INIT`` holds the (ip, port) endpoint that opened the connection -- the only
# side whose bare ACK can complete the handshake.
(C_INIT, C_SYN, C_SYNACK, C_ACK3, C_FIN, C_RST) = range(6)


def _emit(conns: dict, ck: tuple, rec: list) -> None:
    """Count one finished connection attempt into the pair-level rollup.

    IPs are ordered by string comparison, matching
    close_types.build_pair_close_types, so shard-derived and parser-derived rows
    key the same way.
    """
    ip_a, ip_b = ck[0][0], ck[1][0]
    if ip_a > ip_b:
        ip_a, ip_b = ip_b, ip_a
    k = (ip_a, ip_b, classify_close(rec))
    conns[k] = conns.get(k, 0) + 1


def classify_close(rec: list) -> str:
    """Name the way a TCP connection ended, from the flags seen on both halves.

    The rule was recovered from the archived parquet shards, which carry both the
    raw packet flag sequence and the decoder's own ``close_type`` code: replaying
    it reproduces their label on 2,424,166 / 2,425,280 flows (99.954%). Names
    match ``close_types.CODE_TO_NAME`` so shard-derived and parser-derived rows
    share one legend.

    The lone residual is ``invalid_ack`` (0.046%), which needs ACK-number
    validation against sequence space rather than flags alone; those connections
    land in ongoing/graceful/abortive here.
    """
    if not rec[C_SYN] and not rec[C_SYNACK]:
        # Mid-stream: the handshake happened before this capture file began (a
        # long connection, or one straddling the ~50s file boundary). Calling it
        # "incomplete_no_synack" would invent a half-open connection, so judge it
        # on how it ended instead.
        if rec[C_RST]:
            return "abortive"
        return "graceful" if rec[C_FIN] else "ongoing"
    if not rec[C_ACK3]:
        if rec[C_RST]:
            return "rst_during_handshake"
        return "incomplete_no_ack" if rec[C_SYNACK] else "incomplete_no_synack"
    if rec[C_RST]:          # RST outranks FIN: a connection torn down after a
        return "abortive"   # partial graceful close is still abortive.
    return "graceful" if rec[C_FIN] else "ongoing"


def open_capture(path: str | Path):
    """Return a binary file-like for a .pcap or .pcap.xz, streaming if compressed."""
    path = str(path)
    if path.endswith(".xz"):
        return lzma.open(path, "rb")
    return open(path, "rb")


def parse_file(path: str | Path, progress_every: int = 1_000_000) -> tuple[dict, dict, dict]:
    """Parse one capture into ``(flows, buckets, conns)``. Malformed packets are skipped."""
    flows: dict[tuple, list] = {}
    buckets: dict[tuple, list] = {}
    tcp_conns: dict[tuple, list] = {}   # canonical 4-tuple -> OPEN attempt's state
    conns: dict[tuple, int] = {}        # (ip_a, ip_b, close_type) -> attempts
    n = 0

    def bkt(ip, b):
        k = (ip, b)
        r = buckets.get(k)
        if r is None:
            r = [0, 0, 0, 0, 0, 0, 0, 0]
            buckets[k] = r
        return r

    with open_capture(path) as fh:
        reader = dpkt.pcap.Reader(fh)
        for ts, buf in reader:
            n += 1
            if progress_every and n % progress_every == 0:
                print(f"  {Path(path).name}: {n:,} packets", file=sys.stderr)
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue
            ip = eth.data
            if isinstance(ip, dpkt.ip.IP):
                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)
            elif isinstance(ip, dpkt.ip6.IP6):
                src = socket.inet_ntop(socket.AF_INET6, ip.src)
                dst = socket.inet_ntop(socket.AF_INET6, ip.dst)
            else:
                continue  # not IP (ARP, etc.)

            l4 = ip.data
            syn = synack = fin = rst = 0
            syn_ts = synack_ts = 0.0
            itype = icode = -1
            seq = None
            consumes = 0          # TCP sequence space this packet uses (payload + SYN/FIN)
            if isinstance(l4, dpkt.tcp.TCP):
                proto = "tcp"
                sport, dport = l4.sport, l4.dport
                f = l4.flags
                if f & _TH_SYN:
                    if f & _TH_ACK:
                        synack = 1; synack_ts = ts
                    else:
                        syn = 1; syn_ts = ts
                if f & _TH_FIN:
                    fin = 1
                if f & _TH_RST:
                    rst = 1
                seq = l4.seq
                consumes = len(l4.data) + (1 if f & _TH_SYN else 0) + (1 if f & _TH_FIN else 0)
                # Close-type state, keyed so both directions land on one record.
                ep_a = (src, sport)
                ep_b = (dst, dport)
                ck = (ep_a, ep_b) if ep_a < ep_b else (ep_b, ep_a)
                c = tcp_conns.get(ck)
                # ATTEMPT-LEVEL counting: a SYN arriving on a 4-tuple that already
                # carries one opens a NEW attempt, so close the previous one out
                # first. A retried SYN is therefore its own connection -- see the
                # module docstring for why this unit was chosen.
                if c is not None and syn and c[C_SYN]:
                    _emit(conns, ck, c)
                    c = None
                if c is None:
                    # Initiator = whoever sent the SYN. A SYN-ACK means the *peer*
                    # opened it; with neither (mid-stream) assume this sender.
                    c = [ep_b if synack else ep_a, 0, 0, 0, 0, 0]
                    tcp_conns[ck] = c
                if syn:
                    c[C_SYN] = 1; c[C_INIT] = ep_a
                elif synack:
                    c[C_SYNACK] = 1; c[C_INIT] = ep_b
                elif f & _TH_ACK and c[C_SYNACK] and ep_a == c[C_INIT]:
                    c[C_ACK3] = 1   # handshake completed by the initiator's ACK
                if fin:
                    c[C_FIN] = 1
                if rst:
                    c[C_RST] = 1
            elif isinstance(l4, dpkt.udp.UDP):
                proto = "udp"
                sport, dport = l4.sport, l4.dport
            elif isinstance(l4, (dpkt.icmp.ICMP, dpkt.icmp6.ICMP6)):
                proto = "icmp"
                sport = dport = 0
                itype, icode = int(l4.type), int(l4.code)
            else:
                proto = "other"
                sport = dport = 0

            length = len(buf)
            is_retrans = 0
            key = (src, dst, sport, dport, proto)
            rec = flows.get(key)
            if rec is None:
                rec = [ts, ts, 1, length, syn, synack, fin, rst,
                       syn_ts, synack_ts, 0, itype, icode, -1]
                flows[key] = rec
                if proto == "tcp" and consumes > 0:
                    rec[_LAST_SEQ] = seq + consumes
            else:
                if ts < rec[FIRST_TS]:
                    rec[FIRST_TS] = ts
                if ts > rec[LAST_TS]:
                    rec[LAST_TS] = ts
                rec[PKTS] += 1
                rec[BYTES] += length
                rec[SYN] += syn
                rec[SYNACK] += synack
                rec[FIN] += fin
                rec[RST] += rst
                if syn_ts and not rec[FIRST_SYN_TS]:
                    rec[FIRST_SYN_TS] = syn_ts
                if synack_ts and not rec[FIRST_SYNACK_TS]:
                    rec[FIRST_SYNACK_TS] = synack_ts
                if itype >= 0 and rec[ICMP_TYPE] < 0:
                    rec[ICMP_TYPE] = itype; rec[ICMP_CODE] = icode
                # Retransmission heuristic: a sequence-consuming TCP segment whose
                # seq we have already advanced past (covers SYN/data retransmits;
                # pure ACKs consume nothing and are ignored). Wrap is ignored.
                if proto == "tcp" and consumes > 0:
                    last = rec[_LAST_SEQ]
                    if last >= 0 and seq < last:
                        rec[RETRANS] += 1; is_retrans = 1
                    end = seq + consumes
                    if end > last:
                        rec[_LAST_SEQ] = end

            # Per-host time buckets (src = outbound, dst = inbound).
            b = int(ts // BUCKET_SECONDS) * BUCKET_SECONDS
            bs = bkt(src, b)
            bs[B_PKTS_OUT] += 1; bs[B_BYTES_OUT] += length
            if synack:
                bs[B_SYNACK_OUT] += 1
            if rst:
                bs[B_RST] += 1
            if is_retrans:
                bs[B_RETRANS] += 1
            bd = bkt(dst, b)
            bd[B_PKTS_IN] += 1; bd[B_BYTES_IN] += length
            if syn:
                bd[B_SYN_IN] += 1
            if rst:
                bd[B_RST] += 1

    # Close out every attempt still open when the capture ended.
    for ck, c in tcp_conns.items():
        _emit(conns, ck, c)
    return flows, buckets, conns


def _summary(flows: dict) -> dict:
    import datetime as dt

    total_pkts = sum(r[PKTS] for r in flows.values())
    total_bytes = sum(r[BYTES] for r in flows.values())
    total_retrans = sum(r[RETRANS] for r in flows.values())
    mn = min((r[FIRST_TS] for r in flows.values()), default=0)
    mx = max((r[LAST_TS] for r in flows.values()), default=0)
    fmt = lambda t: dt.datetime.fromtimestamp(t, dt.timezone.utc).isoformat() if t else "n/a"
    return {
        "flows": len(flows),
        "packets": total_pkts,
        "bytes": total_bytes,
        "retransmissions": total_retrans,
        "first_ts_utc": fmt(mn),
        "last_ts_utc": fmt(mx),
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Smoke-test the streaming flow parser on one file.")
    ap.add_argument("path", help="path to a .pcap or .pcap.xz")
    ap.add_argument("--limit", type=int, default=0,
                    help="stop after N packets (0 = whole file)")
    args = ap.parse_args()

    if args.limit:
        # Lightweight bounded read for quick checks.
        seen: dict[tuple, float] = {}
        with open_capture(args.path) as fh:
            for i, (ts, buf) in enumerate(dpkt.pcap.Reader(fh)):
                if i >= args.limit:
                    break
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                except Exception:
                    continue
                ip = eth.data
                if not isinstance(ip, dpkt.ip.IP):
                    continue
                seen[(socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst))] = ts
        print(f"read {args.limit} packets, {len(seen)} distinct v4 src/dst pairs")
    else:
        flows, buckets, conns = parse_file(args.path)
        import collections
        import json
        by_type = collections.Counter()
        for (_a, _b, ct), n in conns.items():
            by_type[ct] += n
        print(json.dumps({**_summary(flows), "host_buckets": len(buckets),
                          "connections": sum(by_type.values()),
                          "close_types": dict(by_type.most_common())}, indent=2))
