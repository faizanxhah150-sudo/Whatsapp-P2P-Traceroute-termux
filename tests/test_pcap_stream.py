"""tcpdump pcap-stream parser: byte orders, timestamp precision, link types, partial data."""
import pytest

from core.pcap_stream import (
    MAX_CAPLEN,
    PcapStreamError,
    PcapStreamParser,
)
from tests.frames import (
    ether,
    pcap_bytes,
    pcap_header,
    pcap_record,
    sll,
    sll2,
    udp4,
)

IP = udp4("10.1.2.3", "157.240.1.5", 40000, 40001)
ETH = ether(IP)

COMBOS = [(e, n, lt) for e in ("<", ">") for n in (False, True) for lt in (1, 101, 12)]


@pytest.mark.parametrize("endian,nano,linktype", COMBOS)
def test_byte_orders_precisions_and_linktypes(endian, nano, linktype):
    payload = ETH if linktype == 1 else IP
    stream = pcap_bytes([payload, payload], endian=endian, nano=nano, linktype=linktype)
    p = PcapStreamParser()
    frames = p.feed(stream)
    assert len(frames) == 2 and p.linktype == linktype and p.leftover == 0
    assert frames[0].data == payload
    assert frames[0].kind == ("ethernet" if linktype == 1 else "raw")
    assert frames[0].direction is None
    assert abs(frames[0].ts - 1700000000.5) < 1e-6 and abs(frames[1].ts - 1700000001.5) < 1e-6


def test_one_byte_at_a_time():
    stream = pcap_bytes([ETH, ETH, ETH], linktype=1)
    p = PcapStreamParser()
    frames = []
    for i in range(len(stream)):
        frames += p.feed(stream[i:i + 1])
    assert len(frames) == 3 and all(f.data == ETH for f in frames) and p.leftover == 0


def test_arbitrary_chunk_boundaries():
    stream = pcap_bytes([IP] * 10, linktype=101)
    for size in (7, 23, 24, 25, 40, 1000):
        p = PcapStreamParser()
        got = []
        for i in range(0, len(stream), size):
            got += p.feed(stream[i:i + size])
        assert len(got) == 10, size


def test_linux_cooked_sll_strips_header_and_reports_direction():
    stream = pcap_bytes([sll(4, IP), sll(0, IP), sll(3, IP)], linktype=113)
    frames = PcapStreamParser().feed(stream)
    assert [f.direction for f in frames] == ["out", "in", None]
    assert all(f.data == IP and f.kind == "raw" for f in frames)


def test_linux_cooked_sll2():
    frames = PcapStreamParser().feed(pcap_bytes([sll2(4, IP), sll2(0, IP)], linktype=276))
    assert [f.direction for f in frames] == ["out", "in"] and frames[0].data == IP


def test_bsd_null_loopback_header_stripped():
    frames = PcapStreamParser().feed(pcap_bytes([b"\x02\x00\x00\x00" + IP], linktype=0))
    assert frames[0].data == IP and frames[0].kind == "raw"


def test_fcs_bits_in_network_field_are_masked():
    stream = pcap_header(linktype=0x10000001) + pcap_record(ETH)
    assert len(PcapStreamParser().feed(stream)) == 1


def test_truncated_stream_delivers_complete_frames_and_keeps_leftover():
    stream = pcap_bytes([ETH, ETH], linktype=1)
    cut = stream[:-10]  # second packet cut mid-payload
    p = PcapStreamParser()
    frames = p.feed(cut)
    assert len(frames) == 1 and p.leftover > 0
    frames += p.feed(stream[-10:])  # the rest arrives later
    assert len(frames) == 2 and p.leftover == 0


def test_truncated_global_header_waits_quietly():
    p = PcapStreamParser()
    assert p.feed(pcap_header()[:10]) == [] and p.leftover == 10


def test_truncated_record_header_waits_quietly():
    p = PcapStreamParser()
    assert p.feed(pcap_header() + b"\x00" * 7) == [] and p.leftover == 7


def test_large_packet():
    big = udp4("10.1.2.3", "157.240.1.5", 1, 2)[:20] + b"\x00" * 60000
    frames = PcapStreamParser().feed(pcap_bytes([big], linktype=101))
    assert len(frames) == 1 and len(frames[0].data) == len(big)


def test_bad_magic_unsupported_linktype_and_corrupt_length_raise():
    with pytest.raises(PcapStreamError, match="magic"):
        PcapStreamParser().feed(b"\x00" * 40)
    with pytest.raises(PcapStreamError, match="linktype 147"):
        PcapStreamParser().feed(pcap_header(linktype=147))
    corrupt = pcap_header() + pcap_record(b"x" * 10)[:8] + (MAX_CAPLEN + 1).to_bytes(4, "little") + b"\0" * 4
    with pytest.raises(PcapStreamError, match="corrupt"):
        PcapStreamParser().feed(corrupt)


def test_short_sll_frame_is_skipped_not_fatal():
    frames = PcapStreamParser().feed(pcap_bytes([b"\x00" * 5, sll(4, IP)], linktype=113))
    assert len(frames) == 1
