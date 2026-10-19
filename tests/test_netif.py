from pathlib import Path

from utils import netif

PROC_DEV_HEADER = (
    "Inter-|   Receive                                                |  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs"
    " drop fifo colls carrier compressed\n"
)


def make_tree(tmp_path: Path, spec: dict):
    """spec: {name: (link_type, operstate, rx_packets, tx_packets)} -> (sys_net, proc_dev)."""
    sys_net = tmp_path / "sys_class_net"
    sys_net.mkdir()
    lines = [PROC_DEV_HEADER]
    for name, (link_type, state, rx, tx) in spec.items():
        d = sys_net / name
        d.mkdir()
        (d / "type").write_text(f"{link_type}\n")
        (d / "operstate").write_text(f"{state}\n")
        lines.append(f"{name:>8}: 1000 {rx} 0 0 0 0 0 0 2000 {tx} 0 0 0 0 0 0\n")
    proc_dev = tmp_path / "proc_net_dev"
    proc_dev.write_text("".join(lines))
    return sys_net, proc_dev


def listing(tmp_path, spec, ips=None):
    sys_net, proc_dev = make_tree(tmp_path, spec)
    ips = ips or {}
    return netif.list_interfaces(sys_net, proc_dev, ipv4_lookup=lambda n: ips.get(n))


def by_name(items):
    return {i.name: i for i in items}


def test_list_reads_type_state_counters_and_ip(tmp_path):
    items = by_name(listing(
        tmp_path,
        {"wlan0": (1, "up", 100, 50), "ccmni1": (519, "unknown", 7, 3), "lo": (772, "unknown", 1, 1)},
        {"wlan0": "192.168.1.50"},
    ))
    assert items["wlan0"].link_type == 1 and items["wlan0"].link_kind == "ethernet"
    assert items["wlan0"].ipv4 == "192.168.1.50" and items["wlan0"].packets == 150
    assert items["ccmni1"].link_kind == "raw" and items["ccmni1"].operstate == "unknown"
    assert items["lo"].skipped


def test_link_kind_mapping():
    assert netif.link_kind_from_type(1) == "ethernet"
    assert netif.link_kind_from_type(519) == "raw"
    assert netif.link_kind_from_type(512) == "raw"
    assert netif.link_kind_from_type(0xFFFE) == "raw"
    assert netif.link_kind_from_type(None) == "unknown"
    assert netif.link_kind_from_type(9999) == "unknown"


def test_link_kind_for_reads_sysfs(tmp_path):
    sys_net, _ = make_tree(tmp_path, {"wlan0": (1, "up", 1, 1), "rmnet_data1": (519, "unknown", 1, 1)})
    assert netif.link_kind_for("wlan0", sys_net) == "ethernet"
    assert netif.link_kind_for("rmnet_data1", sys_net) == "raw"
    assert netif.link_kind_for("missing0", sys_net) == "unknown"


def test_prefers_wlan0_over_cellular(tmp_path):
    items = listing(tmp_path, {
        "wlan0": (1, "up", 10, 10), "ccmni1": (519, "unknown", 9999, 9999),
    }, {"wlan0": "192.168.1.5", "ccmni1": "10.1.2.3"})
    chosen, warnings = netif.choose_interface(items)
    assert chosen.name == "wlan0" and warnings == []


def test_cellular_when_wifi_down(tmp_path):
    items = listing(tmp_path, {
        "wlan0": (1, "down", 0, 0), "ccmni1": (519, "unknown", 500, 400),
        "ccmni2": (519, "unknown", 5, 5), "ccmni0": (519, "unknown", 0, 0),
    }, {"ccmni1": "10.1.2.3"})
    chosen, _ = netif.choose_interface(items)
    assert chosen.name == "ccmni1"  # most traffic wins; idle ccmni0 is not 'usable'


def test_default_route_breaks_cellular_ties(tmp_path):
    items = listing(tmp_path, {
        "rmnet_data0": (519, "unknown", 900, 900), "rmnet_data2": (519, "unknown", 10, 10),
    }, {"rmnet_data0": "10.0.0.2", "rmnet_data2": "10.0.0.3"})
    chosen, _ = netif.choose_interface(items, default_routes=["rmnet_data2"])
    assert chosen.name == "rmnet_data2"


def test_skips_pseudo_interfaces(tmp_path):
    items = listing(tmp_path, {
        "lo": (772, "unknown", 5, 5), "dummy0": (1, "up", 5, 5), "sit0": (776, "down", 5, 5),
        "ip6tnl0": (769, "down", 5, 5), "p2p0": (1, "up", 5, 5), "bond0": (1, "up", 5, 5),
    }, {n: "10.9.9.9" for n in ("lo", "dummy0", "sit0", "ip6tnl0", "p2p0", "bond0")})
    chosen, _ = netif.choose_interface(items)
    assert chosen is None
    assert all(i.skipped for i in items)


def test_vpn_is_warned_never_auto_selected(tmp_path):
    items = listing(tmp_path, {
        "wlan0": (1, "up", 10, 10), "tun0": (0xFFFE, "unknown", 50, 50),
    }, {"wlan0": "192.168.1.5", "tun0": "10.8.0.2"})
    chosen, warnings = netif.choose_interface(items)
    assert chosen.name == "wlan0"
    assert warnings and "VPN" in warnings[0] and "tun0" in warnings[0]


def test_hotspot_with_traffic_is_picked_when_wlan0_is_down(tmp_path):
    items = listing(tmp_path, {
        "wlan0": (1, "down", 0, 0), "ap0": (1, "up", 99, 99), "ccmni1": (519, "unknown", 5000, 5000),
    }, {"ap0": "192.168.43.1", "ccmni1": "10.1.2.3"})
    assert by_name(items)["ap0"].category == "hotspot"
    chosen, _ = netif.choose_interface(items)
    assert chosen.name == "ap0"  # hotspot with traffic beats cellular


def test_hotspot_without_traffic_is_not_picked(tmp_path):
    items = listing(tmp_path, {"ap0": (1, "up", 0, 0), "swlan0": (1, "up", 0, 0)},
                    {"ap0": "192.168.43.1", "swlan0": "192.168.44.1"})
    chosen, _ = netif.choose_interface(items)
    assert chosen is None  # idle hotspot interfaces need an explicit --iface


def test_wlan0_beats_hotspot(tmp_path):
    items = listing(tmp_path, {"wlan0": (1, "up", 1, 1), "ap0": (1, "up", 999, 999)},
                    {"wlan0": "192.168.1.5", "ap0": "192.168.43.1"})
    assert netif.choose_interface(items)[0].name == "wlan0"


def test_default_route_interface_wins_over_wlan0(tmp_path):
    items = listing(tmp_path, {"wlan0": (1, "up", 5, 5), "ccmni1": (519, "unknown", 5, 5)},
                    {"wlan0": "192.168.1.5", "ccmni1": "10.1.2.3"})
    assert netif.choose_interface(items, default_routes=["ccmni1"])[0].name == "ccmni1"


def test_default_route_on_vpn_is_ignored_but_warned(tmp_path):
    items = listing(tmp_path, {"wlan0": (1, "up", 5, 5), "tun0": (0xFFFE, "unknown", 50, 50)},
                    {"wlan0": "192.168.1.5", "tun0": "10.8.0.2"})
    chosen, warnings = netif.choose_interface(items, default_routes=["tun0"])
    assert chosen.name == "wlan0" and warnings


def test_unreadable_sysfs_attributes_never_crash_listing(tmp_path, monkeypatch):
    sys_net, proc_dev = make_tree(tmp_path, {"wlan0": (1, "up", 1, 2), "ccmni1": (519, "unknown", 3, 4)})
    (sys_net / "ccmni1" / "operstate").unlink()          # ENOENT (ROM hides the attribute)
    (sys_net / "ccmni1" / "type").unlink()
    (sys_net / "wlan0" / "type").unlink()
    (sys_net / "wlan0" / "type").mkdir()                  # reading a directory -> EISDIR
    real = type(sys_net).read_text

    def deny(self, *a, **k):
        if self.name == "operstate" and self.parent.name == "wlan0":
            raise PermissionError(13, "EACCES")
        return real(self, *a, **k)

    monkeypatch.setattr(type(sys_net), "read_text", deny)
    items = by_name(netif.list_interfaces(sys_net, proc_dev, ipv4_lookup=lambda n: None))
    assert set(items) == {"wlan0", "ccmni1"}
    assert items["wlan0"].operstate == "unknown" and items["wlan0"].link_type is None
    assert items["ccmni1"].link_kind == "unknown" and items["ccmni1"].packets == 7


def test_sysfs_directory_unreadable_uses_proc_net_dev(tmp_path, monkeypatch):
    _, proc_dev = make_tree(tmp_path, {"wlan0": (1, "up", 3, 4)})
    real_iterdir = Path.iterdir

    def boom(self):
        raise PermissionError(13, "EACCES")

    monkeypatch.setattr(Path, "iterdir", boom)
    try:
        items = netif.list_interfaces(tmp_path / "sys_class_net", proc_dev, ipv4_lookup=lambda n: "1.2.3.4")
    finally:
        monkeypatch.setattr(Path, "iterdir", real_iterdir)
    assert [i.name for i in items] == ["wlan0"]


def test_ipv4_lookup_exceptions_are_contained(tmp_path):
    sys_net, proc_dev = make_tree(tmp_path, {"wlan0": (1, "up", 1, 1)})

    def boom(_n):
        raise OSError(13, "netlink blocked")

    items = netif.list_interfaces(sys_net, proc_dev, ipv4_lookup=boom)
    assert items[0].ipv4 is None


def test_desktop_linux_ethernet_fallback(tmp_path):
    items = listing(tmp_path, {"enp3s0": (1, "up", 40, 40), "docker0": (1, "up", 1, 1)},
                    {"enp3s0": "10.0.0.8", "docker0": "172.17.0.1"})
    chosen, _ = netif.choose_interface(items)
    assert chosen.name == "enp3s0"


def test_missing_sysfs_falls_back_to_proc_net_dev(tmp_path):
    _, proc_dev = make_tree(tmp_path, {"wlan0": (1, "up", 3, 4)})
    items = netif.list_interfaces(tmp_path / "does-not-exist", proc_dev, ipv4_lookup=lambda n: "1.2.3.4")
    assert [i.name for i in items] == ["wlan0"]
    assert items[0].operstate == "unknown" and items[0].link_type is None


def test_parse_proc_net_dev_and_default_routes(tmp_path):
    _, proc_dev = make_tree(tmp_path, {"wlan0": (1, "up", 11, 22)})
    assert netif.parse_proc_net_dev(proc_dev) == {"wlan0": (11, 22)}

    route = tmp_path / "route"
    route.write_text(
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
        "wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"
        "ccmni1\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
        "wlan0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n"
    )
    assert netif.default_route_ifaces(route) == ["ccmni1", "wlan0"]
    assert netif.default_route_ifaces(tmp_path / "nope") == []


def test_ipv6_addresses_and_local_addresses(tmp_path):
    inet6 = tmp_path / "if_inet6"
    inet6.write_text(
        "20010db8000000000000000000000001 05 40 00 80 ccmni1\n"
        "fe800000000000000000000000000002 05 40 20 80 ccmni1\n"
        "20010db8000000000000000000000009 06 40 00 80 wlan0\n"
    )
    assert netif.ipv6_addresses("ccmni1", inet6) == ["2001:db8::1", "fe80::2"]
    addrs = netif.local_addresses("ccmni1", ipv4_lookup=lambda n: "10.1.2.3", inet6_path=inet6)
    assert addrs == {"10.1.2.3", "2001:db8::1", "fe80::2"}


def test_local_addresses_survives_lookup_failure(tmp_path):
    def boom(_name):
        raise OSError("netlink blocked")

    assert netif.local_addresses("wlan0", ipv4_lookup=boom, inet6_path=tmp_path / "none") == set()


def test_format_table_has_expected_columns(tmp_path):
    items = listing(tmp_path, {"wlan0": (1, "up", 1, 2), "lo": (772, "unknown", 0, 0)},
                    {"wlan0": "192.168.1.9"})
    text = netif.format_iface_table(items)
    assert "NAME" in text and "wlan0" in text and "192.168.1.9" in text and "1/ethernet" in text
