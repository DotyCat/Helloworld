#!/usr/bin/env python3
from pathlib import Path
import stat
import sys

BASE = Path("/tmp/passwall-sync/luci-app-passwall")


def fail(msg):
    print(f"ERROR: {msg}")
    sys.exit(1)


def read(path):
    if not path.exists():
        fail(f"missing file: {path}")
    return path.read_text(encoding="utf-8", errors="ignore")


def write(path, text):
    path.write_text(text, encoding="utf-8")


def patch_global_lua():
    path = BASE / "luasrc/model/cbi/passwall/client/global.lua"
    text = read(path)
    lines = text.splitlines()

    idx = None
    for i, line in enumerate(lines):
        if "filter_proxy_ipv6" in line and "Filter Proxy Host IPv6" in line:
            idx = i
            break

    if idx is None:
        fail("filter_proxy_ipv6 option not found in global.lua")

    end = min(idx + 12, len(lines))
    has_default = False
    has_rmempty = False
    default_idx = None

    for i in range(idx + 1, end):
        line = lines[i].strip()

        if line.startswith("o.default"):
            lines[i] = 'o.default = "1"'
            has_default = True
            default_idx = i

        if line == "o.rmempty = false":
            has_rmempty = True

        if i > idx + 1 and line.startswith("o = "):
            break

    if not has_default:
        default_idx = idx + 1
        lines.insert(default_idx, 'o.default = "1"')

    if not has_rmempty:
        lines.insert(default_idx + 1, "o.rmempty = false")

    write(path, "\n".join(lines) + "\n")
    print("OK: patched global.lua")


def patch_other_lua():
    path = BASE / "luasrc/model/cbi/passwall/client/other.lua"
    text = read(path)

    if "ipv6_leak_protect" in text:
        print("SKIP: other.lua already has ipv6_leak_protect")
        return

    marker = 'o = s:option(Flag, "accept_icmp", translate("Hijacking ICMP (PING)"))'
    if marker not in text:
        fail("accept_icmp marker not found in other.lua")

    block = '''
---- IPv6 Leak Guard
o = s:option(Flag, "ipv6_leak_protect", translate("Block IPv6 Leak"),
	translate("When IPv6 TProxy is disabled, block direct IPv6 traffic to avoid ISP IPv6 leak. Disable this only if your node supports IPv6 and you enable IPv6 TProxy."))
o.default = "1"
o.rmempty = false
o:depends("ipv6_tproxy", "0")
o.remove = function(self, section)
	-- Do not delete while hidden
end

'''

    text = text.replace(marker, block + marker, 1)
    write(path, text)
    print("OK: patched other.lua")


def patch_uci_defaults():
    path = BASE / "root/etc/uci-defaults/luci-passwall"
    text = read(path)

    changed = False

    add_lines = [
        "uci -q set passwall.@global[0].filter_proxy_ipv6='1'",
        "uci -q set passwall.@global_forwarding[0].ipv6_leak_protect='1'",
    ]

    if "passwall.@global[0].filter_proxy_ipv6" not in text:
        marker = "uci -q commit passwall"
        if marker not in text:
            fail("uci commit marker not found in luci-passwall")

        text = text.replace(marker, "\n".join(add_lines) + "\n" + marker, 1)
        changed = True

    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    if changed:
        write(path, text)
        print("OK: patched luci-passwall uci-defaults")
    else:
        print("SKIP: luci-passwall uci-defaults already patched")


def patch_default_config():
    path = BASE / "root/usr/share/passwall/0_default_config"
    text = read(path)

    if "option ipv6_leak_protect" in text:
        print("SKIP: 0_default_config already patched")
        return

    marker = "\toption ipv6_tproxy '0'"
    if marker not in text:
        marker = "option ipv6_tproxy '0'"

    if marker not in text:
        fail("ipv6_tproxy marker not found in 0_default_config")

    text = text.replace(marker, marker + "\n\toption ipv6_leak_protect '1'", 1)
    write(path, text)
    print("OK: patched 0_default_config")


def patch_nftables():
    path = BASE / "root/usr/share/passwall/nftables.sh"
    text = read(path)

    if "IPV6_LEAK_GUARD_DROP" in text:
        print("SKIP: nftables.sh already patched")
        return

    lines = text.splitlines()
    insert_idx = None

    for i, line in enumerate(lines):
        if "TCP_UDP" in line and "UDP_NODE=$TCP_NODE" in line:
            insert_idx = i
            break

    if insert_idx is None:
        fail("TCP_UDP / UDP_NODE marker not found in nftables.sh")

    block = [
        "",
        "\t# IPv6 leak guard: when node/VPS has no IPv6 and IPv6 TProxy is disabled,",
        "\t# block direct IPv6 so clients do not leak ISP/telco IPv6.",
        '\t[ "$PROXY_IPV6" != "1" ] && [ "$(config_t_get global_forwarding ipv6_leak_protect 1)" = "1" ] && {',
        '\t\tnft "add rule $NFTABLE_NAME mangle_prerouting meta nfproto ipv6 ip6 daddr @$NFTSET_LAN6 counter return comment \\"IPV6_LEAK_GUARD_LAN_RETURN\\""',
        '\t\tnft "add rule $NFTABLE_NAME mangle_prerouting meta nfproto ipv6 counter drop comment \\"IPV6_LEAK_GUARD_DROP\\""',
        '\t\tnft "add rule $NFTABLE_NAME mangle_output meta nfproto ipv6 ip6 daddr @$NFTSET_LAN6 counter return comment \\"IPV6_LEAK_GUARD_OUTPUT_LAN_RETURN\\""',
        '\t\tnft "add rule $NFTABLE_NAME mangle_output meta nfproto ipv6 counter drop comment \\"IPV6_LEAK_GUARD_OUTPUT_DROP\\""',
        '\t\techolog "  - IPv6 leak guard enabled: direct IPv6 blocked because IPv6 TProxy is disabled"',
        "\t}",
        "",
    ]

    lines[insert_idx:insert_idx] = block
    write(path, "\n".join(lines) + "\n")
    print("OK: patched nftables.sh")


def main():
    if not BASE.exists():
        fail(f"PassWall folder not found: {BASE}")

    patch_global_lua()
    patch_other_lua()
    patch_uci_defaults()
    patch_default_config()
    patch_nftables()

    print("Done: PassWall IPv6 leak guard patch applied.")


if __name__ == "__main__":
    main()
