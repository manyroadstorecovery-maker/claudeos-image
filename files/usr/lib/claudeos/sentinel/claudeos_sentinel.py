#!/usr/bin/python3 -I
"""ClaudeOS network sentinel — always on, no AI. Runs as a locked-down system service.

What it watches
  - devices on your home network (ARP, DHCP, mDNS; plus a gentle ARP check every 15 min)
  - the router's hardware address changing (a classic sign of a "man in the middle" attack)
  - every website name this computer looks up (DNS)
  - which program connects where (with the website name when known)
  - programs that open a door for incoming connections (listening ports)
  - remote-access / remote-control tools (AnyDesk, TeamViewer, VNC, ...): running, installed,
    looked up or connected to
  - things set to start automatically (systemd units, autostart entries, cron, SSH keys, ...)

What it writes: one line per event to the system journal (journalctl -u claudeos-sentinel):
  ALERT {json}  serious (priority warning) or notable (priority notice)
  DEVICE/DNS/CONN/SNAPSHOT/INFO {json}  plain log (priority info)
The ClaudeOS notifier turns ALERT lines into pop-ups and asks Claude to explain serious ones.

Everything it reads from the network is treated as untrusted text: lengths are capped and
non-printable characters removed before logging.
"""
import ctypes
import fcntl
import json
import os
import re
import select
import socket
import struct
import sys
import time
import hashlib
from pathlib import Path

STATE_DIR = Path(os.environ.get("STATE_DIRECTORY", "/var/lib/claudeos-sentinel"))
STATE_FILE = STATE_DIR / "state.json"
OUI_FILE = Path("/usr/share/hwdata/oui.txt")
LEARN_SECONDS = 3600          # first hour: learn what's normal, don't alert on "new" things
CONN_POLL, SLOW_POLL, AUTOSTART_POLL, SWEEP_EVERY = 5, 30, 300, 900
REPEAT_LOG = 6 * 3600         # log the same DNS name / connection at most every 6 h
MAX_DEVICES, MAX_PROGRAMS = 4096, 2048

ETH_P_ALL, ETH_P_ARP, ETH_P_IP, ETH_P_IPV6 = 0x0003, 0x0806, 0x0800, 0x86DD
PACKET_OUTGOING = 4

# Remote-access / remote-control tools. A match is always serious, learning period or not.
REMOTE_TOOLS = re.compile(
    r"anydesk|teamviewer|rustdesk|x11vnc|wayvnc|vncserver|xvnc|tigervnc|krfb|gnome-remote-desktop|"
    r"chrome-remote|remoting_host|splashtop|srservice|screenconnect|connectwise|meshagent|ammyy|"
    r"ultraviewer|supremo|dwagent|dwservice|ngrok|cloudflared|frpc|chisel|tmate|logmein|gotoassist|"
    r"zohoassist|remotepc|nomachine|nxserver|parsec|getscreen|aeroadmin|litemanager|radmin",
    re.I)
REMOTE_DOMAINS = re.compile(
    r"(^|\.)(anydesk\.com|teamviewer\.com|rustdesk\.com|screenconnect\.com|connectwise\.com|"
    r"splashtop\.com|ngrok\.(io|com|app)|ngrok-free\.app|logmein\.com|gotomypc\.com|remotepc\.com|"
    r"ultraviewer\.net|ammyy\.com|supremocontrol\.com|dwservice\.net|meshcentral\.com|"
    r"assist\.zoho\.com|getscreen\.me|aeroadmin\.com|tmate\.io|beyondtrust\.com|bomgar\.com)\.?$", re.I)
REMOTE_PORTS = {22: "SSH", 3389: "Windows Remote Desktop", 5900: "VNC", 5901: "VNC", 5902: "VNC",
                5938: "TeamViewer", 6568: "AnyDesk", 7070: "AnyDesk", 21115: "RustDesk",
                21116: "RustDesk", 21117: "RustDesk", 4000: "NoMachine", 8200: "GoToMyPC"}

AUTOSTART_PLACES = [
    "/etc/systemd/system", "/etc/systemd/user", "/etc/xdg/autostart", "/etc/cron.d",
    "/etc/cron.daily", "/etc/cron.hourly", "/var/spool/cron", "/etc/sudoers.d", "/etc/sudoers",
    "/etc/polkit-1/rules.d", "/etc/ld.so.preload", "/etc/profile.d", "/etc/ssh/sshd_config.d",
    "/root/.ssh/authorized_keys", "/var/lib/flatpak/app",
]
HOME_AUTOSTART = [".config/autostart", ".config/systemd/user", ".config/labwc/autostart",
                  ".config/environment.d", ".bashrc", ".bash_profile", ".profile",
                  ".ssh/authorized_keys", ".local/share/flatpak/app"]
SERIOUS_AUTOSTART = re.compile(r"authorized_keys|sudoers|ld\.so\.preload|polkit")


# ---------- small helpers ----------

def clean(text, limit=120):
    """Untrusted text → short, printable, single line."""
    text = text.decode("utf-8", "replace") if isinstance(text, bytes) else str(text)
    return "".join(c if c.isprintable() else "?" for c in text)[:limit]


def emit(kind, data, priority=6):
    """One journal line. <N> prefix sets the journal priority (4 warning, 5 notice, 6 info)."""
    sys.stdout.write(f"<{priority}>{kind} {json.dumps(data, separators=(',', ':'), sort_keys=True)}\n")
    sys.stdout.flush()


def mac_str(raw):
    return ":".join(f"{b:02x}" for b in raw)


def is_randomized(mac):
    return bool(int(mac[:2], 16) & 0x02)


def vendor(mac):
    """Manufacturer from the first half of the hardware address (hwdata's IEEE list)."""
    if is_randomized(mac):
        return "private (randomized) address, typical of phones/tablets/laptops"
    key = mac[:8].replace(":", "-").upper()
    try:
        with open(OUI_FILE, encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith(key) and "(hex)" in line:
                    return clean(line.split("(hex)", 1)[1].strip(), 60)
    except OSError:
        pass
    return "unknown maker"


# ---------- kernel packet filter ----------
# Classic BPF so the kernel hands us only: ARP, and UDP port 53 (DNS) / 67-68 (DHCP) / 5353 (mDNS).

def assemble(program):
    labels, idx = {}, 0
    for ins in program:
        if isinstance(ins, str):
            labels[ins] = idx
        else:
            idx += 1
    out, idx = [], 0
    for ins in program:
        if isinstance(ins, str):
            continue
        op, k, jt, jf = (*ins, None, None)[:4]
        jt = labels[jt] - idx - 1 if jt else 0
        jf = labels[jf] - idx - 1 if jf else 0
        assert 0 <= jt < 256 and 0 <= jf < 256
        out.append(struct.pack("HBBI", op, jt, jf, k))
        idx += 1
    return out


LDH, LDB, LDXB_MSH, LDH_IND, JEQ, JSET, RET = 0x28, 0x30, 0xB1, 0x48, 0x15, 0x45, 0x06


def filter_program():
    def ports(load, *offs):
        seq = []
        for off in offs:
            seq += [(load, off)] + [(JEQ, p, "ACCEPT") for p in (53, 67, 68, 5353)]
        return seq
    return assemble([
        (LDH, 12), (JEQ, ETH_P_ARP, "ACCEPT"), (JEQ, ETH_P_IP, None, "V6"),
        (LDB, 23), (JEQ, 17, None, "DROP"),                 # UDP only
        (LDH, 20), (JSET, 0x1FFF, "DROP"),                  # skip fragments
        (LDXB_MSH, 14),                                     # X = IPv4 header length
        *ports(LDH_IND, 14, 16), (RET, 0),
        "V6", (JEQ, ETH_P_IPV6, None, "DROP"), (LDB, 20), (JEQ, 17, None, "DROP"),
        *ports(LDH, 54, 56),
        "DROP", (RET, 0),
        "ACCEPT", (RET, 0xFFFF),
    ])


def open_capture(iface):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)  # receives nothing until bound
    code = b"".join(filter_program())
    buf = ctypes.create_string_buffer(code)
    fprog = struct.pack("HL", len(code) // 8, ctypes.addressof(buf))
    s.setsockopt(socket.SOL_SOCKET, 26, fprog)  # SO_ATTACH_FILTER (kernel copies it)
    s.bind((iface, ETH_P_ALL))
    s.setblocking(False)
    return s


# ---------- packet parsing (pure functions, tested) ----------

def dns_name(data, off, depth=0):
    labels, jumped, end = [], False, off
    for _ in range(128):
        if off >= len(data):
            raise ValueError("short name")
        n = data[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            if depth > 10 or off + 1 >= len(data):
                raise ValueError("bad pointer")
            ptr = ((n & 0x3F) << 8) | data[off + 1]
            if not jumped:
                end = off + 2
            jumped, depth, off = True, depth + 1, ptr
            continue
        labels.append(data[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    else:
        raise ValueError("name too long")
    return ".".join(labels).lower(), (end if jumped else off)


def parse_dns(data):
    """→ (is_response, [question names], [(name, type, value)])"""
    if len(data) < 12:
        raise ValueError("short dns")
    _id, flags, qd, an = struct.unpack("!HHHH", data[:8])
    off, questions, answers = 12, [], []
    for _ in range(min(qd, 8)):
        name, off = dns_name(data, off)
        off += 4
        questions.append(name)
    for _ in range(min(an, 64)):
        name, off = dns_name(data, off)
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        if rtype == 1 and rdlen == 4:
            answers.append((name, "A", socket.inet_ntop(socket.AF_INET, rdata)))
        elif rtype == 28 and rdlen == 16:
            answers.append((name, "AAAA", socket.inet_ntop(socket.AF_INET6, rdata)))
        elif rtype == 5:
            answers.append((name, "CNAME", dns_name(data, off)[0]))
        off += rdlen
    return bool(flags & 0x8000), questions, answers


def parse_dhcp(data):
    """Client hardware address, host name and vendor from a DHCP request."""
    if len(data) < 240 or data[0] != 1 or data[236:240] != b"\x63\x82\x53\x63":
        return None
    info, off = {"mac": mac_str(data[28:34])}, 240
    while off + 1 < len(data) and data[off] != 255:
        code = data[off]
        if code == 0:
            off += 1
            continue
        ln = data[off + 1]
        val = data[off + 2:off + 2 + ln]
        if code == 12:
            info["name"] = clean(val, 64)
        elif code == 60:
            info["vendor_class"] = clean(val, 64)
        off += 2 + ln
    return info


def parse_frame(frame):
    """Ethernet frame → dict describing what it tells us, or None."""
    if len(frame) < 14:
        return None
    src = mac_str(frame[6:12])
    etype = struct.unpack("!H", frame[12:14])[0]
    if etype == ETH_P_ARP and len(frame) >= 42:
        op = struct.unpack("!H", frame[20:22])[0]
        return {"kind": "arp", "op": op, "mac": mac_str(frame[22:28]),
                "ip": socket.inet_ntop(socket.AF_INET, frame[28:32]), "src": src}
    if etype == ETH_P_IP and len(frame) >= 34:
        ihl = (frame[14] & 0x0F) * 4
        ip_src = socket.inet_ntop(socket.AF_INET, frame[26:30])
        udp = 14 + ihl
        payload = frame[udp + 8:]
    elif etype == ETH_P_IPV6 and len(frame) >= 62:
        ip_src = socket.inet_ntop(socket.AF_INET6, frame[22:38])
        udp = 54
        payload = frame[62:]
    else:
        return None
    sport, dport = struct.unpack("!HH", frame[udp:udp + 4])
    if {sport, dport} & {67, 68}:
        d = parse_dhcp(payload)
        return d and {"kind": "dhcp", **d, "src": src}
    if 5353 in (sport, dport):
        resp, _q, ans = parse_dns(payload)
        names = [n for n, t, v in ans if t in ("A", "AAAA") and n.endswith(".local")]
        return resp and names and {"kind": "mdns", "src": src, "ip": ip_src, "name": clean(names[0], 64)}
    if 53 in (sport, dport):
        resp, q, ans = parse_dns(payload)
        return {"kind": "dns", "response": resp, "questions": q, "answers": ans, "src": src}
    return None


# ---------- /proc readers ----------

TCP_STATES = {"01": "established", "02": "connecting", "0A": "listen"}


def hex_addr(h):
    ip, port = h.split(":")
    raw = bytes.fromhex(ip)
    if len(raw) == 4:
        addr = socket.inet_ntop(socket.AF_INET, raw[::-1])
    else:
        addr = socket.inet_ntop(socket.AF_INET6, b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4)))
        if addr.startswith("::ffff:"):
            addr = addr[7:]
    return addr, int(port, 16)


def is_local(addr):
    return (addr.startswith("127.") or addr in ("::1", "0.0.0.0", "::")
            or addr.startswith("fe80:"))


def read_sockets():
    """Every TCP/UDP socket: (proto, state, local, lport, remote, rport, inode)."""
    out = []
    for proto in ("tcp", "tcp6", "udp", "udp6"):
        try:
            lines = Path(f"/proc/net/{proto}").read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            f = line.split()
            if len(f) < 10:
                continue
            (la, lp), (ra, rp) = hex_addr(f[1]), hex_addr(f[2])
            if proto.startswith("tcp"):
                state = TCP_STATES.get(f[3])
            else:  # UDP: "connected" if it has a remote end, else it's waiting for anyone
                state = "established" if rp else "listen"
            if state:
                out.append((proto[:3], state, la, lp, ra, rp, f[9]))
    return out


def socket_owners():
    """socket inode → pid (needs CAP_SYS_PTRACE to see other users' processes)."""
    owners = {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            for fd in os.listdir(f"/proc/{pid}/fd"):
                link = os.readlink(f"/proc/{pid}/fd/{fd}")
                if link.startswith("socket:["):
                    owners[link[8:-1]] = int(pid)
        except OSError:
            continue
    return owners


def program_of(pid):
    """A stable name for the program: the Flatpak app id, or the executable's path."""
    try:
        cg = Path(f"/proc/{pid}/cgroup").read_text()
        m = re.search(r"app-flatpak-([A-Za-z0-9_.-]+?)-\d+\.scope", cg)
        if m:
            return f"flatpak:{m.group(1)}"
        exe = os.readlink(f"/proc/{pid}/exe").removesuffix(" (deleted)")
        return exe
    except OSError:
        try:
            return "?" + Path(f"/proc/{pid}/comm").read_text().strip()
        except OSError:
            return "?"


def default_route():
    """(interface, gateway ip) for the internet route, from /proc/net/route."""
    try:
        for line in Path("/proc/net/route").read_text().splitlines()[1:]:
            f = line.split()
            if f[1] == "00000000" and int(f[3], 16) & 2:
                return f[0], socket.inet_ntoa(struct.pack("<I", int(f[2], 16)))
    except OSError:
        pass
    return None, None


def iface_info(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        req = struct.pack("256s", iface.encode()[:15])
        ip = socket.inet_ntoa(fcntl.ioctl(s, 0x8915, req)[20:24])     # SIOCGIFADDR
        mask = socket.inet_ntoa(fcntl.ioctl(s, 0x891B, req)[20:24])   # SIOCGIFNETMASK
    finally:
        s.close()
    mac = Path(f"/sys/class/net/{iface}/address").read_text().strip()
    return ip, mask, mac


def fingerprint(path):
    p = Path(path)
    try:
        if p.is_symlink():
            return "link:" + os.readlink(p)
        if p.is_file():
            return hashlib.sha256(p.read_bytes()[:1 << 20]).hexdigest()[:16]
        if p.is_dir():
            return "dir"
    except OSError:
        return None
    return None


def autostart_entries():
    homes = [h for h in Path("/home").iterdir()] if Path("/home").exists() else []
    places = list(AUTOSTART_PLACES) + [str(h / rel) for h in homes for rel in HOME_AUTOSTART]
    found = {}
    for place in places:
        p = Path(place)
        if not p.exists() and not p.is_symlink():
            continue
        if p.is_dir() and not p.is_symlink():
            depth = 1 if place.endswith("flatpak/app") else 3
            for root, dirs, files in os.walk(p):
                rel_depth = len(Path(root).relative_to(p).parts)
                if rel_depth >= depth:
                    dirs[:] = []
                for name in files + (dirs if rel_depth + 1 >= depth else []):
                    fp = os.path.join(root, name)
                    v = fingerprint(fp)
                    if v:
                        found[fp] = v
        else:
            v = fingerprint(p)
            if v:
                found[str(p)] = v
    return found


# ---------- the sentinel ----------

class Sentinel:
    def __init__(self):
        self.state = self.load()
        now = time.time()
        self.state.setdefault("started", now)
        self.state.setdefault("devices", {})
        self.state.setdefault("programs", {})
        self.state.setdefault("listeners", {})
        self.state.setdefault("autostarts", None)
        self.state.setdefault("gateway_macs", {})
        self.ip_names = {}        # ip → website name, from DNS answers
        self.recent = {}          # dedupe key → last time logged
        self.sock_seen = set()    # socket inodes already handled
        self.tools_seen = set()   # (pid, name) remote tools already reported
        self.iface = self.gateway = self.my_ip = self.my_mac = self.mask = None
        self.cap = None

    # state
    def load(self):
        try:
            return json.loads(STATE_FILE.read_text())
        except (OSError, ValueError):
            return {}

    def save(self):
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.state))
        os.replace(tmp, STATE_FILE)

    @property
    def learning(self):
        return time.time() < self.state["started"] + LEARN_SECONDS

    def alert(self, severity, kind, title, **details):
        emit("ALERT", {"severity": severity, "kind": kind, "title": title, "details": details,
                       "time": int(time.time())}, 4 if severity == "high" else 5)

    def once(self, key, every=REPEAT_LOG):
        now = time.time()
        if now - self.recent.get(key, 0) < every:
            return False
        self.recent[key] = now
        if len(self.recent) > 50000:
            cutoff = now - every
            self.recent = {k: t for k, t in self.recent.items() if t > cutoff}
        return True

    # network capture
    def setup_capture(self):
        iface, gw = default_route()
        if iface == self.iface and self.cap:
            self.gateway = gw
            return
        if self.cap:
            self.cap.close()
            self.cap = None
        self.iface, self.gateway = iface, gw
        if not iface:
            return
        try:
            self.my_ip, self.mask, self.my_mac = iface_info(iface)
            self.cap = open_capture(iface)
            emit("INFO", {"msg": "watching", "iface": iface, "ip": self.my_ip, "gateway": gw,
                          "learning": self.learning})
        except OSError as e:
            emit("INFO", {"msg": "capture unavailable", "error": str(e)}, 3)

    def on_frame(self, frame, outgoing):
        try:
            info = parse_frame(frame)
        except (ValueError, struct.error, IndexError, OSError):
            return
        if not info:
            return
        kind = info["kind"]
        if kind == "arp":
            self.see_device(info["mac"], ip=info["ip"])
            self.check_gateway(info["ip"], info["mac"])
        elif kind == "dhcp":
            self.see_device(info["mac"], name=info.get("name"), extra=info.get("vendor_class"))
        elif kind == "mdns":
            self.see_device(info["src"], ip=info["ip"], name=info["name"])
        elif kind == "dns":
            self.on_dns(info, outgoing)

    def see_device(self, mac, ip=None, name=None, extra=None):
        if mac in (self.my_mac, "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") or int(mac[:2], 16) & 1:
            return
        if ip in ("0.0.0.0", None):
            ip = None
        devs, now = self.state["devices"], int(time.time())
        d = devs.get(mac)
        if d is None:
            if len(devs) >= MAX_DEVICES:
                return
            d = devs[mac] = {"first": now, "last": now, "ips": [], "name": "", "vendor": vendor(mac)}
            emit("DEVICE", {"event": "new", "mac": mac, "ip": ip, "vendor": d["vendor"], "name": name})
            if not self.learning:
                randomized = is_randomized(mac)
                self.alert("notice" if randomized else "high", "new_device",
                           "A new device joined your home network", mac=mac, ip=ip,
                           vendor=d["vendor"], name=name or "", dhcp_vendor=extra or "")
        d["last"] = now
        if ip and ip not in d["ips"]:
            d["ips"] = (d["ips"] + [ip])[-4:]
        if name and name != d["name"]:
            d["name"] = name
            emit("DEVICE", {"event": "name", "mac": mac, "name": name})

    def check_gateway(self, ip, mac):
        if ip != self.gateway:
            return
        known = self.state["gateway_macs"].setdefault(ip, [])
        if mac in known:
            return
        if known:
            self.alert("high", "gateway_changed",
                       "Your router's hardware address changed (possible network interception)",
                       router_ip=ip, new_mac=mac, new_vendor=vendor(mac), known_macs=known)
        known.append(mac)

    def on_dns(self, info, outgoing):
        if info["response"]:
            q = info["questions"][0] if info["questions"] else ""
            for _name, rtype, value in info["answers"]:
                if rtype in ("A", "AAAA"):
                    if len(self.ip_names) > 20000:
                        self.ip_names.clear()
                    self.ip_names[value] = clean(q, 100)
            return
        if not outgoing:
            return  # someone else's lookup (multicast etc.)
        for name in info["questions"]:
            name = clean(name, 200)
            if REMOTE_DOMAINS.search(name) and self.once(("rdns", name), 3600):
                self.alert("high", "remote_access_lookup",
                           "This computer looked up a remote-access service", name=name)
            if self.once(("dns", name)):
                emit("DNS", {"name": name})

    def arp_sweep(self):
        """Ask every address on the local network 'who has this?' (one tiny packet each)."""
        if not (self.cap and self.my_ip and self.mask):
            return
        ip = struct.unpack("!I", socket.inet_aton(self.my_ip))[0]
        mask = struct.unpack("!I", socket.inet_aton(self.mask))[0]
        if bin(mask).count("1") < 22:
            return  # bigger than ~1000 addresses: not a home network, don't sweep
        net, my_mac = ip & mask, bytes.fromhex(self.my_mac.replace(":", ""))
        for host in range(net + 1, (net | (~mask & 0xFFFFFFFF))):
            if host == ip:
                continue
            frame = (b"\xff" * 6 + my_mac + struct.pack("!H", ETH_P_ARP)
                     + struct.pack("!HHBBH", 1, ETH_P_IP, 6, 4, 1) + my_mac
                     + socket.inet_aton(self.my_ip) + b"\x00" * 6 + struct.pack("!I", host))
            try:
                self.cap.send(frame)
            except OSError:
                return
            time.sleep(0.05)
            self.drain()

    # connections & listeners
    def poll_sockets(self):
        socks = read_sockets()
        new = [s for s in socks if s[6] not in self.sock_seen and s[6] != "0"]
        if not new:
            return
        owners = socket_owners()
        listening = {(s[0], s[3]) for s in socks if s[1] == "listen"}
        for proto, state, la, lp, ra, rp, inode in new:
            self.sock_seen.add(inode)
            prog = program_of(owners[inode]) if inode in owners else "?"
            if state == "listen":
                self.check_listener(proto, la, lp, prog)
            elif not is_local(ra):
                incoming = (proto, lp) in listening and proto == "tcp"
                self.on_connection(proto, ra, rp, prog, incoming)
        if len(self.sock_seen) > 100000:
            self.sock_seen = {s[6] for s in socks}

    def on_connection(self, proto, ra, rp, prog, incoming):
        name = self.ip_names.get(ra, "")
        if incoming:
            if self.once(("in", prog, ra), 3600):
                self.alert("high", "incoming_connection",
                           "Another computer connected IN to this one", program=prog,
                           remote=ra, remote_port=rp, name=name)
            return
        if rp in REMOTE_PORTS and self.once(("rport", prog, ra, rp), 3600):
            self.alert("high", "remote_access_connection",
                       f"A program connected out on the {REMOTE_PORTS[rp]} port", program=prog,
                       remote=ra, port=rp, name=name)
        progs = self.state["programs"]
        if prog not in progs and prog != "?" and len(progs) < MAX_PROGRAMS:
            progs[prog] = int(time.time())
            if not self.learning:
                self.alert("notice", "new_program_online",
                           "A program went online for the first time", program=prog,
                           remote=ra, port=rp, name=name)
        if self.once(("conn", prog, name or ra, rp)):
            emit("CONN", {"program": prog, "remote": ra, "port": rp, "proto": proto, "name": name})

    def check_listener(self, proto, la, lp, prog):
        if is_local(la) and la not in ("0.0.0.0", "::"):
            return  # only reachable from this computer
        if proto == "udp" and lp >= 1024:
            return  # browsers/video calls open many short-lived UDP ports; not a server
        key = f"{proto}/{lp}"
        known = self.state["listeners"]
        if known.get(key) == prog:
            return
        known[key] = prog
        if not self.learning or REMOTE_TOOLS.search(prog):
            self.alert("high", "new_listener",
                       "A program opened a door for incoming connections", program=prog,
                       proto=proto, port=lp, address=la,
                       remote_access_port=REMOTE_PORTS.get(lp, ""))

    # processes & autostarts
    def scan_processes(self):
        alive = set()
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                comm = Path(f"/proc/{pid}/comm").read_text().strip()
                cmd = Path(f"/proc/{pid}/cmdline").read_bytes()[:300].replace(b"\0", b" ")
            except OSError:
                continue
            text = comm + " " + cmd.decode("utf-8", "replace")
            m = REMOTE_TOOLS.search(text)
            if m:
                key = (pid, comm)
                alive.add(key)
                if key not in self.tools_seen:
                    self.tools_seen.add(key)
                    self.alert("high", "remote_access_tool", "A remote-access program is running",
                               match=m.group(0), program=clean(comm, 40), pid=int(pid),
                               command=clean(cmd, 200), exe=program_of(pid))
        self.tools_seen &= alive

    def scan_autostarts(self):
        now_found = autostart_entries()
        before = self.state["autostarts"]
        self.state["autostarts"] = now_found
        if before is None:
            emit("INFO", {"msg": "autostart baseline", "entries": len(now_found)})
            return
        for path in sorted(set(now_found) | set(before)):
            old, new = before.get(path), now_found.get(path)
            if old == new:
                continue
            change = "added" if old is None else "removed" if new is None else "changed"
            serious = SERIOUS_AUTOSTART.search(path) or REMOTE_TOOLS.search(path)
            self.alert("high" if serious else "notice", "autostart_changed",
                       f"Something that starts automatically was {change}", path=path,
                       change=change, remote_tool=bool(REMOTE_TOOLS.search(path)))

    def snapshot(self):
        devs = self.state["devices"]
        emit("SNAPSHOT", {"devices": {m: {k: d[k] for k in ("ips", "name", "vendor", "first", "last")}
                                      for m, d in sorted(devs.items(), key=lambda x: -x[1]["last"])[:200]},
                          "programs_online": len(self.state["programs"]),
                          "learning": self.learning})

    # main loop
    def drain(self):
        if not self.cap:
            return
        for _ in range(500):
            try:
                frame, addr = self.cap.recvfrom(65535)
            except BlockingIOError:
                return
            except OSError:
                return
            self.on_frame(frame, addr[2] == PACKET_OUTGOING)

    def run(self):
        emit("INFO", {"msg": "sentinel started", "learning_until": int(self.state["started"] + LEARN_SECONDS)})
        timers = {"conn": 0, "slow": 0, "auto": 0, "sweep": time.time() + 60, "save": 0, "snap": 0}
        while True:
            now = time.time()
            if now >= timers["slow"]:
                self.setup_capture()
                self.scan_processes()
                timers["slow"] = now + SLOW_POLL
            if now >= timers["conn"]:
                self.poll_sockets()
                timers["conn"] = now + CONN_POLL
            if now >= timers["auto"]:
                self.scan_autostarts()
                timers["auto"] = now + AUTOSTART_POLL
            if now >= timers["sweep"]:
                self.arp_sweep()
                timers["sweep"] = now + SWEEP_EVERY
            if now >= timers["snap"]:
                if timers["snap"]:
                    self.snapshot()
                timers["snap"] = now + 6 * 3600
            if now >= timers["save"]:
                self.save()
                timers["save"] = now + 300
            wait = max(0.1, min(timers.values()) - time.time())
            ready = select.select([self.cap], [], [], wait)[0] if self.cap else time.sleep(wait)
            if ready:
                self.drain()


if __name__ == "__main__":
    s = Sentinel()
    try:
        s.run()
    finally:
        s.save()
