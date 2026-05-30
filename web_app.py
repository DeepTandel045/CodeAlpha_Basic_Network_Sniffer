import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from flask import Flask, render_template
from flask_socketio import SocketIO
import threading
import socket as sock_module

from scapy.all import sniff, conf

from packet_analyzer import analyze_packet
from filters import build_bpf_filter
from statistics import PacketStatistics

# ── Flask / SocketIO setup ────────────────────────────────────────────────────
app = Flask(__name__)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")

# ── Global sniffer state ──────────────────────────────────────────────────────
is_sniffing   = False
bpf_filter    = ""
stats         = PacketStatistics()
sniffer_thread = None

# ── Helpers ───────────────────────────────────────────────────────────────────
def get_local_ip():
    try:
        s = sock_module.socket(sock_module.AF_INET, sock_module.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

local_ip = get_local_ip()

# ── Packet Processing ─────────────────────────────────────────────────────────
def process_packet(packet):
    global is_sniffing
    if not is_sniffing:
        return

    try:
        pkt_info = analyze_packet(packet)
        stats.update(pkt_info)

        pkt_info["id"] = stats.total_packets

        # Build info string
        proto = pkt_info.get("protocol", "UNKNOWN")
        if proto == "TCP":
            info = f"{pkt_info['src_port']} -> {pkt_info['dst_port']}  Len={pkt_info['length']}"
        elif proto == "UDP":
            info = f"src:{pkt_info['src_port']}  dst:{pkt_info['dst_port']}"
        elif proto == "ICMP":
            info = f"Echo  Len={pkt_info['length']}"
        elif proto in ("HTTP", "HTTPS"):
            payload = pkt_info.get("payload", "")
            info = payload[:100] if payload else f"Len={pkt_info['length']}"
        elif proto == "DNS":
            info = f"DNS Query/Response  Len={pkt_info['length']}"
        else:
            info = f"Len={pkt_info['length']}"

        pkt_info["info_str"] = info

        # Emit to all connected clients
        socketio.emit('new_packet', pkt_info)

        # Stats update every packet
        stats_data = {
            'total':       stats.total_packets,
            'protocols':   stats.protocols,
            'top_src_ips': stats.top_source_ips(5),
            'top_dst_ips': stats.top_dest_ips(5),
        }
        socketio.emit('stats_update', stats_data)

    except Exception as e:
        print(f"[packet error] {e}")

def stop_filter_fn(packet):
    """Scapy calls this after each packet — return True to stop."""
    return not is_sniffing

def sniffer_worker():
    """Runs in a background thread. Exits when is_sniffing becomes False."""
    global is_sniffing
    print(f"[sniffer] Starting capture — filter: '{bpf_filter or 'none'}'")
    try:
        while is_sniffing:
            sniff(
                prn=process_packet,
                filter=bpf_filter,
                store=False,
                timeout=0.5,
            )
    except PermissionError:
        print("[sniffer] PermissionError — please run as Administrator!")
        socketio.emit('sniffer_error', {'msg': 'Permission denied — run as Administrator.'})
    except Exception as e:
        print(f"[sniffer] Error: {e}")
        socketio.emit('sniffer_error', {'msg': str(e)})
    finally:
        is_sniffing = False
        print("[sniffer] Capture stopped.")
        socketio.emit('capture_stopped', {})

# ── Flask Routes ──────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html', local_ip=local_ip)

# ── SocketIO Events ───────────────────────────────────────────────────────────
@socketio.on('connect')
def on_connect():
    print("[ws] Client connected")
    # Send current stats so the UI is up-to-date on reconnect
    socketio.emit('stats_update', {
        'total':       stats.total_packets,
        'protocols':   stats.protocols,
        'top_src_ips': stats.top_source_ips(5),
        'top_dst_ips': stats.top_dest_ips(5),
    })

@socketio.on('disconnect')
def on_disconnect():
    print("[ws] Client disconnected")

@socketio.on('toggle_capture')
def handle_toggle(data):
    global is_sniffing, bpf_filter, sniffer_thread

    action = data.get('action', '')

    if action == 'start':
        if is_sniffing:
            return  # already running
        bpf_filter = data.get('filter', '').strip()
        is_sniffing = True
        sniffer_thread = threading.Thread(target=sniffer_worker, daemon=True)
        sniffer_thread.start()
        print("[ws] Capture START requested")

    elif action == 'stop':
        if not is_sniffing:
            return
        is_sniffing = False   # stop_filter_fn will pick this up
        print("[ws] Capture STOP requested")

@socketio.on('clear_data')
def handle_clear():
    global stats
    stats = PacketStatistics()
    print("[ws] Data cleared")

# ── Entry Point ───────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("=" * 55)
    print("  CYBERNETIC PROTOCOL INTELLIGENCE DASHBOARD")
    print("  Open in browser ->  http://localhost:5000")
    print("=" * 55)
    socketio.run(
        app,
        host='0.0.0.0',
        port=5000,
        debug=False,
        allow_unsafe_werkzeug=True
    )
