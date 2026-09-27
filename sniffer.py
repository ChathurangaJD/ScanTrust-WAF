import time
import datetime
import html
import pandas as pd
from scapy.all import sniff, Raw, IP
from scapy.config import conf

def get_network_interfaces():
    try:
        ifaces = [iface.name for iface in conf.ifaces.values() if iface.name]
        return list(set(ifaces)) if ifaces else ["Default"]
    except Exception:
        return ["Default"]

def make_packet_callback(st_state, rf_model, vectorizer, check_rule_signatures):
    def process_packet(packet):
        if not packet.haslayer(Raw):
            return
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore').strip()
            if not payload:
                return

            start_t = time.time()
            features = vectorizer.transform([payload])
            pred = rf_model.predict(features)[0]
            verdict = "🚨 Attack" if pred == 1 else "✅ Safe"

            if check_rule_signatures(payload):
                verdict = "🚨 Attack"

            end_t = time.time()
            st_state.inference_speed = (end_t - start_t) * 1000.0
            st_state.live_req += 1
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown IP"

            display_payload = payload[:70].replace("\n", " ") + "..." if len(payload) > 70 else payload.replace("\n", " ")
            safe_payload = html.escape(display_payload)

            if verdict == "🚨 Attack":
                st_state.live_blocked += 1
                status = "🚨 [DETECTED]"
                color = "#ff4b4b"
            else:
                status = "✅ [PASSED]"
                color = "#00cc66"

            safe_count = st_state.live_req - st_state.live_blocked
            new_row = pd.DataFrame({
                "Time": [timestamp],
                "✅ Safe Requests": [safe_count],
                "🚨 Detected Attacks": [st_state.live_blocked]
            }).set_index("Time")

            st_state.chart_data = pd.concat([st_state.chart_data, new_row])
            if len(st_state.chart_data) > 20:
                st_state.chart_data = st_state.chart_data.iloc[-20:]

            new_log = (
                f"<span style='color: #888;'>[{timestamp}]</span> "
                f"<span style='color: #4da6ff;'>IP: {src_ip}</span> | "
                f"<span style='color: #aaa;'>Payload:</span> <span style='color: #ffd700;'>{safe_payload}</span> | "
                f"<span style='color: #aaa;'>Status:</span> <span style='color: {color}; font-weight: bold;'>{status}</span><br>"
            )
            st_state.log_data += new_log

            st_state.raw_packets.append(packet)
            if len(st_state.raw_packets) > 1000:
                st_state.raw_packets = st_state.raw_packets[-1000:]

            new_exp = pd.DataFrame([{"Time": timestamp, "Source IP": src_ip, "Payload": payload, "Status": verdict}])
            st_state.export_logs = pd.concat([st_state.export_logs, new_exp], ignore_index=True)
            if len(st_state.export_logs) > 1000:
                st_state.export_logs = st_state.export_logs.iloc[-1000:]

            lines = [l for l in st_state.log_data.split("<br>") if l]
            if len(lines) > 10:
                st_state.log_data = "<br>".join(lines[-10:]) + "<br>"

        except Exception:
            pass

    return process_packet

def run_sniffer_thread(iface_name, callback_fn, is_live_predicate):
    try:
        if iface_name == "Default":
            sniff(filter="tcp", prn=callback_fn, stop_filter=is_live_predicate, store=False)
        else:
            sniff(iface=iface_name, filter="tcp", prn=callback_fn, stop_filter=is_live_predicate, store=False)
    except Exception:
        pass