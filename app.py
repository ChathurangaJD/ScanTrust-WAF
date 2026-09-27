import streamlit as st
import time
import pandas as pd
import datetime
import tempfile
import matplotlib.pyplot as plt
from fpdf import FPDF
import requests
import io
from PIL import Image
import os
import threading
from scapy.all import rdpcap, wrpcap, Raw
from streamlit.runtime.scriptrunner import add_script_run_ctx

from database import init_db, log_threat
from classifier import load_models, is_valid_sql_query, check_rule_signatures, classify_payload
from sniffer import get_network_interfaces, make_packet_callback, run_sniffer_thread

logo_url = "https://raw.githubusercontent.com/ChathurangaJD/web_portfolio/a4845df5ee7732164a02b5e6a832b1f1ce50849b/logoipsum-435.png"
response = requests.get(logo_url)
logo_img = Image.open(io.BytesIO(response.content))

with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp_logo:
    logo_img.save(tmp_logo.name, format="PNG")
    logo_path = tmp_logo.name

st.set_page_config(page_title="scantrust", page_icon=logo_img, layout="wide", initial_sidebar_state="expanded")
init_db()
rf_model, vectorizer = load_models()

if 'saved_iface' not in st.session_state:
    st.session_state.saved_iface = None
if 'saved_is_live' not in st.session_state:
    st.session_state.saved_is_live = False
if 'live_req' not in st.session_state:
    st.session_state.live_req = 0
    st.session_state.live_blocked = 0
    st.session_state.log_data = ""
    st.session_state.inference_speed = 0.00
    st.session_state.chart_data = pd.DataFrame(columns=["Time", "✅ Safe Requests", "🚨 Detected Attacks"]).set_index("Time")
    st.session_state.sniffing_active = False 
if 'raw_packets' not in st.session_state:
    st.session_state.raw_packets = [] 
if 'export_logs' not in st.session_state:
    st.session_state.export_logs = pd.DataFrame(columns=["Time", "Source IP", "Payload", "Status"])

with st.sidebar:
    st.markdown(f"""<div style="display: flex; justify-content: center;"><img src="{logo_url}" width="180"></div>""", unsafe_allow_html=True)
    st.markdown("<h2 style='text-align: center;'>𝙎𝙘𝙖𝙣𝙏𝙧𝙪𝙨𝙩</h2>", unsafe_allow_html=True)
    st.markdown("---")
    app_mode = st.radio("Select Mode:", ["Live Dashboard", "Manual Query Scanner", "Bulk Log Scanner"])
    st.sidebar.success("System Status: ONLINE")
    st.sidebar.markdown("---")
    st.sidebar.markdown("""<div style="text-align: center; color: #888888; font-size: 12px; padding-bottom: 10px;">&copy; 2026 ScanTrust AI Web Application Firewall.<br>All Rights Reserved.</div>""", unsafe_allow_html=True)

if app_mode == "Live Dashboard":
    st.title("ScanTrust AI Web Application Firewall")
    st.markdown("Real-time automated SQL Injection detection powered by Machine Learning.")
    st.markdown("---")
    
    available_ifaces = get_network_interfaces()
    colA, colB, colC = st.columns([2, 2, 1])
    
    with colA:
        default_index = available_ifaces.index(st.session_state.saved_iface) if st.session_state.saved_iface in available_ifaces else 0
        selected_iface = st.selectbox("Network Interface:", available_ifaces, index=default_index)
        st.session_state.saved_iface = selected_iface
        
    with colB:
        st.markdown("### Live Traffic Volume")
        
    with colC:
        st.write("")
        is_live = st.toggle("🔴 Live Traffic", value=st.session_state.saved_is_live, help="Turn on to capture real packets")
        st.session_state.saved_is_live = is_live
        
        with st.popover("Export Traffic", use_container_width=True):
            csv_data = st.session_state.export_logs.to_csv(index=False).encode('utf-8')
            st.download_button(label="CSV File", data=csv_data, file_name=f"ScanTrust_Logs_{datetime.datetime.now().strftime('%H%M%S')}.csv", mime="text/csv", use_container_width=True)
            
            if len(st.session_state.raw_packets) > 0:
                try:
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
                        wrpcap(tmp.name, st.session_state.raw_packets)
                        with open(tmp.name, "rb") as f:
                            pcap_bytes = f.read()
                    st.download_button(label="PCAP File", data=pcap_bytes, file_name=f"ScanTrust_Traffic_{datetime.datetime.now().strftime('%H%M%S')}.pcap", mime="application/vnd.tcpdump.pcap", use_container_width=True)
                except Exception:
                    pass
            else:
                st.caption("Waiting for packets...")

    if st.session_state.saved_is_live and not st.session_state.sniffing_active:
        st.session_state.sniffing_active = True
        pkt_cb = make_packet_callback(st.session_state, rf_model, vectorizer, check_rule_signatures)
        stop_predicate = lambda x: not st.session_state.saved_is_live
        t = threading.Thread(target=run_sniffer_thread, args=(selected_iface, pkt_cb, stop_predicate), daemon=True)
        add_script_run_ctx(t)
        t.start()
    elif not st.session_state.saved_is_live and st.session_state.sniffing_active:
        st.session_state.sniffing_active = False

    @st.fragment(run_every=2)
    def show_live_feed():
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Packets Examined", f"{st.session_state.live_req}", "Live Traffic")
        threat_rate = (st.session_state.live_blocked / st.session_state.live_req) * 100 if st.session_state.live_req > 0 else 0
        col2.metric("Total Threats Detected", f"{st.session_state.live_blocked}", f"{threat_rate:.1f}% Threat Rate", delta_color="inverse")
        speed_val = st.session_state.inference_speed if st.session_state.saved_is_live else 0.00
        status_text = "Optimal" if st.session_state.saved_is_live else "Paused"
        col3.metric("Real AI Inference Speed", f"{speed_val:.2f} ms", status_text)
        
        if not st.session_state.chart_data.empty:
            st.area_chart(st.session_state.chart_data, color=["#10b981", "#ef4444"])
        else:
            empty_df = pd.DataFrame(columns=["✅ Safe Requests", "🚨 Detected Attacks"])
            st.area_chart(empty_df, color=["#10b981", "#ef4444"])
            
        st.markdown("### Live Network Traffic Stream")
        st.markdown(
            f"""<div style="background-color: #0e1117; padding: 15px; border-radius: 8px; font-family: 'Courier New', Courier, monospace; font-size: 13px; height: 210px; border: 1px solid #333; box-shadow: 0px 4px 10px rgba(0,0,0,0.5); overflow-y: auto;">
            {st.session_state.log_data if st.session_state.log_data else "<span style='color: #666;'>Waiting for network traffic... Enable Live Traffic and visit a website.</span>"}
            </div>""",
            unsafe_allow_html=True
        )

    show_live_feed()

elif app_mode == "Manual Query Scanner":
    st.title("Advanced Hybrid Threat Scanner")
    user_query = st.text_area("SQL Query Input:", placeholder="e.g. SELECT * FROM users WHERE username='admin' OR 1=1 --")
    
    if st.button("Scan Query", type="primary"):
        if user_query.strip() == "":
            st.warning("Please enter a SQL query to scan.")
        elif not is_valid_sql_query(user_query):
            st.error("⚠️ Invalid SQL Format: The input does not appear to be a valid SQL query.")
        else:
            with st.spinner("Analyzing Payload..."):
                t_start = time.time()
                # Receive only 2 return values:
                verdict, conf_score = classify_payload(user_query, rf_model, vectorizer)
                p_time = (time.time() - t_start) * 1000.0
                
                st.markdown("### Scan Results:")
                if verdict == "🚨 Attack":
                    st.error("🚨 **MALICIOUS PAYLOAD DETECTED!**")
                    st.write(f"**Confidence:** {conf_score:.2f}%")
                    st.write(f"**Analysis Time:** {p_time:.2f} ms")
                    log_threat(user_query, round(conf_score, 2))
                else:
                    st.success("✅ **SAFE QUERY.**")
                    st.write(f"**Analysis Time:** {p_time:.2f} ms")

elif app_mode == "Bulk Log Scanner":
    st.title("Bulk Web Log Analyzer & Reporting")
    st.write("Upload a CSV, PCAP, or PKT file containing network traffic or web logs.")
    uploaded_file = st.file_uploader("Upload File", type=["csv", "pcap", "pkt"])
    
    if uploaded_file is not None and rf_model and vectorizer:
        file_ext = uploaded_file.name.split('.')[-1].lower()
        df = pd.DataFrame()
        
        with st.spinner(f'Extracting and Scanning {file_ext.upper()} file...'):
            if file_ext == 'csv':
                df = pd.read_csv(uploaded_file)
            elif file_ext in ['pcap', 'pkt']:
                with tempfile.NamedTemporaryFile(delete=False, suffix=f".{file_ext}") as tmp:
                    tmp.write(uploaded_file.getvalue())
                    tmp_path = tmp.name
                try:
                    packets = rdpcap(tmp_path)
                    extracted = [pkt[Raw].load.decode('utf-8', errors='ignore') for pkt in packets if pkt.haslayer(Raw) and pkt[Raw].load.decode('utf-8', errors='ignore').strip()]
                    df = pd.DataFrame({"Query": extracted})
                finally:
                    os.remove(tmp_path)
                    
        if not df.empty and "Query" in df.columns:
            with st.spinner('Analyzing payloads...'):
                features = vectorizer.transform(df["Query"].astype(str))
                preds = rf_model.predict(features)
                df["AI_Verdict"] = ["🚨 Attack" if p == 1 else "✅ Safe" for p in preds]
                
                rule_matches = df["Query"].astype(str).apply(check_rule_signatures)
                df.loc[rule_matches, "AI_Verdict"] = "🚨 Attack"
                
                tot_scanned = len(df)
                tot_attacks = len(df[df["AI_Verdict"] == "🚨 Attack"])
                tot_safe = tot_scanned - tot_attacks
                
            st.success(f"Successfully scanned {tot_scanned} queries/packets!")
            col1, col2 = st.columns(2)
            col1.metric("Total Safe Queries", tot_safe)
            col2.metric("Total Threats Detected", tot_attacks)
            st.markdown("---")
            
            filter_opt = st.radio("Select View:", ["Show All", "🚨 Attacks Only", "✅ Safe Only"], horizontal=True)
            if filter_opt == "🚨 Attacks Only":
                f_df = df[df['AI_Verdict'] == '🚨 Attack']
            elif filter_opt == "✅ Safe Only":
                f_df = df[df['AI_Verdict'] == '✅ Safe']
            else:
                f_df = df
            st.dataframe(f_df, use_container_width=True)
            
            exp_c1, exp_c2 = st.columns(2)
            c_data = df.to_csv(index=False).encode('utf-8')
            exp_c1.download_button("Download Results (CSV)", c_data, "waf_scan_results.csv", "text/csv")
            
            if exp_c2.button("Generate & Download PDF Report"):
                with st.spinner("Generating Report..."):
                    fig, ax = plt.subplots(figsize=(6, 4))
                    ax.pie([tot_safe, tot_attacks], labels=['Safe Queries', 'Malicious Attacks'], autopct='%1.1f%%', colors=['#10b981', '#ef4444'], startangle=90, wedgeprops={'edgecolor': 'white', 'linewidth': 2})
                    plt.title('AI Threat Detection Breakdown', pad=20, weight='bold')
                    
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmpfile:
                        fig.savefig(tmpfile.name, format='png', bbox_inches='tight', dpi=300)
                        chart_p = tmpfile.name
                        
                    class PDFReport(FPDF):
                        def header(self):
                            self.set_fill_color(15, 23, 42)
                            self.rect(0, 0, 210, 35, 'F')
                            self.image(logo_path, x=45, y=7, w=20)
                            self.set_y(12)
                            self.set_font("Arial", 'B', 20)
                            self.set_text_color(255, 255, 255)
                            self.set_x(70)
                            self.cell(0, 10, "ScanTrust Security Report", ln=True, align='L')
                            self.set_y(45)

                    pdf = PDFReport()
                    pdf.add_page()
                    pdf.set_font("Arial", 'B', 12)
                    pdf.set_text_color(50, 50, 50)
                    pdf.cell(100, 8, txt="Scan Overview", ln=True)
                    pdf.set_font("Arial", size=10)
                    pdf.set_text_color(100, 100, 100)
                    pdf.cell(200, 6, txt=f"Date Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
                    pdf.cell(200, 6, txt=f"Total Queries Analyzed: {tot_scanned}", ln=True)
                    pdf.ln(10)
                    
                    pdf.set_fill_color(220, 252, 231)
                    pdf.set_text_color(22, 101, 52)
                    pdf.set_font("Arial", 'B', 12)
                    pdf.cell(90, 15, txt=f"  Safe Queries: {tot_safe}  ", border=1, fill=True, align='C')
                    pdf.cell(10, 15, txt="", border=0)
                    pdf.set_fill_color(254, 226, 226)
                    pdf.set_text_color(153, 27, 27)
                    pdf.cell(90, 15, txt=f"  Threats Detected: {tot_attacks}  ", border=1, fill=True, align='C', ln=True)
                    pdf.ln(10)
                    
                    pdf.image(chart_p, x=45, w=120)
                    pdf.ln(5)
                    
                    pdf.set_text_color(50, 50, 50)
                    pdf.set_font("Arial", 'B', 12)
                    pdf.cell(200, 10, txt="All Detected Malicious Payloads:", ln=True)
                    pdf.ln(2)
                    
                    atks = df[df['AI_Verdict'] == '🚨 Attack']
                    pdf.set_fill_color(240, 240, 240)
                    pdf.set_text_color(200, 0, 0)
                    pdf.set_font("Courier", size=9)
                    
                    for _, row in atks.iterrows():
                        q_txt = str(row['Query']).encode('latin-1', 'replace').decode('latin-1')
                        pdf.multi_cell(0, 6, txt=f" {q_txt} ", fill=True, border=1)
                        pdf.ln(2)
                        
                    out_pdf = pdf.output(dest='S').encode('latin-1')
                    exp_c2.download_button("⬇Click here to Download PDF", out_pdf, "ScanTrust_Security_Report.pdf", "application/pdf")
        else:
            st.error("No readable HTTP payloads or queries found in the uploaded file.")