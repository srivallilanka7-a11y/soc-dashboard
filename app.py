import customtkinter as ctk
from tkinter import ttk, filedialog, messagebox
import requests, pandas as pd, threading, time, datetime, json, os, webbrowser
from collections import defaultdict
 
# ================= CONFIG =================
CONFIG_FILE = "config.json"
CACHE_FILE = "cache.json"
 
VT_API_KEY = ""
ABUSE_API_KEY = ""
 
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")
 
app = ctk.CTk()
app.title("SOC Dashboard - FINAL POLISHED")
app.geometry("1750x950")
 
# ================= GLOBAL =================
df = None
cache = {}
 
stop_flag = False
pause_flag = False
 
critical_count = 0
malicious_count = 0
suspicious_count = 0
clean_count = 0
 
threat_rows = []
clean_rows = []
 
asn_tracker = defaultdict(list)
 
# ================= STYLE =================
style = ttk.Style()
style.theme_use("clam")
 
style.configure("Treeview",
                rowheight=30,
                font=("Arial", 11))
 
style.configure("Treeview.Heading",
                background="#16243a",
                foreground="white",
                font=("Arial", 12, "bold"))
 
# ================= HELPERS =================
def ui(f): app.after(0, f)
 
def vt_level(v):
    if v == 0: return "Clean"
    elif v <= 4: return "Suspicious"
    elif v <= 9: return "Malicious"
    return "Critical"
 
def update_counters():
    lbl_clean.configure(text=f"Clean:{clean_count}")
    lbl_susp.configure(text=f"Suspicious:{suspicious_count}")
    lbl_mal.configure(text=f"Malicious:{malicious_count}")
    lbl_critical.configure(text=f"Critical:{critical_count}")
 
# ================= CACHE =================
def load_cache():
    global cache
    if os.path.exists(CACHE_FILE):
        cache.update(json.load(open(CACHE_FILE)))
 
def save_cache():
    json.dump(cache, open(CACHE_FILE, "w"))
 
# ================= API =================
def load_api():
    global VT_API_KEY, ABUSE_API_KEY
    if os.path.exists(CONFIG_FILE):
        d = json.load(open(CONFIG_FILE))
        VT_API_KEY = d.get("vt", "")
        ABUSE_API_KEY = d.get("abuse", "")
 
def validate_vt(k):
    try:
        r = requests.get(
            "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
            headers={"x-apikey": k}, timeout=10)
        return r.status_code == 200
    except: return False
 
def validate_abuse(k):
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": k, "Accept": "application/json"},
            params={"ipAddress": "8.8.8.8"}, timeout=10)
        return r.status_code == 200
    except: return False
 
def save_keys():
    vt = vt_entry.get().strip()
    ab = abuse_entry.get().strip()
 
    if not validate_vt(vt) or not validate_abuse(ab):
        messagebox.showerror("Invalid", "API keys invalid")
        return
 
    json.dump({"vt": vt, "abuse": ab}, open(CONFIG_FILE, "w"))
    load_api()
    messagebox.showinfo("Saved", "API Keys Saved")
 
def open_api():
    w = ctk.CTkToplevel(app)
    w.geometry("420x250")
 
    ctk.CTkLabel(w, text="VirusTotal API").pack(pady=5)
    global vt_entry
    vt_entry = ctk.CTkEntry(w, width=360)
    vt_entry.pack()
    vt_entry.insert(0, VT_API_KEY)
 
    ctk.CTkLabel(w, text="AbuseIPDB API").pack(pady=5)
    global abuse_entry
    abuse_entry = ctk.CTkEntry(w, width=360)
    abuse_entry.pack()
    abuse_entry.insert(0, ABUSE_API_KEY)
 
    ctk.CTkButton(w, text="Validate & Save",
                  command=save_keys).pack(pady=10)
 
# ================= API SCAN =================
def scan_vt(ip):
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VT_API_KEY}, timeout=20)
        if r.status_code != 200: return (0,0,"N/A","N/A","N/A")
 
        d = r.json()["data"]["attributes"]
        s = d["last_analysis_stats"]
 
        return (s["malicious"], sum(s.values()),
                d.get("asn","N/A"),
                d.get("as_owner","N/A"),
                d.get("country","N/A"))
    except:
        return (0,0,"N/A","N/A","N/A")
 
def scan_abuse(ip):
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSE_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip}, timeout=20)
 
        d = r.json()["data"]
        return d["abuseConfidenceScore"], d["totalReports"]
    except:
        return (0,0)
 
# ================= CLICK =================
def on_click(e, tree):
    item = tree.identify_row(e.y)
    if not item: return
 
    v = tree.item(item, "values")
    ip = v[0]
    asn = v[4]
    col = tree.identify_column(e.x)
 
    if col == "#2":
        webbrowser.open(f"https://www.virustotal.com/gui/ip-address/{ip}")
    elif col == "#3":
        webbrowser.open(f"https://www.abuseipdb.com/check/{ip}")
    elif col == "#5":
        webbrowser.open(f"https://who.is/asn/{asn}")
    elif col == "#7":
        webbrowser.open(f"https://who.is/whois-ip/ip-address/{ip}")
 
# ================= ASN POPUP =================
def show_asn_ips(asn):
    win = ctk.CTkToplevel(app)
    win.title(f"ASN {asn} IP List")
 
    tv = ttk.Treeview(win, columns=("IP",), show="headings")
    tv.heading("IP", text="IPs Seen")
    tv.pack(fill="both", expand=True)
 
    for ip in asn_tracker[asn]:
        tv.insert("", 'end', values=(ip,))
 
def top_asn():
    win = ctk.CTkToplevel(app)
    win.title("Top ASN Intelligence")
 
    cols = ("ASN", "Total IPs", "Malicious")
    tv = ttk.Treeview(win, columns=cols, show="headings")
 
    for c in cols:
        tv.heading(c, text=c)
        tv.column(c, width=150, anchor="center")
 
    tv.pack(fill="both", expand=True)
 
    for a, ips in asn_tracker.items():
        mal = sum(1 for r in threat_rows if r[4] == a)
        tv.insert("", 'end', values=(a, len(ips), mal))
 
    tv.bind("<Double-1>", lambda e:
        show_asn_ips(tv.item(tv.selection()[0])["values"][0]))
 
# ================= SCAN =================
def scan_worker(ips):
    global critical_count, malicious_count, suspicious_count, clean_count
 
    start = datetime.datetime.now()
    total = len(ips)
 
    for i, ip in enumerate(ips, 1):
 
        if stop_flag: break
        while pause_flag: time.sleep(1)
 
        ui(lambda ip=ip: current_label.configure(text=f"Scanning: {ip}"))
 
        if ip in cache:
            row = list(cache[ip])
            row[-1] = "CACHE"
            row = tuple(row)
        else:
            vt,tv,asn,org,country = scan_vt(ip)
            abuse,rep = scan_abuse(ip)
            sev = vt_level(vt)
 
            row = (ip,f"{vt}/{tv}",abuse,rep,asn,org,country,sev,"LIVE")
            cache[ip] = row
            save_cache()
 
        asn_tracker[row[4]].append(ip)
 
        sev = row[7]
        if sev == "Critical": critical_count += 1
        elif sev == "Malicious": malicious_count += 1
        elif sev == "Suspicious": suspicious_count += 1
        else: clean_count += 1
 
        ui(update_counters)
 
        if sev == "Clean":
            clean_rows.append(row)
            ui(lambda r=row: tree_clean.insert("",'end',values=r,tags=("clean","cache" if r[-1]=="CACHE" else "live")))
        else:
            threat_rows.append(row)
            ui(lambda r=row: tree_threat.insert("",'end',values=r,tags=(sev.lower(),"cache" if r[-1]=="CACHE" else "live")))
 
        pct = i/total
        elapsed = datetime.datetime.now()-start
        eta = int((elapsed.total_seconds()/i)*(total-i))
 
        ui(lambda p=pct: progress.set(p))
        ui(lambda: percent_label.configure(text=f"{int(pct*100)}%"))
        ui(lambda: time_label.configure(text=f"Time:{str(elapsed).split('.')[0]}"))
        ui(lambda: eta_label.configure(text=f"ETA:{datetime.timedelta(seconds=eta)}"))
 
    ui(lambda: current_label.configure(text="Idle"))
 
# ================= CONTROL =================
def upload():
    global df
    p = filedialog.askopenfilename(filetypes=[("CSV","*.csv"),("Excel","*.xlsx")])
    if p:
        df = pd.read_csv(p) if p.endswith(".csv") else pd.read_excel(p)
 
def start_scan():
    global stop_flag, pause_flag
 
    if not VT_API_KEY or not ABUSE_API_KEY:
        messagebox.showwarning("Missing","Add API Keys")
        return
 
    if df is None: return
 
    progress.set(0)
    stop_flag = False
    pause_flag = False
 
    ips = list(set(df.iloc[:,0].dropna().astype(str).tolist()))
    threading.Thread(target=scan_worker,args=(ips,),daemon=True).start()
 
def scan_single():
    ip = ip_box.get().strip()
    if ip:
        threading.Thread(target=scan_worker,args=([ip],),daemon=True).start()
 
def pause(): globals()['pause_flag']=True
def resume(): globals()['pause_flag']=False
def stop(): globals()['stop_flag']=True
 
# ================= UI =================
top = ctk.CTkFrame(app); top.pack(fill="x")
 
ctk.CTkButton(top,text="Upload File",command=upload).pack(side="left")
ctk.CTkButton(top,text="Start Scan",command=start_scan).pack(side="left")
ctk.CTkButton(top,text="Pause",command=pause).pack(side="left")
ctk.CTkButton(top,text="Resume",command=resume).pack(side="left")
ctk.CTkButton(top,text="Stop",fg_color="red",hover_color="#990000",command=stop).pack(side="left")
ctk.CTkButton(top,text="API Settings",command=open_api).pack(side="left")
 
ip_box = ctk.CTkEntry(top,width=180); ip_box.pack(side="left",padx=5)
ctk.CTkButton(top,text="Scan IP",command=scan_single).pack(side="left")
 
current_label = ctk.CTkLabel(top,text="Idle")
current_label.pack(side="right",padx=10)
 
progress = ctk.CTkProgressBar(app); progress.pack(fill="x")
 
prog_frame = ctk.CTkFrame(app); prog_frame.pack(fill="x")
 
percent_label = ctk.CTkLabel(prog_frame,text="0%")
percent_label.pack(side="left",padx=8)
 
time_label = ctk.CTkLabel(prog_frame,text="Time:00:00:00")
time_label.pack(side="left",padx=12)
 
eta_label = ctk.CTkLabel(prog_frame,text="ETA:00:00:00")
eta_label.pack(side="left",padx=12)
 
cols=("IP","VT Vendors","Abuse Score","Abuse Reports",
      "ASN","Organization","Country","Severity","Source")
 
tree_threat = ttk.Treeview(app,columns=cols,show="headings",height=10)
tree_clean = ttk.Treeview(app,columns=cols,show="headings",height=8)
 
for t in [tree_threat,tree_clean]:
    for c in cols:
        t.heading(c,text=c)
        t.column(c,width=165,anchor="center")
    t.pack(fill="both",expand=True)
 
# ROW COLORS
tree_threat.tag_configure("critical",background="#ff4d4d")
tree_threat.tag_configure("malicious",background="#ff9999")
tree_threat.tag_configure("suspicious",background="#ffd699")
tree_clean.tag_configure("clean",background="#b8f5b8")
tree_threat.tag_configure("cache",background="#d9e6ff")
tree_clean.tag_configure("cache",background="#d9e6ff")
 
tree_threat.bind("<Double-1>",lambda e:on_click(e,tree_threat))
tree_clean.bind("<Double-1>",lambda e:on_click(e,tree_clean))
 
bottom = ctk.CTkFrame(app); bottom.pack(fill="x")
 
ctk.CTkButton(bottom,text="Export Threats",
command=lambda:pd.DataFrame(threat_rows,columns=cols)
.to_excel("threats.xlsx",index=False)).pack(side="left")
 
ctk.CTkButton(bottom,text="Export Clean",
command=lambda:pd.DataFrame(clean_rows,columns=cols)
.to_excel("clean.xlsx",index=False)).pack(side="left")
 
ctk.CTkButton(bottom,text="Export ALL",
command=lambda:pd.DataFrame(threat_rows+clean_rows,columns=cols)
.to_excel("all.xlsx",index=False)).pack(side="left")
 
ctk.CTkButton(bottom,text="Top ASN",
command=top_asn).pack(side="left",padx=5)
 
lbl_clean=ctk.CTkLabel(bottom,text="",text_color="green")
lbl_susp=ctk.CTkLabel(bottom,text="",text_color="yellow")
lbl_mal=ctk.CTkLabel(bottom,text="",text_color="orange")
lbl_critical=ctk.CTkLabel(bottom,text="",text_color="red")
 
for l in [lbl_critical,lbl_mal,lbl_susp,lbl_clean]:
    l.pack(side="right",padx=10)
 
load_api()
load_cache()
update_counters()
 
app.mainloop()
 
