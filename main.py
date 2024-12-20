# Import necessary libraries
import scapy.all as scapy
import tkinter as tk
from tkinter import ttk
import threading
import subprocess

# Global variables
ip_statistics = {}
suspicious_set = set()
blocked_set = set()
monitoring_active = False

login_attempts = {}
spam_count = {}

def handle_packet(packet):
    global ip_statistics, suspicious_set
    if packet.haslayer(scapy.IP):
        source_ip = packet[scapy.IP].src
        packet_size = len(packet)

        if source_ip not in ip_statistics:
            ip_statistics[source_ip] = 0
        ip_statistics[source_ip] += packet_size

        suspicion_reasons = check_suspicion(source_ip)

        if suspicion_reasons and source_ip not in suspicious_set:
            suspicious_set.add(source_ip)
            update_suspicious_ips_table(source_ip, ", ".join(suspicion_reasons))

        if source_ip not in blocked_set:
            port = packet[scapy.IP].sport
            add_to_all_ips_table(source_ip, port, packet_size)

def check_suspicion(ip):
    reasons = []
    if ip_statistics.get(ip, 0) > 1024:
        reasons.append("Packet size too large")
    if is_sending_spam(ip):
        reasons.append("Sending spam emails")
    if is_hosting_malware(ip):
        reasons.append("Hosting malware")
    if is_brute_force_attempt(ip):
        reasons.append("High rate of login attempts")
    return reasons

def is_sending_spam(ip):
    return spam_count.get(ip, 0) > 100

def is_hosting_malware(ip):
    malicious_ips = {"192.192.1.192", "203.0.203.3"}
    return ip in malicious_ips

def is_brute_force_attempt(ip):
    if ip not in login_attempts:
        login_attempts[ip] = 0
    login_attempts[ip] += 1
    return login_attempts[ip] > 5

def begin_monitoring():
    global monitoring_active
    reset_tables()
    if not monitoring_active:
        monitoring_active = True
        threading.Thread(target=sniff_traffic, daemon=True).start()

def sniff_traffic():
    scapy.sniff(prn=handle_packet, store=False)

def end_monitoring():
    global monitoring_active
    monitoring_active = False

def add_to_blocked_ips(ip):
    global blocked_set
    if ip not in blocked_set:
        blocked_set.add(ip)
        update_blocked_ips_table(ip)
        apply_iptables_block(ip)
        remove_from_suspicious_ips_table(ip)


def apply_iptables_block(ip):
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        print(f"[INFO] IP {ip} blocked successfully using iptables.")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to block IP {ip}: {e}")

def remove_from_suspicious_ips_table(ip):
    for item in suspicious_ips_tree.get_children():
        if suspicious_ips_tree.item(item)['values'][0] == ip:
            suspicious_ips_tree.delete(item)
            break

def update_suspicious_ips_table(ip, reason):
    suspicious_ips_tree.insert("", "end", values=(ip, reason))
    print(f"[INFO] IP {ip} added to Suspicious IPs table with reason: {reason}.")

def update_blocked_ips_table(ip):
    blocked_ips_tree.insert("", "end", values=(ip,))

def reset_tables():
    suspicious_ips_tree.delete(*suspicious_ips_tree.get_children())
    all_ips_tree.delete(*all_ips_tree.get_children())

def add_to_all_ips_table(ip, port, size):
    all_ips_tree.insert("", "end", values=(ip, port, size))

def block_selected_ip():
    selected_item = suspicious_ips_tree.selection()
    if selected_item:
        ip_to_block = suspicious_ips_tree.item(selected_item)['values'][0]
        add_to_blocked_ips(ip_to_block)
    else:
        print("No IP selected for blocking.")

def unblock_selected_ip():
    selected_item = blocked_ips_tree.selection()
    if selected_item:
        ip_to_unblock = blocked_ips_tree.item(selected_item)['values'][0]
        remove_from_blocked_ips(ip_to_unblock)
        delete_from_blocked_ips_table(ip_to_unblock)
        # Добавляем IP обратно в таблицу Suspicious IPs
        update_suspicious_ips_table(ip_to_unblock, "Unblocked")
        print(f"[INFO] IP {ip_to_unblock} added back to Suspicious IPs with reason 'Unblocked'.")
    else:
        print("[ERROR] No IP selected for unblocking.")



def apply_iptables_unblock(ip):
    try:
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        print(f"[INFO] IP {ip} unblocked successfully using iptables.")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to unblock IP {ip}: {e}")


def remove_from_blocked_ips(ip):
    global blocked_set
    if ip in blocked_set:
        blocked_set.remove(ip)
        apply_iptables_unblock(ip)
        print(f"[INFO] IP {ip} removed from blocked list and unblocked.")



def delete_from_blocked_ips_table(ip):
    for item in blocked_ips_tree.get_children():
        if blocked_ips_tree.item(item)['values'][0] == ip:
            blocked_ips_tree.delete(item)
            print(f"[INFO] IP {ip} removed from Blocked IPs table.")
            break






# Main application window
app_window = tk.Tk()
app_window.title("Network Traffic Monitor")
app_window.geometry("1400x600")
app_window.configure(bg="#2E2E2E")

# Styling
style = ttk.Style()
style.theme_use("clam")
style.configure("Treeview", background="#3E3E3E", foreground="#E6E6E6", fieldbackground="#3E3E3E")
style.map("Treeview", background=[("selected", "#575757")])
style.configure("Treeview.Heading", background="#575757", foreground="#FFFFFF", font=("Helvetica", 12, "bold"))
style.configure("TButton", font=("Helvetica", 12, "bold"), padding=6, relief="flat", background="#404040", foreground="#FFFFFF")

# Frames
frames = {}
for idx, label in enumerate(["Incoming IPs", "Suspicious IPs", "Blocked IPs"]):
    frame = tk.Frame(app_window, bg="#404040", bd=2, relief="groove")
    frame.grid(row=0, column=idx, padx=10, pady=10, sticky="nsew")
    app_window.grid_columnconfigure(idx, weight=1)
    tk.Label(frame, text=label, bg="#404040", fg="#FFFFFF", font=("Helvetica", 14, "bold")).pack(side="top", pady=(10, 5))
    frames[label] = frame

# Incoming IPs Table
all_ips_tree = ttk.Treeview(frames["Incoming IPs"], columns=("IP", "Port", "Size"), show="headings")
all_ips_tree.heading("IP", text="IP Address")
all_ips_tree.heading("Port", text="Port")
all_ips_tree.heading("Size", text="Size")
all_ips_tree.pack(side="top", fill="both", expand=True)
ttk.Button(frames["Incoming IPs"], text="Start Monitoring", command=begin_monitoring).pack(fill="x", padx=10, pady=(10, 5))
ttk.Button(frames["Incoming IPs"], text="Stop Monitoring", command=end_monitoring).pack(fill="x", padx=10)

# Suspicious IPs Table
suspicious_ips_tree = ttk.Treeview(frames["Suspicious IPs"], columns=("IP", "Reason"), show="headings")
suspicious_ips_tree.heading("IP", text="IP Address")
suspicious_ips_tree.heading("Reason", text="Reason")
suspicious_ips_tree.pack(side="top", fill="both", expand=True)
ttk.Button(frames["Suspicious IPs"], text="Block IP", command=block_selected_ip).pack(fill="x", padx=10, pady=10)

# Blocked IPs Table
blocked_ips_tree = ttk.Treeview(frames["Blocked IPs"], columns=("IP",), show="headings")
blocked_ips_tree.heading("IP", text="IP Address")
blocked_ips_tree.pack(side="top", fill="both", expand=True)
ttk.Button(frames["Blocked IPs"], text="Unblock IP", command=unblock_selected_ip).pack(fill="x", padx=10, pady=10)

app_window.mainloop()

