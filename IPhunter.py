import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import requests
import whois
import subprocess
import threading
import json

# ----------------------------- FUNCTIONS -----------------------------
def get_ip_info(ip):
    try:
        # IP Geolocation
        geo = requests.get(f"http://ip-api.com/json/{ip}").json()
        country = geo.get("country", "N/A")
        region = geo.get("regionName", "N/A")
        city = geo.get("city", "N/A")
        isp = geo.get("isp", "N/A")
        lat, lon = geo.get("lat", "N/A"), geo.get("lon", "N/A")

        # WHOIS
        try:
            w = whois.whois(ip)
            whois_info = str(w)
        except:
            whois_info = "WHOIS lookup failed."

        # Traceroute
        traceroute_result = subprocess.getoutput(f"traceroute -m 5 {ip}" if not is_windows() else f"tracert -h 5 {ip}")

        # Open Ports (basic)
        open_ports = []
        for port in [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 8080]:
            try:
                with socket.create_connection((ip, port), timeout=1):
                    open_ports.append(port)
            except:
                continue

        # OS Guess (very basic)
        os_guess = "Likely Windows" if 135 in open_ports or 445 in open_ports else "Unknown"

        # Firewall detection (dummy logic)
        firewall = "Minimal firewall detected" if len(open_ports) > 3 else "Strict firewall likely"

        # Risk Level
        risk_level = "High" if 445 in open_ports or 23 in open_ports else "Moderate" if len(open_ports) > 5 else "Low"

        return {
            "Country": country,
            "Region": region,
            "City": city,
            "ISP": isp,
            "Lat": lat,
            "Lon": lon,
            "OS": os_guess,
            "Firewall": firewall,
            "Risk": risk_level,
            "Open Ports": open_ports,
            "Traceroute": traceroute_result,
            "WHOIS": whois_info
        }

    except Exception as e:
        return {"Error": str(e)}

def is_windows():
    from sys import platform
    return platform.startswith("win")

def scan():
    ip = ip_entry.get().strip()
    if not ip:
        ip = requests.get("https://api.ipify.org").text

    output_box.delete("1.0", tk.END)
    output_box.insert(tk.END, f"Scanning {ip}...\n\n")

    def worker():
        data = get_ip_info(ip)
        output_box.delete("1.0", tk.END)
        if "Error" in data:
            output_box.insert(tk.END, f"Error: {data['Error']}")
            return

        for key, val in data.items():
            output_box.insert(tk.END, f"{key}:\n{val}\n\n")

    threading.Thread(target=worker).start()

def save_report():
    report = output_box.get("1.0", tk.END)
    if report.strip():
        with open("report.txt", "w") as f:
            f.write(report)
        messagebox.showinfo("Saved", "Report saved as report.txt")
    else:
        messagebox.showwarning("Empty", "No data to save.")

# ----------------------------- GUI SETUP -----------------------------
root = tk.Tk()
root.title("IPHunter Pro - fsociety Edition")
root.geometry("750x600")

style = ttk.Style()
style.theme_use("clam")

frame = ttk.Frame(root, padding=10)
frame.pack(fill="both", expand=True)

tt_label = ttk.Label(frame, text="Enter IP Address (leave blank to use your own):")
tt_label.pack(pady=5)

ip_entry = ttk.Entry(frame, width=50)
ip_entry.pack(pady=5)

btn_frame = ttk.Frame(frame)
btn_frame.pack(pady=10)

scan_btn = ttk.Button(btn_frame, text="Start Scan", command=scan)
scan_btn.pack(side="left", padx=10)

save_btn = ttk.Button(btn_frame, text="Save Report", command=save_report)
save_btn.pack(side="left")

output_box = scrolledtext.ScrolledText(frame, wrap=tk.WORD, font=("Courier", 10))
output_box.pack(fill="both", expand=True, pady=10)

root.mainloop()
