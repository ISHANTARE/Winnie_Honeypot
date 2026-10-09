#!/usr/bin/env python3
"""
Winnie-SOC: External TCP Test Client
Sends raw honeypot JSON events directly over TCP socket (port 5000)
matching the exact firmware behavior of ESP32 sendLogToServer().
"""
import sys
import json
import socket
import time

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 5000

def send_honeypot_event(command, ip="192.168.1.77", session=101):
    payload = {
        "ip": ip,
        "session": session,
        "command": command
    }
    raw_data = json.dumps(payload, indent=2) + "\n"

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((TARGET_HOST, TARGET_PORT))
        s.sendall(raw_data.encode('utf-8'))
        s.close()
        print(f"[✓] Transmitted to {TARGET_HOST}:{TARGET_PORT} -> {command}")
    except Exception as e:
        print(f"[✗] Failed to connect: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        cmd = " ".join(sys.argv[1:])
        send_honeypot_event(cmd)
    else:
        print("--- Winnie-SOC Interactive TCP Attack Injector ---")
        print(f"Target: {TARGET_HOST}:{TARGET_PORT}")
        print("Type commands (e.g. 'cat /etc/passwd', 'LOGIN: root/xc3511', 'wget http://bad.sh', 'exit')")
        print("-------------------------------------------------")
        sess = 999
        while True:
            try:
                line = input("attacker@shell:~# ").strip()
                if not line:
                    continue
                if line.lower() == "quit":
                    break
                send_honeypot_event(line, ip="192.168.1.200", session=sess)
                time.sleep(0.1)
            except (KeyboardInterrupt, EOFError):
                break
        print("\nExiting.")
