# AUTO-RUNNING MOCK SERVER WITH EMBEDDED UI
import sys
import subprocess
import webbrowser
from http.server import HTTPServer, SimpleHTTPRequestHandler
from faker import Faker
import random
import json
import time
import threading
import os

try:
    from faker import Faker
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "faker"])
    from faker import Faker

fake = Faker()

class MockDeviceHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            base_dir = os.path.dirname(os.path.abspath(__file__))  # get script's directory
            index_path = os.path.join(base_dir, 'index.html')  # full path to index
            with open(index_path, 'rb') as f:
                self.wfile.write(f.read())
        elif self.path == '/favicon.ico':
            self.send_response(204)
            self.end_headers()
        elif self.path == '/cached-scan':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            data = self.generate_live_data()
            self.wfile.write(json.dumps(data).encode())
        elif self.path == '/scan':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            data = self.generate_live_data()
            self.wfile.write(json.dumps(data).encode())
        elif self.path == '/scan-stations':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            data = self.generate_station_data()
            self.wfile.write(json.dumps(data).encode())
        elif self.path.startswith('/handshake.pcap'):
            self.send_response(200)
            self.send_header('Content-Type', 'application/vnd.tcpdump.pcap')
            self.send_header('Content-Disposition', 'attachment; filename="handshake.pcap"')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            # minimal pcap global header (little-endian)
            gh = bytes.fromhex('d4c3b2a1 02000400 00000000 00000000 ffff0000 01000000'.replace(' ', ''))
            # empty file with only global header
            self.wfile.write(gh)
        else:
            self.send_error(404)

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8') if length > 0 else ''
        try:
            payload = json.loads(body) if body else {}
        except Exception:
            payload = {}

        if self.path == '/start-attack':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(b'{"status":"success"}')
        elif self.path == '/handshake-capture':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            resp = {"status": "ok", "eapol_count": random.randint(1, 12)}
            self.wfile.write(json.dumps(resp).encode())
        else:
            self.send_error(404)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def generate_live_data(self):
        bands = {
            1: "2.4GHz", 2: "2.4GHz", 3: "2.4GHz", 4: "2.4GHz", 5: "2.4GHz",
            6: "2.4GHz", 7: "2.4GHz", 8: "2.4GHz", 9: "2.4GHz", 10: "2.4GHz",
            11: "2.4GHz", 12: "2.4GHz", 13: "2.4GHz", 14: "2.4GHz",
            32: "5GHz", 36: "5GHz", 40: "5GHz", 44: "5GHz", 48: "5GHz",
            52: "5GHz", 56: "5GHz", 60: "5GHz", 64: "5GHz", 100: "5GHz",
            104: "5GHz", 108: "5GHz", 112: "5GHz", 116: "5GHz", 120: "5GHz",
            124: "5GHz", 128: "5GHz", 132: "5GHz", 136: "5GHz", 140: "5GHz",
            144: "5GHz", 149: "5GHz", 153: "5GHz", 157: "5GHz", 161: "5GHz",
            165: "5GHz"
        }
        
        joke_ssids = [
            "FBI_Surveillance", "Twin_Peaks_WiFi", "Dildo_Factory_Guest",
            "Mom_Click_This", "Skynet_Global", "Virus_Distribution",
            "Click_For_Dick_Pics", "Nacho_WiFi", "Bill_Nye_The_WiFi_Guy",
            "Diddy_Party_Van", "Pretty_Fly_For_A_WiFi", "Router?I_Barely_KnowHer",
            "Tell_My_WiFi_Love_Her", "It_Hurts_When_IP", "Noah's_LAN",
            "The_Password_Is_1234", "HideYoKids_HideYoWiFi"
        ]
        
        return {
            "rows": [
                {
                    "SSID": random.choice(joke_ssids) if random.random() > 0.2 else "",
                    "MAC": fake.bothify(text='??:??:??:??:??:??').lower(),
                    "Channel": random.choice([1, 6, 11, 36, 40, 44, 149, 153]),
                    "Security": random.choice(["WPA2", "WPA3", "WEP", "Open", "UNKNOWN"]),
                    "Band": bands[channel],
                    "stations": [
                        {
                            "mac": fake.bothify(text='??:??:??:??:??:??').lower(),
                            "rssi": random.randint(-90, -30)
                        } for _ in range(random.randint(0, 3))
                    ] if random.random() > 0.3 else []
                } for channel in [random.choice([1, 6, 11, 36, 40, 44, 149, 153]) for _ in range(random.randint(5, 12))]
            ]
        }

    def generate_station_data(self):
        return {
            ap["MAC"]: {
                "stations": [
                    {
                        "mac": ":".join(f"{random.randint(0,255):02x}" for _ in range(6)),  # real MAC format
                        "rssi": random.randint(-90, -30)
                    } for _ in range(random.randint(1, 5))
                ]
            } for ap in self.generate_live_data()["rows"]
        }

def run_server():
    server = HTTPServer(('localhost', 8000), MockDeviceHandler)
    print("Mock device running at http://localhost:8000")
    webbrowser.open('http://localhost:8000')
    server.serve_forever()

if __name__ == "__main__":
    run_server()