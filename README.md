<div id="header" align="center">
<h1> PyQt5 DNS SPoofing Tool </h1>
</div>
<div id="header" align="center">
  <img src="https://image.noelshack.com/fichiers/2023/12/6/1679776387-gui.jpg">
</div>

# Introduction  
DNS Spoofing Tool is a user-friendly Python-based application for performing ARP poisoning and DNS spoofing attacks. 
With its intuitive GUI, simply input the target domain, router IP, victim IP, and redirect IP to intercept DNS requests and redirect the victim's traffic. 


# DISCLAIMER
This tool is for educational purposes only. 
Use it responsibly and only on networks you have permission to access. The developer is not responsible for any misuse or damages caused by this program.

# Installation
 
1. Clone the repository or download the zip file.
```bash
git clone https://github.com/busirus/PyQt5-DNSSpoofing-Tool.git
```
2. Install the required libraries by running the following command in the terminal:
```bash
pip install -r requirements.txt
```
4. Run the program by executing the following command:
```bash
python main.py
```

# Features

ARP poisoning for man-in-the-middle attacks
DNS spoofing to redirect specific domains to desired IP addresses
A simple and user-friendly graphical interface
Real-time output display

# Usage 

1. Domain to spoof: The domain you want to redirect (e.g., example.com)
2. Router IP: The IP address of the router (e.g., 192.168.1.254)
3. Victim IP: The IP address of the victim's machine (e.g., 192.168.1.100)
4. Redirect to IP: The IP address you want to redirect the victim to (e.g., 192.168.1.2)
5.Click the "Start" button to begin ARP poisoning and DNS spoofing.
6. To stop the spoofing, click the "Stop" button. The tool will restore the original MAC addresses of the router and victim's machine.

# License

This project is licensed under the MIT License. See the LICENSE file for more information.
