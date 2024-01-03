# ARP Network Scanner 

## Description
This Network Scanner is a Python tool developed for educational purposes at the University of Colorado - Boulder. It scans a specified host range and identifies active IP addresses and their associated MAC addresses. 
The results are recorded in a JSON format, making them easy to import into databases or central logging tools like SIEM systems for further analysis.

## Prerequisites
* Python 3.x
* `Scapy` library (pip install scapy)
* Install npcap on your machine

## Installation
Via HTTPS:
```bash
git clone https://github.com/dwmson/arp_scan.git
cd arp_scan
```

Via GH CLI
```bash
gh repo clone dwmson/arp_scan
cd arp_scan
```

## Usage
To use the network scanner, update the placeholder IP Address in the main section with your own and run the script with python. Example: 
```bash
python3 main.py

```

## Educational Purpose and Ethical use
This project was developed as part of an educational program at the University of Colorado - Boulder. It is intended solely for educational and research purposes. 
Users are expected to comply with all applicable laws and ethical guidelines when using or modifying this tool. Unauthorized scanning and probing of networks can be illegal and unethical. 
**It is the user's responsibility to ensure lawful and ethical use of this tool.**

## License 
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
