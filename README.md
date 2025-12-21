Scapy Python Networking Lab

This repository contains Python scripts developed using the **Scapy** library for learning and practicing fundamental networking concepts.

All projects in this repository are created **for educational purposes only**.
The scripts have **not been used on any real networks or devices**.

#Project Scope

The purpose of this repository is to gain practical understanding of how network traffic is created and processed at a low level by working directly with packets.

#Covered Topics:
* ARP-Based Network Interaction and Spoofing
* TCP/UDP Packet Creation and Injection
* Network Discovery and Tracing (Traceroute)
* Packet Structure and Protocol Behavior Analysis

These scripts are intended to improve practical understanding of:
* TCP / UDP Behavior and Port Utilization
* Packet Structure and Protocol Headers
* Network Traffic Fundamentals

#Working with the Scripts (How to Run)

##Setup

1.  **Clone the repository:**
    ```bash
    git clone 
    cd
    ```
2.  **Install dependencies:** (Installs the Scapy library)
    ```bash
    pip install scapy
    ```

### Execution Examples

* **For Basic Scripts (Root access optional):**
    ```bash
    python3 dns_query.py
    ```

* **For Privileged Scripts (Requires raw socket access):**
    ```bash
    sudo python3 arp_spoof.py
    ```

* ** !!!!!!System Setup for ARP Spoofing (MITM):!!!!!**
    Before running the `arp_spoof.py` script, enable IP forwarding on your Linux machine to ensure traffic passes through your machine:
    ```bash
    sudo sysctl -w net.ipv4.ip_forward=1
    ```
    *(Remember to turn it off after cleaning up ARP tables: `sudo sysctl -w net.ipv4.ip_forward=0`)*

## Environment (Lab Setup)

All experiments were conducted in a controlled virtual lab environment:

* **Host:** VirtualBox
* **Attacker / Script Machine:** Ubuntu Linux
* **Target Machine:** Windows Server
* **Language:** Python 3
* **Library:** Scapy

## !!!!!WARNING!!!!!

**Educational Use Only**

The scripts in this repository were developed and tested exclusively in an isolated lab environment. These codes **must not be used** on real systems or networks without proper authorization. Any malicious use is strictly the responsibility of the user.
