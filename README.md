# 🛰️ Azure SIEM Geolocation Simulation

## Overview

This project demonstrates how to build a **Security Information and Event Management (SIEM)** simulation using **Microsoft Azure**.
The setup replicates a real-world environment where a **public-facing Windows Virtual Machine (VM)** is intentionally exposed to the **public internet** to attract real attackers.
The generated attack logs are ingested into **Azure Log Analytics** and visualized in **Microsoft Sentinel**, including **geolocation-based threat mapping**.


This project provides a practical understanding of how Security Operations Centers (SOCs) collect, detect, and visualize cyber threats in real time.

----

## Project Architecture Diagram

![Project Architecture](images/ProjectArchitecture.png)

### Components:

1. **Public Internet:** Represents real-world attackers scanning and exploiting open ports.
2. **Azure Virtual Machine (VM):** A Windows Server machine exposed to the internet (with the firewall disabled) to simulate attacks.
3. **Network Security Group (NSG):** Disabled or relaxed to allow inbound traffic from the internet.
4. **Log Analytics Workspace:** Collects and stores logs from the VM for monitoring and query analysis.
5. **Microsoft Sentinel (SIEM):** Visualizes data, detects patterns, and displays geolocation of attacks on a world map.

---

## ⚙️ Tools and Technologies

| Component                                   | Purpose                                                         |
| ------------------------------------------- | --------------------------------------------------------------- |
| **Azure Virtual Machine**                   | Host target system to simulate attacks                          |
| **Network Security Group (NSG)**            | Normally protects Azure resources, here disabled for simulation |
| **Azure Log Analytics Workspace**           | Centralized log collection and query platform                   |
| **Microsoft Sentinel (SIEM)**               | Threat detection, visualization, and geolocation mapping        |
| **PowerShell / Kusto Query Language (KQL)** | For querying and analyzing log data                             |
| **Attackers (Public Internet)**             | Simulated real-world scanning and intrusion attempts            |

---

## 🚀 Setup Guide

### **1. Create Azure Resources**

* Create a **Free or Paid Azure Subscription**:
  [https://azure.microsoft.com/en-us/pricing/purchase-options/azure-account](https://azure.microsoft.com/en-us/pricing/purchase-options/azure-account)
* Inside your subscription, create a **Resource Group** and a **Virtual Network (VNet-SoC)**.

![Resource Group](images/1.png)

![Resource Group](images/2-2.png)

### **2. Deploy a Windows Virtual Machine**

![Project Architecture](images/3-4.png)

* Create a **Windows VM** (In this case, Windows 11).
* During setup:
  * Allow **RDP (port 3389)** and **HTTP (port 80)**.

    ![RDP](images/3-2.png)
  * Turn off NSG rules for testing and Create a new inbound rule to allow traffic from anywhere.

    ![NSG Rule](images/4.png)

  * Log into the VM via RDP, Disable **Windows Firewall** to expose the machine.
 
    ![RDP Login](images/7.png)
    
  * Ping the VM via from your local machine
 
    ![Ping](images/8.png)

> ⚠️ *This VM will be publicly accessible. Do not use sensitive credentials or store personal data.*
>
> At the end of this stage, the project's architecture is as shown below:

![Part1](images/EoP1.png)

### **3. Enable Log Collection**

* Go to **Azure Monitor → Logs → Create Log Analytics Workspace**.
* Connect your VM to this workspace via:

  * **Azure Portal → VM → Monitoring → Insights → Enable**

### **4. Onboard Microsoft Sentinel**

* Navigate to **Microsoft Sentinel → Add → Select your Log Analytics Workspace**.
* Once onboarded, Sentinel will start collecting data from connected VMs.

### **5. Generate Logs**

* Leave your VM exposed for a few hours or days.
* Logs will automatically start populating with brute-force, RDP, and network scan attempts.

### **6. Create Attack Map Visualization**

* In **Microsoft Sentinel**, open **Workbooks → Add Workbook → Windows VM Attack Map**.
* Modify or create your own workbook using **Kusto Query Language (KQL)**:

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent;
WindowsEvents | where EventID == 4625
| order by TimeGenerated desc
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| summarize FailureCount = count() by IpAddress, latitude, longitude, cityname, countryname
| project FailureCount, AttackerIp = IpAddress, latitude, longitude, city = cityname, country = countryname,
friendly_location = strcat(cityname, " (", countryname, ")");
```

* Visualize the results on a **World Map** to see attack origins.

---

## 🧠 Learning Objectives

* Understand how **SIEM systems** collect and correlate security logs.
* Learn how to simulate **real-world cyberattacks** safely.
* Visualize **global attack patterns** using geolocation mapping.
* Build hands-on experience with **Microsoft Sentinel** and **Azure Log Analytics**.

---

## 🧩 Possible Enhancements

* Integrate **honeypots** or **custom attack simulation tools** (e.g., Cowrie, HoneyDB).
* Add **alert rules** and **automated incident response** using Sentinel playbooks.
* Extend simulation to **Linux VMs** or **containerized workloads**.
* Export dashboards for presentation or SOC training sessions.

---

## 🧾 License

This project is for **educational and research purposes only**.
Do **not** use this setup in production or on networks containing sensitive data. 
Copyright (c) 2025 Johnson Oje

---

## ✍️ Author

**Johnson Oje**
🔗 [LinkedIn](https://www.linkedin.com/in/johnson-pamilerin-oje/) | 💻 [Portfolio](ojejp.github.io) | 🛡️ Cybersecurity Analyst & Penetration Tester
