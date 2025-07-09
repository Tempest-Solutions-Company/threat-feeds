# 🛡️ Ethical Threat Feeds — By Devs, For Devs

**A transparent, community-first threat intelligence system powered by real-world firewall data.** This project collects and categorizes malicious IP addresses observed via UDM Pro logs—promoting accountability, empowering sysadmins, and preserving data ethics.

---

## 🚀 Project Goals

- ✅ Supply **lightweight, actionable IP blocklists** for real-world defense
- ✅ Track offensive behavior over time with offense counts and timestamps
- ✅ Rotate old IPs out of the system to keep the lists fresh
- ✅ Account for CGNAT infrastructure and avoid collateral overblocking
- ✅ Send **daily awareness reports** to ASNs and IP owners based on WHOIS data
- ✅ Provide an API and dashboard for community access, transparency, and insight

---

## 📡 What We Collect

From parsed UDM Pro logs, we extract and track:

- **IP Address**
- **Threat Type** (e.g. Port Scan, Targeted Attack, TOR Node)
- **Offense Count**
- **First Seen / Last Seen Timestamps**
- **Country of Origin** (from log metadata)
- **ASN (Autonomous System Number)**

---

## 📁 Output Files

We publish public `.txt` and `.csv` lists for each threat category:
