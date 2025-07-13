Of course, Liam! Here's the full, polished `README.md` that incorporates everything we've built together — structured threat feed info, file formats, update cadence, ethics, support options, and footer links:


## 🛡️ Ethical Threat Feeds — By Devs, For Devs

A transparent, community-first repository of curated **threat feeds** in `.txt`, `.csv`, and `.json` formats. Built from real-world firewall logs and IDS/IPS alerts, these datasets help sysadmins defend their networks with actionable, ethically-sourced data. Each feed includes timestamps, offense counts, and traffic metadata—supporting responsible threat sharing and collaborative defense.


### 📅 Update Frequency

Threat files are refreshed every **30 minutes**, ensuring timely access to active indicators of compromise.


### 📁 Published Threat Feeds

We prioritize the most common and impactful threats, with lesser-known patterns placed in an **uncategorized** catch-all.  
Structured blocklists are maintained across distinct malicious behavior categories:

- **Compromised Hosts**  
- **Port Scanners**  
- **Targeted Attackers**  
- **TOR Exit Nodes**  
- **High Offense IPs**  
- **Uncategorized Threats**

Each feed includes offense counts, first/last seen timestamps, threat signatures, and country of origin when available.

**Available formats:**
- `.txt`: Pipe-delimited, human-readable  
- `.csv`: Tab-delimited, ideal for automation  
- `.json`: Schema-based for direct parsing and enrichment


### 🧭 Ethics & Transparency

We believe responsible sharing is key to sustainable cybersecurity:

- Feeds are built solely from confirmed malicious activity  
- CGNAT awareness and de-duplication help reduce false positives  
- **No personal or non-malicious traffic is ever included**  
- We avoid tracking user-identifiable data and follow responsible disclosure practices


### 💡 Use Cases

- Blocklisting malicious IPs at the firewall or WAF level  
- Enriching SIEM/SOAR intelligence pipelines  
- Powering anomaly detection and machine learning models  
- Researching threat trends across geography and ASN


### 📦 File Structure Examples

**Plain Text (`.txt`):**
```
IP | Severity | Signature | Country | First Seen | Last Seen | Count
193.32.162.141 | HIGH | ET COMPROMISED Known Compromised or Hostile Host Traffic group 9 | GB | 2025-07-13 | 2025-07-13 | 1
```

**CSV (`.csv`):**
```
IP	First Seen	Last Seen	Count	Severity	Signature	Protocol	Country
193.32.162.141	2025-07-13T10:22:38.935Z	2025-07-13T10:22:38.935Z	1	high	ET COMPROMISED Known Compromised or Hostile Host Traffic group 9	TCP	GB
```

**JSON (`.json`):**
```json
{
  "metadata": {
    "category": "Compromised_Host",
    "generated": "2025-07-13T11:21:42.025Z",
    "source": "Ethical Threat Feeds by Devs, for Devs",
    "total_threats": 7,
    "expiry_days": 30,
    "format_version": "1.0"
  },
  "threats": [
    {
      "ip": "193.32.162.141",
      "first_seen": "2025-07-13T10:22:38.935Z",
      "last_seen": "2025-07-13T10:22:38.935Z",
      "count": 1,
      "severity": "high",
      "signature": "ET COMPROMISED Known Compromised or Hostile Host Traffic group 9",
      "protocol": "TCP",
      "country": "GB"
    }
  ]
}
```


### 💖 Support Ethical Threat Intelligence

If our **blocklists** or **threat feeds** help secure your network, consider buying us a coffee.  
Even **£1/$1** helps offset infrastructure costs and keeps everything updated and open every 30 minutes.

[![Support us on Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/J3J31HZAUU)  
> Transparent. Non-commercial. Community-powered cybersecurity.

---

### 🌐 Project Home

For more information, updates, and future developments, visit  
**[Tempest Solutions](https://tempest-solutions.org.uk/)** — powering ethical threat intelligence and community-first cybersecurity.

---

