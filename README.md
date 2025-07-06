# Ethical Threat Feeds by Devs, for Devs 🛡️

## 🌐 Community-Driven Threat Intelligence

Real-time threat feeds generated from UDM Pro firewall logs, providing categorized lists of IP addresses involved in malicious activity.

**Last Updated:** 2025-07-06 21:35:04 UTC

## 📊 Available Threat Categories

| Category | Description | Risk Level |
|----------|-------------|------------|
| Port_Scanning | Network reconnaissance attempts | Low |
| Compromised_Host | Known malicious/compromised hosts | Important |
| SSH_Scanning | SSH brute force attempts | Suspicious |
| DNS_Attack | DNS enumeration/attacks | Suspicious |
| Tor_Traffic | Tor network activity | Suspicious |
| Web_Attack | Generic web application attacks | Important |
| SQL_Injection | Database injection attempts | Important |
| XSS_Attempt | Cross-site scripting attacks | Important |
| Command_Injection | OS command injection attempts | Important |

## 📁 Feed Files

### CSV Format
- Contains structured data with metadata
- Fields: ip_address, offense_count, first_seen, last_seen, severity, is_targeted_attack, is_cgnat

### TXT Format  
- Simple space-separated format
- Suitable for direct import into security tools

## 🔄 Update Frequency

- Feeds are updated every 15 minutes
- 30-day rolling expiration for IP addresses
- Automatic cleanup of stale entries

## 🛡️ Usage Guidelines

### For Network Administrators
```bash
# Download and use in pfSense, OPNsense, etc.
curl -O https://raw.githubusercontent.com/Tempest-Solutions-Company/threat-feeds/main/feeds/SQL_Injection.txt
```

### For Security Tools
```python
import requests
import pandas as pd

# Load CSV format for analysis
url = "https://raw.githubusercontent.com/Tempest-Solutions-Company/threat-feeds/main/feeds/SQL_Injection.csv"
df = pd.read_csv(url)
high_risk_ips = df[df['is_targeted_attack'] == True]
```

## 📋 File Descriptions


## 🔍 Data Sources

- **UDM Pro Firewalls**: Real network traffic analysis
- **Proofpoint CyberSecure**: 55,000+ threat signatures
- **Community Reporting**: Ethical disclosure to IP owners/ISPs

## ⚠️ Important Notes

- **CGNAT Awareness**: IPs from Carrier-Grade NAT ranges are tagged
- **False Positives**: Always verify before blocking critical services
- **Attribution**: Single offense IPs are for observation only
- **Targeted Attacks**: IPs with ≥3 offenses are flagged as targeted

## 🤝 Contributing

This is a community-driven project. To contribute:

1. Deploy your own instance
2. Share anonymized threat intelligence
3. Report false positives
4. Improve detection signatures

## 📄 License

MIT License - Use freely with attribution

## 📞 Contact

- **Issues**: GitHub Issues
- **Community**: Discussions tab
- **Security**: security@example.com

---

*Generated automatically by the Ethical Threat Feeds system*
