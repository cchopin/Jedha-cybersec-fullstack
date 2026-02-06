# Incident Response Case Study: Mirai/XMRig Double Compromise

Real-world incident response and threat intelligence investigation of a server compromised by both a cryptominer and a Mirai botnet variant.

---

## Contents

### English Version

| File | Description |
|------|-------------|
| [01_incident_report.md](01_incident_report.md) | Full incident report with timeline, IOCs, and remediation steps |
| [02_threat_intelligence.md](02_threat_intelligence.md) | CTI analysis: malware identification, infrastructure attribution, MITRE ATT&CK mapping |
| [03_writeup.md](03_writeup.md) | Narrative write-up suitable for blog/educational purposes |

### Version Francaise

| Fichier | Description |
|---------|-------------|
| [01_incident_report.md](01_incident_report.md) | Rapport d'incident (deja en francais) |
| [02_threat_intelligence_FR.md](02_threat_intelligence_FR.md) | Analyse CTI : identification malware, attribution infrastructure, mapping MITRE ATT&CK |
| [03_writeup_FR.md](03_writeup_FR.md) | Write-up narratif pour blog/formation |

## Key Findings

- **Malware:** Mirai variant EIW (34/72 VirusTotal detection)
- **Secondary payload:** XMRig cryptominer
- **C2 Infrastructure:** Virtualine Technologies (Russian bulletproof hosting)
- **Attack vectors:** Strapi CMS misconfiguration + Next.js Server Actions exploitation

## Skills Demonstrated

- Incident response and forensic analysis
- Malware identification and classification
- OSINT and threat intelligence gathering
- Infrastructure attribution
- MITRE ATT&CK mapping
- Detection rule development (Snort/YARA)

## Tools Used

- VirusTotal, ANY.RUN (malware analysis)
- Shodan, IPinfo (infrastructure recon)
- AbuseIPDB, Spamhaus (reputation)
- Standard Linux forensics tools

## Timeline

| Date | Event |
|------|-------|
| Dec 5, 2025 | First compromise - XMRig deployed |
| Jan 22-28, 2026 | Reconnaissance and probing |
| Feb 3, 2026 | Mirai dropper deployed |
| Feb 6, 2026 | Botnet active, incident detected |
| Feb 6, 2026 | Cleanup and hardening |

---

*Case study based on real incident. All identifying information redacted.*
