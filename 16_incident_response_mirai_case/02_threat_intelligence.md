# Cyber Threat Intelligence Report

**Incident Reference:** Mirai/XMRig Double Compromise  
**Analysis Date:** 2026-02-06  
**Classification:** TLP:CLEAR  

---

## Executive Summary

This CTI report documents the attribution analysis performed following a real-world server compromise. The investigation identified a **Mirai botnet variant (EIW)** operating through **Russian bulletproof hosting infrastructure** (Virtualine Technologies), with Command & Control servers hosted in the Netherlands via Bulgarian transit providers.

---

## 1. Malware Identification

### 1.1 Primary Sample

| Attribute | Value |
|-----------|-------|
| **SHA256** | `833bca151dc3ff83cbed22b6e7e849f0ee752bac55f68e156660e4d33d17caad` |
| **File Type** | ELF 32-bit x86 static |
| **File Size** | 107,508 bytes |
| **File Names** | `x86_32.kok`, `x86_64.kok`, `arm7.kok` |
| **Packer** | None detected (static binary) |

### 1.2 VirusTotal Detection (34/72)

| Vendor | Signature |
|--------|-----------|
| ESET-NOD32 | `Linux/Mirai.EIW Trojan` |
| Fortinet | `ELF/Mirai.EIW!tr` |
| DrWeb | `Linux.Mirai.9774` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.gu` |
| Microsoft | `Backdoor:Linux/Mirai.DN!MTB` |
| Tencent | `Backdoor.Linux.Mirai.ckb` |
| Avast/AVG | `ELF:Mirai-BXK [Bot]` |
| ClamAV | `Unix.Trojan.Mirai-10001386-0` |

**Notable non-detections:** CrowdStrike Falcon, Malwarebytes, McAfee

### 1.3 Malware Family Classification

```
Gafgyt (2014)
    |
    +-- Mirai (2016) - Source code leaked
            |
            +-- Multiple variants (2016-present)
                    |
                    +-- Mirai.EIW (2025-2026) <-- THIS SAMPLE
                    +-- Broadside (Dec 2025)
                    +-- Murdoc (Jan 2025)
                    +-- CatDDoS
                    +-- V3G4
```

---

## 2. Command & Control Infrastructure

### 2.1 C2 Servers Identified

| IP Address | Port | Role | Status |
|------------|------|------|--------|
| `91[.]92[.]241[.]12` | 6969 | Primary C2 | Active (last seen 2026-02-01) |
| `91[.]92[.]243[.]113` | 235 | Dropper distribution | Active |
| `91[.]92[.]241[.]10` | 80 | Payload download | Active |

### 2.2 Infrastructure Analysis (Shodan)

**Target: 91[.]92[.]241[.]12**

| Field | Value |
|-------|-------|
| Country | Netherlands |
| City | Amsterdam |
| Organization | Neterra Ltd. (Bulgaria) |
| ISP | NTT America, Inc. |
| ASN | AS2914 |
| OS | Linux (Ubuntu 24.04) |
| Open Ports | 22/tcp (SSH) |
| SSH Version | OpenSSH 9.6p1 Ubuntu-3ubuntu13.14 |
| Last Seen | 2026-02-01 |

### 2.3 Port 6969 Significance

The use of **TCP port 6969** as C2 is a distinctive marker associated with the **Broadside** Mirai variant:

- Primary C2: TCP/1026
- **Fallback C2: TCP/6969**
- Magic Header: `0x36694201`

Source: [Cydome Research - Broadside Analysis](https://cydome.io/cydome-identifies-broadside-a-new-mirai-botnet-variant-targeting-maritime-iot/)

---

## 3. Threat Actor Infrastructure

### 3.1 Hosting Chain

```
[Threat Actor]
      |
      v
+------------------+
| Virtualine       |  <-- Russian bulletproof hosting
| Technologies     |      Advertised on underground forums
+------------------+
      |
      v
+------------------+
| Railnet LLC      |  <-- Legal front (US-registered)
| ASN 214943       |      Leases IP prefixes
+------------------+
      |
      v
+------------------+
| Neterra Ltd.     |  <-- Bulgarian transit provider
| (Transit)        |
+------------------+
      |
      v
+------------------+
| NTT America      |  <-- Tier 1 carrier
| ASN 2914         |      Final routing
+------------------+
      |
      v
[Amsterdam Data Center]
```

### 3.2 Virtualine Technologies Profile

| Attribute | Details |
|-----------|---------|
| **Type** | Bulletproof Hosting Provider |
| **Origin** | Russia |
| **Forum Presence** | Russian underground forums (alias "Secury") |
| **Legal Front** | Railnet LLC (US) |
| **Related Services** | Proxio, DripHosting, RetryHost |
| **Tracked By** | Spamhaus, Recorded Future |
| **Known Clients** | UAC-0006, various botnet operators |

### 3.3 OSINT Sources

- [Spamhaus Alert on Virtualine](https://x.com/spamhaus/status/1968663056524644781) - Expansion tracking
- [IPinfo AS214943](https://ipinfo.io/AS214943) - ASN details
- [Intel Insights - Bulletproof Hosting Hunt](https://intelinsights.substack.com/p/bulletproof-hosting-hunt)

---

## 4. Dropper Analysis

### 4.1 logic.sh / logicdr.sh

The dropper script was analyzed on ANY.RUN:

**Sample:** [ANY.RUN Report](https://any.run/report/bf5a1e8b25d6ef368f11028fc492cc5e4a7e623a5b603a505828ae1c2e62fa3d/ea466e56-b198-4997-b76a-5b7f80caa591)

| Attribute | Value |
|-----------|-------|
| **SHA256** | `bf5a1e8b25d6ef368f11028fc492cc5e4a7e623a5b603a505828ae1c2e62fa3d` |
| **Type** | Bourne-Again shell script |
| **C2** | `91[.]92[.]241[.]12:6969` |
| **Download Server** | `91[.]92[.]241[.]10:80` |

### 4.2 Downloaded Payloads

The dropper fetches architecture-specific binaries:

```
x86_64.kok
x86_32.kok
arm.kok
arm5.kok
arm7.kok
mips.kok
mipsel.kok
powerpc.kok
```

### 4.3 Persistence Mechanisms

| Method | Location |
|--------|----------|
| Cron job | Modified crontab |
| Monitor script | `/var/tmp/.monitor` (60s respawn loop) |
| Init script | `/etc/rc2.d/S99backup*` |
| Hidden files | `.bins`, `.b_aa` to `.b_ah`, `.x` |

---

## 5. Secondary Payload: XMRig Cryptominer

### 5.1 Mining Configuration

| Attribute | Value |
|-----------|-------|
| **Miner** | XMRig 6.24.0-C3 (c3pool fork) |
| **Algorithm** | RandomX (Monero) |
| **Pool 1** | `pool[.]hashvault[.]pro:443` |
| **Pool 2** | `auto[.]c3pool[.]org:80` |

### 5.2 Wallet Addresses

```
89ASvi6ZBHXE6ykUZZFtqE1QqVhmwxCDCUvW2jvGZy1yP6n34uNdMKYj54ck81UC87KAKLaZT2L4YfC85ZCePDVeQPWoeAq

44VvVLU2Vmja6gTMbhNHAzc7heYTiT7VmQEXkjdaYo6K41WqH8qWw1CL8wKAAgz5xLYT3XL3pb9KCUZS7PPZbzUGCCpZ9Ee
```

### 5.3 Attribution Assessment

- Public pools (no private infrastructure)
- Monero wallets are anonymous by design
- Common tooling (XMRig is open source)
- **Assessment:** Opportunistic mining, low attribution confidence

---

## 6. MITRE ATT&CK Mapping

### 6.1 Initial Access

| Technique | ID | Description |
|-----------|----|-------------|
| Exploit Public-Facing Application | T1190 | Next.js Server Actions exploitation |
| Valid Accounts | T1078 | Strapi open registration abuse |

### 6.2 Execution

| Technique | ID | Description |
|-----------|----|-------------|
| Command and Scripting Interpreter | T1059.004 | Shell script dropper (logic.sh) |
| Native API | T1106 | Direct ELF execution |

### 6.3 Persistence

| Technique | ID | Description |
|-----------|----|-------------|
| Scheduled Task/Job | T1053.003 | Cron-based persistence |
| Boot or Logon Initialization Scripts | T1037 | .profile modification |
| Create or Modify System Process | T1543 | rc.d init scripts |

### 6.4 Defense Evasion

| Technique | ID | Description |
|-----------|----|-------------|
| Masquerading | T1036 | Process name spoofing (udhcpc, httpd) |
| Hidden Files and Directories | T1564.001 | Dot-prefixed files (.monitor, .bins) |
| Indicator Removal | T1070 | Self-deletion after execution |

### 6.5 Command and Control

| Technique | ID | Description |
|-----------|----|-------------|
| Application Layer Protocol | T1071 | HTTP-based C2 (/info.json, /client) |
| Non-Standard Port | T1571 | Port 6969 for C2 |
| Fallback Channels | T1008 | Multiple C2 servers |

### 6.6 Impact

| Technique | ID | Description |
|-----------|----|-------------|
| Resource Hijacking | T1496 | Cryptomining (XMRig) |
| Network Denial of Service | T1498 | DDoS attacks (SYN flood) |

---

## 7. Attribution Assessment

### 7.1 Confidence Matrix

| Element | Attribution | Confidence |
|---------|-------------|------------|
| Malware Family | Mirai variant EIW | **High** (34 AV detections) |
| C2 Infrastructure | Virtualine/Railnet | **High** (OSINT confirmed) |
| Hosting Origin | Russia | **High** (forum advertising) |
| Physical Location | Netherlands (Amsterdam) | **High** (Shodan) |
| Variant Type | Broadside-related | **Medium** (port 6969 match) |
| Operator Profile | Russian-speaking cybercriminals | **Medium** |
| State Sponsorship | None (organized crime) | **High** |

### 7.2 Threat Actor Profile

| Attribute | Assessment |
|-----------|------------|
| **Type** | Cybercriminal (non-APT) |
| **Motivation** | Financial (DDoS-as-a-Service + Cryptomining) |
| **Sophistication** | Medium (commodity tools, bulletproof infra) |
| **Language** | Russian (forum presence) |
| **Operations** | Opportunistic scanning and exploitation |

### 7.3 What We Cannot Prove

- Individual operator identities
- Direct link to specific criminal groups
- Cryptominer operator (public pools used)
- Exact Mirai variant lineage

---

## 8. Indicators of Compromise (IOCs)

### 8.1 Network IOCs

```
# C2 Servers
91[.]92[.]241[.]12:6969
91[.]92[.]243[.]113:235
91[.]92[.]241[.]10:80

# DDoS Source Block
138[.]121[.]0[.]0/16

# Mining Pools
pool[.]hashvault[.]pro:443
auto[.]c3pool[.]org:80
```

### 8.2 File IOCs

```
# Botnet binaries
833bca151dc3ff83cbed22b6e7e849f0ee752bac55f68e156660e4d33d17caad (SHA256)

# File patterns
*.kok
logic.sh
.monitor
.bins
.b_aa through .b_ah
.x
```

### 8.3 Behavioral IOCs

```
# Process names (masquerading)
/x86_64.kok
udhcpc (fake)
httpd (fake)
dnsmasq (fake)

# Network behavior
HTTP GET /info.json
HTTP POST /client
TCP connections to port 6969
High volume SYN packets (DDoS)
```

---

## 9. Recommendations

### 9.1 Detection Rules

**Snort/Suricata:**
```
alert tcp any any -> any 6969 (msg:"Possible Mirai C2 (port 6969)"; flow:established,to_server; sid:1000001; rev:1;)
alert http any any -> any any (msg:"Mirai C2 beacon"; content:"GET"; http_method; content:"/info.json"; http_uri; sid:1000002; rev:1;)
```

**YARA:**
```yara
rule Mirai_EIW_Variant {
    meta:
        description = "Detects Mirai.EIW variant"
        hash = "833bca151dc3ff83cbed22b6e7e849f0ee752bac55f68e156660e4d33d17caad"
    strings:
        $s1 = "/info.json" ascii
        $s2 = "/client" ascii
        $s3 = "udhcpc" ascii
        $s4 = ".kok" ascii
    condition:
        uint32(0) == 0x464C457F and 2 of them
}
```

### 9.2 Blocking Recommendations

```bash
# Block C2 infrastructure
iptables -A OUTPUT -d 91.92.241.0/24 -j DROP
iptables -A OUTPUT -d 91.92.243.0/24 -j DROP
iptables -A INPUT -s 138.121.0.0/16 -j DROP

# Block C2 port
iptables -A OUTPUT -p tcp --dport 6969 -j DROP
```

### 9.3 Threat Intelligence Feeds

- [Spamhaus DROP List](https://www.spamhaus.org/drop/)
- [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/)
- [AbuseIPDB](https://www.abuseipdb.com/)

---

## 10. References

1. [ANY.RUN - logicdr.sh Analysis](https://any.run/report/bf5a1e8b25d6ef368f11028fc492cc5e4a7e623a5b603a505828ae1c2e62fa3d/ea466e56-b198-4997-b76a-5b7f80caa591)
2. [ANY.RUN - x86_64.kok Analysis](https://any.run/report/430122ce9b795d5744234385ebfd0698d767f005cd663f6f6e9761ee1e885661/faf5b899-456f-484d-8d62-af908cfd4c09)
3. [Cydome - Broadside Mirai Variant](https://cydome.io/cydome-identifies-broadside-a-new-mirai-botnet-variant-targeting-maritime-iot/)
4. [Spamhaus - Virtualine Technologies Alert](https://x.com/spamhaus/status/1968663056524644781)
5. [IPinfo - AS214943 Railnet LLC](https://ipinfo.io/AS214943)
6. [Qualys - Murdoc Botnet Analysis](https://blog.qualys.com/vulnerabilities-threat-research/2025/01/21/mass-campaign-of-murdoc-botnet-mirai-a-new-variant-of-corona-mirai)
7. [Cloudflare - Mirai Botnet Overview](https://www.cloudflare.com/learning/ddos/glossary/mirai-botnet/)
8. [USENIX - Understanding the Mirai Botnet](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-antonakakis.pdf)

---

*Report generated as part of incident response and threat hunting exercise.*
