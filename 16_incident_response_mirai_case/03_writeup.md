# When Your Roommate's Server Joins a Botnet: A Real-World IR Case Study

*A hands-on incident response and threat intelligence investigation*

---

## TL;DR

A personal web server was compromised twice in two months:
1. **December 2025**: XMRig cryptominer deployed via Strapi CMS vulnerabilities
2. **February 2026**: Mirai botnet variant (EIW) deployed via Next.js Server Actions exploitation

The investigation traced the C2 infrastructure to **Virtualine Technologies**, a Russian bulletproof hosting provider operating through shell companies in the US and transit providers in Bulgaria and the Netherlands.

---

## Part 1: The Discovery

### Something's Wrong

The first sign was obvious: the server was **loud**. The fan was spinning at full speed, and the web applications were sluggish. A quick SSH session revealed the horror:

```
$ top
PID    USER        %CPU  COMMAND
1061829 nextjs-app  45.2  /x86_64.kok
1061864 nextjs-app  18.1  /x86_64.kok
1061865 nextjs-app  12.3  /x86_64.kok
```

Three processes named `/x86_64.kok` were consuming 75% of CPU. The `.kok` extension is a known marker for **Mirai botnet variants**. This server was actively participating in DDoS attacks.

### The Network Tells a Story

```
$ netstat -an | grep ESTABLISHED
tcp  0  0  [SERVER]:random  91.92.241.12:6969  ESTABLISHED
tcp  0  0  [SERVER]:random  91.92.241.12:6969  ESTABLISHED
```

Two persistent connections to `91.92.241.12` on port **6969**. Classic C2 behavior.

But wait, there's more:

```
$ cat /proc/net/dev
eth0: 974GB transmitted, 2.7GB received
```

**974 GB transmitted in 12 days**. A TX/RX ratio of 360:1. This server wasn't just infected—it was a **DDoS cannon**.

---

## Part 2: The Forensics

### Timeline Reconstruction

Diving into file timestamps revealed two distinct compromise waves:

**Wave 1: December 5, 2025 - Cryptominer**
```
$ ls -la /var/www/webserver-next/c3pool/
-rwxr-xr-x  1 nextjs-app  3.4M Dec  5 10:02 xmrig
-rw-r--r--  1 nextjs-app  299  Dec  5 10:02 miner.sh
-rw-r--r--  1 nextjs-app  4.0M Dec  5 11:20 xmrig.log
```

XMRig cryptominer, mining Monero to two wallet addresses via public pools (c3pool, hashvault).

**Wave 2: February 3-6, 2026 - Botnet**
```
$ ls -la /tmp/
-rwxr-xr-x  1 nextjs-app  107K Feb  3 23:26 x86_32.kok.1
-rwxr-xr-x  1 nextjs-app   10K Feb  3 23:28 logic.sh
-rwxr-xr-x  1 nextjs-app  150K Feb  6 07:00 .b_aa
...
```

A dropper script (`logic.sh`) downloading multi-architecture Mirai binaries.

### The Entry Point

Two vulnerabilities were exploited:

**1. Strapi CMS (Wave 1)**
- Open public registration (`POST /api/auth/local/register`)
- Auto-confirmed accounts, no CAPTCHA
- Admin panel exposed without IP restriction
- `.env` file with secrets readable

**2. Next.js Server Actions (Wave 2)**

Nginx logs showed a coordinated attack:

```
193.142.147.209 - - [22/Jan/2026] "POST / HTTP/1.1" 200 ...
193.142.147.209 - - [28/Jan/2026] "POST / HTTP/1.1" 500 ...  <-- First successful exploit
195.3.222.78    - - [28/Jan/2026] "POST / HTTP/1.1" 500 ...
...
[8,979 requests from 193.142.147.209 alone]
```

The HTTP 500 errors indicated payload execution crashing the Node.js process—exactly what happens when Server Actions are exploited for RCE.

---

## Part 3: The Hunt

### Starting with What We Have

After cleaning the server, we preserved the key IOCs:

| IOC Type | Value |
|----------|-------|
| SHA256 | `833bca151dc3ff83cbed22b6e7e849f0ee752bac55f68e156660e4d33d17caad` |
| C2 IP | `91.92.241.12:6969` |
| C2 IP | `91.92.243.113:235` |
| File pattern | `*.kok` |

### VirusTotal Confirms Mirai

Submitting the hash to VirusTotal:

```
Detection: 34/72 (47%)
Consensus: Linux/Mirai.EIW
```

Every major AV that detected it agreed: **Mirai**. Kaspersky called it `Gafgyt.gu` (Gafgyt is Mirai's predecessor), but same family.

### The Port 6969 Connection

Port 6969 isn't random. Security researchers at **Cydome** documented a new Mirai variant called **Broadside** in December 2025:

> "Broadside employs a custom C2 protocol over TCP/1026, with **fallback communications over TCP/6969**."

Our C2 was using the fallback port. This placed our sample in the Broadside family tree.

### Following the Infrastructure

**Shodan query on 91.92.241.12:**

```
Country: Netherlands
City: Amsterdam
Organization: Neterra Ltd.
ISP: NTT America, Inc.
ASN: AS2914
OS: Ubuntu 24.04
Last Seen: 2026-02-01  <-- 5 days before our incident
```

Wait—Neterra is Bulgarian, NTT is American, but the IP range `91.92.x.x` belongs to **AS214943 (Railnet LLC)**. What's going on?

### Unmasking Railnet LLC

OSINT revealed the connection:

1. **Railnet LLC** (ASN 214943) is registered in the US
2. Railnet is a legal front for **Virtualine Technologies**
3. Virtualine is a **Russian bulletproof hosting provider**
4. Advertised on Russian underground forums by user "Secury"
5. **Spamhaus** actively tracks them as a threat

The routing path:

```
Threat Actor
    ↓
Virtualine Technologies (Russia) - Orders bulletproof hosting
    ↓
Railnet LLC (US) - Announces IP prefixes
    ↓
Neterra Ltd (Bulgaria) - Provides transit
    ↓
NTT America (US) - Tier 1 carrier
    ↓
Amsterdam Data Center - Physical location
```

This is classic bulletproof hosting: multiple layers of indirection to frustrate takedowns and attribution.

### ANY.RUN Jackpot

Searching for the `.kok` pattern on ANY.RUN found an exact match:

**Sample: logicdr.sh**
- SHA256: `bf5a1e8b25d6ef368f11028fc492cc5e4a7e623a5b603a505828ae1c2e62fa3d`
- C2: `91.92.241.12:6969` *(exact match!)*
- Downloads: `x86_64.kok`, `x86_32.kok`, `arm.kok`...
- SURICATA alert: **"MIRAI botnet detected"**

Someone had already submitted essentially the same dropper. Our incident wasn't unique—it was part of an ongoing campaign.

---

## Part 4: Attribution

### What We Can Prove

| Element | Confidence | Evidence |
|---------|------------|----------|
| Malware: Mirai.EIW | **High** | 34 AV detections, SURICATA signature |
| C2 Infra: Virtualine/Railnet | **High** | OSINT, Spamhaus tracking |
| Origin: Russia | **High** | Underground forum advertising |
| Variant: Broadside-related | **Medium** | Port 6969 signature match |
| Operators: Russian-speaking | **Medium** | Forum language, infrastructure choices |

### What We Can't Prove

- **Individual identities**: Bulletproof hosting exists specifically to prevent this
- **Specific criminal group**: Could be any Virtualine customer
- **Cryptominer attribution**: Public pools, anonymous Monero wallets
- **State sponsorship**: This looks like organized crime, not APT activity

### Threat Actor Profile

```
Type:           Cybercriminal (non-APT)
Motivation:     Financial
                - DDoS-as-a-Service (botnet rental)
                - Cryptomining (Monero)
Sophistication: Medium
                - Uses commodity malware (Mirai)
                - Leverages bulletproof infrastructure
                - Automated scanning and exploitation
Language:       Russian (inferred from infrastructure)
Operations:     Opportunistic
                - Mass scanning for vulnerable services
                - No specific targeting observed
```

---

## Part 5: Lessons Learned

### Factors That Enabled the Compromise

These configuration elements, common on development or personal servers, were exploited:

1. **Firewall not configured** - Ports were accessible from the internet
2. **Strapi admin accessible** - Default configuration without IP restriction
3. **Open registration** - Strapi feature enabled by default
4. **Secrets in .env** - Default file permissions
5. **Next.js not updated** - Recent Server Actions vulnerability
6. **No monitoring** - No alerts configured

### The Defense Checklist

```markdown
[ ] Firewall with default-deny policy
[ ] Admin panels restricted by IP or VPN
[ ] Registration disabled or protected (CAPTCHA, email verification)
[ ] Secrets with proper permissions (chmod 600)
[ ] Regular patching schedule
[ ] Log aggregation and alerting
[ ] Network traffic monitoring
[ ] Regular integrity checks (AIDE, Tripwire)
```

### Detection Opportunities

The attackers left plenty of traces:

| Indicator | Detection Method |
|-----------|------------------|
| CPU spike | Resource monitoring |
| Unusual processes | Process allowlisting |
| C2 connections | Network monitoring, port 6969 |
| Hidden files | File integrity monitoring |
| Cron modifications | Configuration auditing |
| Outbound DDoS | Netflow analysis |

---

## Part 6: The Cleanup

### Immediate Actions

```bash
# Kill malicious processes
kill -9 $(pgrep -f '.kok')

# Remove botnet files
rm -rf /tmp/.b_* /tmp/.bins /tmp/.x /tmp/logic.sh /tmp/*.kok
rm -f /var/tmp/.monitor
rm -f /dev/shm/lrt

# Remove cryptominer
rm -rf /var/www/webserver-next/c3pool
rm -f /var/www/webserver-next/sex.sh
rm -f /var/www/webserver-next/kal.tar.gz

# Clean persistence
# (restore .profile, check crontabs, check rc.d)
```

### Results

| Metric | Before | After |
|--------|--------|-------|
| CPU usage | 78% | 10% |
| Network TX | 974 GB/12 days | Normal |
| Malicious processes | 5 | 0 |
| C2 connections | 2 | 0 |

### Hardening

```bash
# Enable firewall
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow http
ufw allow https
ufw enable

# Block known-bad IPs
iptables -A OUTPUT -d 91.92.241.0/24 -j DROP
iptables -A OUTPUT -d 91.92.243.0/24 -j DROP
iptables -A INPUT -s 138.121.0.0/16 -j DROP
```

---

## Conclusion

This incident demonstrates the reality of modern cybercrime:

1. **Opportunistic attacks dominate** - Automated scanners found and exploited misconfigurations
2. **Multiple payloads are common** - Cryptomining and botnets often coexist
3. **Attribution is hard but possible** - Following infrastructure leads to bulletproof hosting
4. **Bulletproof hosting enables crime** - Virtualine and similar providers are the backbone
5. **A few simple measures are enough** - A firewall and regular updates would have blocked these attacks

The attackers weren't sophisticated. They used commodity malware (Mirai), public mining pools, and rented infrastructure. This type of opportunistic attack targets thousands of servers daily—this one was simply part of the sweep.

**The good news: these attacks are easily preventable with basic security measures. A firewall and access restrictions would have been enough.**

---

## Resources

### Tools Used
- [VirusTotal](https://www.virustotal.com/) - Malware identification
- [Shodan](https://www.shodan.io/) - Infrastructure reconnaissance
- [ANY.RUN](https://any.run/) - Malware sandboxing
- [AbuseIPDB](https://www.abuseipdb.com/) - IP reputation
- [IPinfo](https://ipinfo.io/) - ASN lookup

### References
- [Cydome - Broadside Analysis](https://cydome.io/cydome-identifies-broadside-a-new-mirai-botnet-variant-targeting-maritime-iot/)
- [USENIX - Understanding the Mirai Botnet](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-antonakakis.pdf)
- [Spamhaus - Bulletproof Hosting](https://www.spamhaus.org/resource-hub/bulletproof-hosting/)
- [MITRE ATT&CK - Linux Techniques](https://attack.mitre.org/matrices/enterprise/linux/)

---

*This write-up is based on a real incident. Server identifying information has been redacted. IOCs are defanged for safety.*

**Author:** Security Incident Response Team  
**Date:** February 2026  
**Classification:** TLP:CLEAR  
