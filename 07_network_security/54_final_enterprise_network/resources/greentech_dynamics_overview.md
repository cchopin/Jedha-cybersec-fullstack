# Greentech Dynamics Inc.

## Company Profile

**Industry:** Sustainable Energy & Smart Infrastructure

**Founded:** 2018

**Headquarters:** Lyon, France (planned)

**Employees:** 400 (projected)

---

## Business Overview

Greentech Dynamics Inc. develops innovative solutions for sustainable energy management and smart infrastructure. Core business areas include:

- **Smart Grid Solutions**: Real-time energy monitoring and optimization
- **IoT Sensors**: Environmental and industrial monitoring devices
- **Energy Analytics**: AI-powered consumption prediction and optimization
- **Building Automation**: Smart HVAC and lighting control systems

---

## Organizational Structure

### Departments

| Department | Headcount | Data Sensitivity |
|------------|-----------|------------------|
| R&D | 80 | Critical (IP) |
| Engineering | 120 | High |
| Finance | 30 | High (PII, Financial) |
| Sales & Marketing | 60 | Standard |
| Human Resources | 20 | High (PII) |
| IT Operations | 40 | High (Infrastructure) |
| Executive | 10 | High |
| Facilities | 20 | Standard |
| Customer Support | 20 | Standard |

### Key Stakeholders

- **CTO**: Technical architecture approval
- **CISO**: Security requirements validation
- **CFO**: Budget approval
- **COO**: Operations continuity requirements

---

## Technical Requirements

### Infrastructure

| Component | Requirement |
|-----------|-------------|
| Data Centers | 2 (Production + DR) |
| Remote Sites | Paris branch office |
| Cloud Services | Office 365, AWS, Salesforce |
| IoT Devices | ~500 sensors deployed at client sites |

### Availability Requirements

| Service | SLA Target | Max Downtime/Year |
|---------|------------|-------------------|
| Production Systems | 99.99% | 52 minutes |
| Business Applications | 99.9% | 8.7 hours |
| Email/Collaboration | 99.9% | 8.7 hours |
| Guest WiFi | 99% | 3.6 days |

### Security Requirements

- **Compliance**: RGPD, ISO 27001 (planned)
- **Data Classification**: Public, Internal, Confidential, Restricted
- **Access Control**: Role-based, least privilege
- **Audit**: Full logging, 2-year retention

---

## Network Requirements

### Bandwidth Estimates

| Traffic Type | Peak Bandwidth | Notes |
|--------------|----------------|-------|
| Internet | 2 Gbps | Dual ISP required |
| Inter-DC | 10 Gbps | Low latency required |
| Branch (Paris) | 500 Mbps | VPN + Direct Internet |
| Cloud Services | 1 Gbps | Office 365, AWS |

### Critical Applications

| Application | Protocol | Latency Requirement |
|-------------|----------|---------------------|
| SAP ERP | TCP/3200 | < 50ms |
| VoIP | UDP/RTP | < 150ms, jitter < 30ms |
| Video Conf | UDP/TCP | < 200ms |
| IoT Data | MQTT/HTTPS | < 500ms |
| File Shares | SMB/CIFS | < 100ms |

---

## Growth Projections

### 3-Year Plan

| Year | Employees | Sites | Notes |
|------|-----------|-------|-------|
| Y1 | 400 | 2 | Lyon HQ + Paris |
| Y2 | 600 | 3 | + Munich |
| Y3 | 1000 | 5 | + New York, Singapore |

### Technology Roadmap

- **Y1**: Core infrastructure deployment, SD-WAN, NAC
- **Y2**: Zero Trust implementation, SASE adoption
- **Y3**: Global network expansion, AI-driven operations

---

## Budget Guidelines

### Capital Expenditure (CapEx)

| Category | Budget Range |
|----------|--------------|
| Network Infrastructure | €500K - €800K |
| Security Solutions | €200K - €350K |
| Data Center Equipment | €400K - €600K |

### Operational Expenditure (OpEx)

| Category | Annual Budget |
|----------|---------------|
| ISP/WAN Services | €150K - €200K |
| Cloud Services | €100K - €150K |
| Maintenance Contracts | €80K - €120K |
| Managed Security Services | €50K - €100K |

---

## Contact Information

**Project Sponsor:** Jean-Pierre Martin, CTO

**IT Director:** Sophie Dubois

**Security Manager:** Marc Lefebvre

---

*Document Classification: Internal*

*Last Updated: January 2026*
