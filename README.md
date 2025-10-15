# Internal-Penetration-Test---Design-World

# Internal Network Penetration Test – Design World

## Overview
This repository contains the deliverables and findings from an internal penetration test conducted against the Design World enterprise environment. The objective of this assessment was to identify exploitable vulnerabilities in a segmented network simulating a real-world enterprise domain, and to evaluate the potential impact of these vulnerabilities on business operations.

> **Engagement Period**: Jun 2025 – Aug 2025  
> **Role**: Penetration Tester | Red Team Operator  
> **Client**: Simulated Enterprise – Design World  
> **Report**: [Read Full PDF](https://cyberbykayvon.com/designworldpentest.pdf) *(link placeholder)*

---

## Scope of Work
- **Target Systems**: 8 hosts including Windows Server (AD/DC), user endpoints, Linux servers, and file servers.
- **In-Scope Services**: SMB, RDP, LDAP, DNS, Kerberos, TLS.
- **Assessment Type**: Internal Penetration Test (no credentials provided).

---

## Methodology
The penetration test followed a structured approach combining automated and manual techniques:

1. **Reconnaissance**  
   - Nmap scans to discover hosts and services  
   - Banner grabbing and service enumeration

2. **Vulnerability Assessment**  
   - Identification of known CVEs (e.g., MS17-010)  
   - Weak cipher detection (SWEET32, RC4)

3. **Exploitation**  
   - Simulated attacks on vulnerable SMBv1 service  
   - RDP exposure analysis and brute-force scenarios

4. **Post-Exploitation & Lateral Movement**  
   - Active Directory service enumeration  
   - Kerberos attack surface analysis

5. **Reporting & Remediation Planning**  
   - Documented impact, CVSS scores, and mitigation recommendations

---

## Key Findings

| CVE ID         | Severity | Description                                      |
|----------------|----------|--------------------------------------------------|
| CVE-2017-0143  | 🔴 High   | EternalBlue - SMB RCE vulnerability              |
| CVE-2016-2183  | 🔴 High   | SWEET32 – Weak TLS/SSL ciphers                   |
| CVE-2013-2566  | 🟠 Medium | RC4 Cipher Suite Support                         |
| RDP Exposure   | 🔴 High   | Unrestricted access to RDP (TCP/3389)            |
| AD Services    | 🔴 Critical | LDAP/Kerberos accessible to unauthorized networks |

---

## Tools & Technologies
- 🔹 Nmap
- 🔹 Wireshark
- 🔹 Windows & Linux OSes
- 🔹 Kali Linux
- 🔹 Manual Exploitation Techniques
- 🔹 CVE Exploit Research
- 🔹 MSRPC, SMB, and RDP Analysis

---

## Remediation Recommendations
- Patch vulnerable SMB services (MS17-010).
- Block RDP at perimeter; use VPN + NLA + MFA.
- Harden AD infrastructure; restrict LDAP/Kerberos.
- Enforce strong TLS configurations (disable RC4/SWEET32).
- Deploy centralized SIEM for AD & RDP event logging.
- Apply the principle of least privilege and network segmentation.

---

## Deliverables
- 📝 Full PDF Report: `DesignWorld_Pentest_Report.pdf`
- 🖼️ Screenshots of scans and findings (appendix)
- 📁 Nmap scan outputs (XML/Greppable formats)

---

## Learning Objectives / Takeaways
- Demonstrated ability to execute a full-scope internal penetration test in a simulated enterprise.
- Identified and exploited real-world CVEs with valid proof-of-concept attacks.
- Delivered professional, business-impact-focused reporting with actionable remediation.

---

## Reference
- [MS17-010 – Microsoft Security Bulletin](https://msrc.microsoft.com)
- [NIST CVE Database](https://nvd.nist.gov)

---

## Disclaimer
This penetration test was conducted in an isolated lab environment with permission and does not reflect unauthorized access to real-world systems. Always obtain proper authorization before conducting any form of security testing.

---

## Author
**Kayvon Karimi**  
Cybersecurity Engineer | Offensive Security | Penetration Tester  
[CyberByKayvon.com](https://cyberbykayvon.com)
