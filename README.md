<h1 align="center">Enes Arda Baydaş</h1>
<h3 align="center">SOC Analyst Candidate | Building Detection & DFIR Labs</h3>

<p align="center">
Turkey | Available for SOC Analyst Internship.
</p>

<p align="center">
  <a href="https://linkedin.com/in/enesardabaydas"><img src="https://img.shields.io/badge/LinkedIn-blue?style=for-the-badge&logo=linkedin"/></a>
  <a href="mailto:enesardabaydas@gmail.com"><img src="https://img.shields.io/badge/Gmail-D14836?style=for-the-badge&logo=gmail&logoColor=white"/></a>
</p>

## About Me
SOC Analyst candidate building proactive threat detection and malware triage pipelines. Specialized in bridging the gap between theoretical security concepts and applied engineering through custom lab environments and automation. Currently a Management Information Systems student at Marmara University.

##  Certifications & Continuous Learning

CompTIA Security+ (In Progress)

## Technical Arsenal
| Category | Tools & Frameworks |
| :--- | :--- |
| **Security Frameworks** | MITRE ATT&CK®, MITRE D3FEND™, Cyber Kill Chain, Unified Kill Chain |
| **Network Traffic Analysis** | Wireshark, Snort, NetworkMiner, Zeek, Brim |
| **SIEM & Log Management** | Splunk (SPL), Elastic (ELK) |
| **Endpoint Monitoring** |	Windows Event Logs & Sysmon
---

### Featured Engineering Projects

* **[Autonomous Tier 1 Phishing Triage Pipeline](https://github.com/eabboa/eabboa/blob/main/Home-Labs/Autonomous_Tier_1_Phishing_Triage_Pipeline.md)**
    * *Architecture:* Engineered a two-process SOC automation system using a LangGraph ReAct AI agent and a FastMCP tool server.
    * *Capabilities:* Automates email ingestion, extracts IOCs via Regex, queries live threat intelligence (VirusTotal API), and routes verdicts to a SIEM.
    * *SIEM Integration:* Configured Splunk Enterprise for continuous JSON log ingestion, building a real-time "Single Pane of Glass" dashboard for threat distribution and analyst queues.
    * *Constraints Overcome:* Managed API rate limits via asynchronous batch processing loops and engineered custom JSON log formatters to ensure SIEM compatibility.

## Lab Exercises & Security Write-ups

<!-- PORTFOLIO:START -->

* **[Malware-Analysis](./Malware-Analysis/)**
  * *Static & Dynamic triage of obfuscated payloads (e.g., Cryptbot, Loaders). IOC extraction and MITRE ATT&CK mapping.*
  * [Agent Tesla VBA Dropper](./Malware-Analysis/Agent_Tesla_VBA_Dropper.md)
  * [WannaCry Memory Forensics Analysis](./Malware-Analysis/WannaCry_Memory_Forensics_Analysis.md)

* **[Network-Forensics](./Network-Forensics/)**
  * *PCAP analysis, C2 traffic identification, and protocol abuse detection.*
  * [ARP Spoofing Competing MITM Analysis](./Network-Forensics/ARP_Spoofing_Competing_MITM_Analysis.md)
  * [CobaltStrike and IcedID Infection](./Network-Forensics/CobaltStrike-and-IcedID-Infection.md)
  * [PCAP Analysis of SSL Stripping&Credential Theft](./Network-Forensics/PCAP_Analysis_of_SSL_Stripping&Credential_Theft.md)
  * [Triage of Local DNS Spoofing Activity](./Network-Forensics/Triage_of_Local_DNS_Spoofing_Activity.md)

* **[SIEM-Hunting](./SIEM-Hunting/)**
  * *Splunk/ELK queries, Sigma rules, and brute-force detection.*
  * [AI As C2 Theoretical Analysis](./SIEM-Hunting/AI_as_C2_Theoretical_Analysis.md)
  * [BITSAdmin LOLBin C2 Kibana](./SIEM-Hunting/BITSAdmin_LOLBin_C2_Kibana.md)
  * [LOLBin C2 Beaconing Via BITS Jobs](./SIEM-Hunting/LOLBin_C2_Beaconing_via_BITS_Jobs.md)

* **[Incident-Response](./Incident-Response/)**
  * *Forensic timeline reconstruction, live triage, and containment playbooks for active breaches.*
  * [Boogeyman1 Phishing DNS Exfiltration](./Incident-Response/Boogeyman1_Phishing_DNS_Exfiltration.md)
  * [Boogeyman2 Macro to C2 Memory Analysis](./Incident-Response/Boogeyman2_Macro_to_C2_Memory_Analysis.md)
  * [Tempest IR Follina Killchain](./Incident-Response/Tempest_IR_Follina_Killchain.md)

* **[Detection-Engineering](./Detection-Engineering/)**
  * *Custom YARA/Snort signatures, proactive alert creation, and false-positive tuning against adversary tradecraft.*
  * [Atomic Red Team Emulation Sysmon Detection](./Detection-Engineering/Atomic_Red_Team_Emulation_Sysmon_Detection.md)

<!-- PORTFOLIO:END -->
