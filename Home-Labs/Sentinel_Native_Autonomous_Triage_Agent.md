# Sentinel-Native Autonomous Triage Agent

![Python](https://img.shields.io/badge/Python-3.13-3776AB?style=flat-square&logo=python&logoColor=white)
![LangGraph](https://img.shields.io/badge/LangGraph-StateGraph-1C3C3C?style=flat-square)
![Microsoft Sentinel](https://img.shields.io/badge/Microsoft_Sentinel-REST_API-0078D4?style=flat-square&logo=microsoftazure&logoColor=white)
![Claude](https://img.shields.io/badge/Claude-4.6_Sonnet-D97757?style=flat-square&logo=anthropic&logoColor=white)
![Google Gemini](https://img.shields.io/badge/Gemini-2.5_Flash-4285F4?style=flat-square&logo=google&logoColor=white)
![Microsoft Entra ID|114](https://img.shields.io/badge/Entra_ID-OAuth2_MSAL-0072C6?style=flat-square&logo=microsoft&logoColor=white)
![VirusTotal](https://img.shields.io/badge/VirusTotal-API_v3-394EFF?style=flat-square)
![AbuseIPDB](https://img.shields.io/badge/AbuseIPDB-API_v2-8B0000?style=flat-square)
![aiohttp](https://img.shields.io/badge/aiohttp-Async_I/O-2C5BB4?style=flat-square)

**Type:** Home Lab - Cloud Security / Detection Engineering / AI Automation  
**Stack:** Microsoft Azure · Microsoft Sentinel · LangGraph · Google Gemini · VirusTotal · AbuseIPDB  
**Cost:** $0 (free tier across all services)  
**Code:** [sentinel-triage-agent](https://github.com/eabboa/sentinel-triage-agent)

_Status_: Currently being updated.

_Note_: This project is designed as a prototype to establish the logic of cybersecurity. LLMs (Github Copilot/Gemini/Claude) were actively used in the coding processes. My focus is not on software engineering, but rather on designing a security architecture that will solve the bottlenecks in SOC processes.

---

## What I Built

An autonomous pipeline that reads live incidents from **Microsoft Sentinel**, triages them using an **LLM**, and writes a structured verdict back into the incident as a comment. Without any human in the loop, if it is a benign-positive.

Most SIEM integrations flow in one direction: a tool reads logs and produces output elsewhere. This project is **bidirectional**. Sentinel is both the source and the destination. 

The agent reads an incident, extracts raw alerts, orchestrates threat intelligence enrichment concurrently, reasons about severity, performs LLM-based deterministic classification, generates schema-aware **KQL** hunting queries, and posts the result back into the incident record where a human analyst would see it. 

That is the architecture SOAR platforms implement. This is a recreation of it for $0.

## What This Covers

| Area | Specifics |
|---|---|
| Cloud infrastructure | Azure tenant setup, Log Analytics Workspace, Microsoft Sentinel |
| Identity and access | Service Principal, App Registration, OAuth2 Client Credentials flow, RBAC at Resource Group scope |
| API integration | Sentinel REST API (incidents, alerts, comments, status updates), Azure policy constraints |
| Detection engineering | MITRE ATT&CK tactic mapping, KQL query generation, schema-aware prompting |
| AI automation | LangGraph StateGraph orchestration, LLM-based triage reasoning, structured JSON output |
| Threat intelligence | VirusTotal API v3, AbuseIPDB API v2, async concurrent enrichment |
| Engineering judgment | Token budget management, rate limit handling, fault isolation per node |

# Sincerity first.

How did I make that happen?

I already had the idea of this:

"Shift your LangGraph pipeline to integrate directly with Microsoft Sentinel. Deploy a free Azure tenant. Feed it sample attack data. Write Python scripts to pull incidents via the Sentinel REST API. Use LangGraph to analyze the data, query external CTI (VirusTotal and AbuseIPDB), and automatically post a triage summary and recommended KQL hunting queries back into the Sentinel incident comments."

My previous phishing triage project was localized. It merely monitored an inbox folder for .txt files. This project represents the jump to bidirectional, enterprise-grade SIEM integration.

I provided the idea to **Claude** to generate the Python scripts.

I then manually audited and commented the code line-by-line (visible in the source files). I provided the **what** and **why**. AI provided the how.

---

## Architecture

<img width="2773" height="1510" alt="MS Sentinel final" src="https://github.com/user-attachments/assets/d95821ec-2a9a-4fa4-846f-82d360e9e514" />


Each node is a single-responsibility function. The pipeline is orchestrated by **LangGraph**, which enforces a typed state schema shared across all nodes. If a node writes a key not defined in the schema, it fails immediately rather than propagating silently.

---

```
Sentinel Incident (New status)
         │
         ▼
    [Fetch Node]         Pull incident metadata and associated raw alerts via REST API
         │
         ▼
  [Summarize Node]       Condense raw alert data into a token-efficient summary (no LLM)
         │
         ▼
   [Extract Node]        Regex extracts IPs, hashes, URLs — LLM extracts usernames, hostnames
         │
         ▼
   [Enrich Node]         Async queries to AbuseIPDB (IPs) and VirusTotal (URLs, hashes)
         │
         ▼
  [Analyst Node]         LLM produces a structured verdict on a confidence level of 0-100
         │
         ▼
    [KQL Node]           Schema-gated KQL hunting queries using only tables present in the workspace
         │
         ▼
 [Write-back Node]       Posts formatted triage report to Sentinel incident auto-closes BenignPositive
```
---

## Key Design Decisions

**Why deterministic pre-processing before the LLM?**  
Sentinel alerts can contain hundreds of raw log lines, base64 blobs, and repeated fields. Feeding that directly into an LLM wastes tokens and degrades reasoning quality. A separate summarize node uses **string truncation** and **field selection** to produce a clean, budget-conscious input. The LLM only touches data that requires language understanding. 

**Why async for CTI enrichment?**  
Synchronous requests would query each indicator serially. For a batch of three IPs and two URLs, that is five blocking HTTP calls in sequence. Async fires all IP lookups simultaneously via **asyncio.gather()**, then rate-limits VirusTotal calls individually (4 requests/minute on the free tier). This cuts enrichment time without exceeding API limits.

**Why schema-gated KQL generation?**  
LLMs hallucinate Kusto at roughly a 40% error rate when given no constraints. They invent table names and reference columns that do not exist in the workspace. The KQL node provides an explicit schema map in the prompt only for tables that exist in a fresh Sentinel tenant with their valid column names. And the gates table selection by the detected MITRE tactic. This reduces the error rate drastically.

**Why PUT instead of PATCH for incident updates?**  
The Sentinel REST API does not support partial updates on incidents. The full incident object must be fetched, modified, and sent back via PUT. Sending only the changed fields returns a 400 error.

**Why is BenignPositive the only auto-close classification?**  
TruePositive incidents require human escalation before closure. False-positive incidents require rule-tuning review. BenignPositive, alert fired correctly, but the activity is authorized, is the only classification where auto-closing does not bypass a necessary review step.

---

## What I Ran Into

**Azure for Students region restrictions**  
The subscription has a hardcoded policy that restricts certain resource types to a non-overlapping set of regions. Log Analytics Workspaces are allowed in West-Europe. Azure Automation Accounts (which the Microsoft Training Lab uses to inject sample data) are not. I identified the allowed regions by querying the policy assignments directly from Cloud Shell, then deployed everything to `germanywestcentral`.

**Microsoft Training Lab ARM template failure**  
The official Sentinel Training Lab deployment script requires Automation Accounts in regions my subscription cannot access. I abandoned the template and built a synthetic incident generator using a Sentinel Analytics Rule with an inline `datatable` KQL query. Which produces incidents natively without any external tooling.

**aiohttp boolean parameter rejection**  
`aiohttp` enforces strict types on query parameters. Python `True` is not accepted. The string `"true"` is required. This caused the AbuseIPDB async calls to crash at the parameter encoding stage.


---

## Example Output

<img width="1919" height="1047" alt="Pasted image 20260427083107" src="https://github.com/user-attachments/assets/3a7f72d3-c49c-40be-8b5d-d48dd467af37" />

<img width="927" height="385" alt="Pasted image 20260427082826" src="https://github.com/user-attachments/assets/dbdc73c8-7398-4148-ba2c-5c494dede0ae" />
The agent posts a formatted markdown comment directly into the Sentinel incident:

```
## 🤖 Autonomous Triage Agent Report

**Verdict:** TruePositive

### Summary
Malicious IP and file hash confirm a genuine threat. User account was compromised.
A malicious payload was successfully downloaded from an external host.

### MITRE ATT&CK Analysis
Password spray and successful login align with Credential Access (T1110).
Subsequent payload download indicates execution of a secondary stage.

### Extracted Entities
IPs: 185.220.101.14
URLs: https://spotify-premium-mod.latestmodapks.com/
Hashes: 44d88612fea8a8f36de82e1278abb02f
Users: kenzou.tenma@monster.com

### CTI Enrichment
🔴 IP 185.220.101.14: AbuseIPDB score 100/100 (Fixed Line ISP | DE)
🟢 URL https://spotify-premium-mod.latestmodapks.com/: 0/95 VT detections

### KQL Hunting Queries
// Suspicious Sign-ins from Malicious IP
SigninLogs
| where IPAddress == '185.220.101.14'
| where TimeGenerated > ago(7d)

_Generated by sentinel-triage-agent | LangGraph + Gemini + VirusTotal + AbuseIPDB_
```

---

## Known Limitations

This is a working prototype, not a production system. Three structural problems exist that I documented but did not fix in this iteration:

**No conditional routing.** The graph is linear. If the fetch node fails, every downstream node still runs — burning LLM tokens to analyze an empty state. The correct fix is a conditional edge after the fetch node that routes failures to a dedicated error handler, bypassing all LLM and CTI nodes.

**Comment idempotency.** Each run generates a fresh UUID for the Sentinel comment. A crash-and-retry produces a duplicate comment. The fix is to derive the comment UUID from a hash of `incident_id + date`, making the same incident on the same day idempotent. Azure would reject the second PUT.
