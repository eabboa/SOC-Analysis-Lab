# Sentinel-Native Autonomous Triage Agent

![Python](https://img.shields.io/badge/Python-3.13-3776AB?style=flat-square&logo=python&logoColor=white)
![LangGraph](https://img.shields.io/badge/LangGraph-StateGraph-1C3C3C?style=flat-square)
![Microsoft Sentinel](https://img.shields.io/badge/Microsoft_Sentinel-REST_API-0078D4?style=flat-square&logo=microsoftazure&logoColor=white)
![Claude](https://img.shields.io/badge/Claude-4.6_Sonnet-D97757?style=flat-square&logo=anthropic&logoColor=white)
![Google Gemini](https://img.shields.io/badge/Gemini-2.5_Flash-4285F4?style=flat-square&logo=google&logoColor=white)
![Microsoft Entra ID|114](https://img.shields.io/badge/Entra_ID-OAuth2_MSAL-0072C6?style=flat-square&logo=microsoft&logoColor=white)
![VirusTotal](https://img.shields.io/badge/VirusTotal-API_v3-394EFF?style=flat-square)
![AbuseIPDB](https://img.shields.io/badge/AbuseIPDB-API_v2-8B0000?style=flat-square)
![asyncio](https://img.shields.io/badge/asyncio-Parallel_Execution-2C5BB4?style=flat-square)
![aiohttp](https://img.shields.io/badge/aiohttp-Async_I/O-2C5BB4?style=flat-square)
![Pydantic](https://img.shields.io/badge/Pydantic-Structured_Output-E92063?style=flat-square)

**Type:** Cloud Security / Detection Engineering / AI Automation  
**Stack:** Microsoft Azure · Microsoft Sentinel · LangGraph · Pydantic · Managed Identities · Google Gemini · VirusTotal · AbuseIPDB
**Cost:** $0 (free tier across all services)  
**Code:** [sentinel-triage-agent](https://github.com/eabboa/sentinel-triage-agent)

**Objective:** A defensively engineered, zero-cost SOAR prototype designed to safely handle Tier 1 benign-positive alarm fatigue without compromising true positive retention or crashing under high log volumes. 

_Note_: This project establishes the logic of cybersecurity automation. LLMs were actively used to bridge coding execution. The focus is on designing an enterprise-resilient security architecture that solves SOC bottlenecks under production constraints.

---

## What I Built

An autonomous pipeline that reads live incidents from **Microsoft Sentinel**, triages them using an **LLM**, and writes a structured verdict back into the incident as a comment, requiring explicit human approval before altering incident status.

Most SIEM integrations flow in one direction: a tool reads logs and produces output elsewhere. This project is **bidirectional**. Sentinel is both the source and the destination. 

The agent reads an incident, extracts raw alerts, orchestrates threat intelligence enrichment concurrently, reasons about severity, performs LLM-based deterministic classification, generates schema-aware **KQL** hunting queries, and posts the result back into the incident record where a human analyst would see it. 

That is the architecture SOAR platforms implement. This is a recreation of it for $0.

## What This Covers

| Area | Specifics |
|---|---|
| Cloud infrastructure | Azure tenant setup, Log Analytics Workspace, Microsoft Sentinel |
| Identity and access | Azure Managed Identities, DefaultAzureCredential, RBAC at Resource Group scope (Zero-secret architecture) |
| API integration | Sentinel REST API (incidents, alerts, comments, status updates), Azure policy constraints |
| Detection engineering | MITRE ATT&CK tactic mapping, KQL query generation, schema-aware prompting |
| AI automation | LangGraph StateGraph orchestration, LangChain with_structured_output, Pydantic strict schema validation |
| Threat intelligence | VirusTotal API v3, AbuseIPDB API v2, async concurrent enrichment |
| Engineering judgment | Optimistic Concurrency Control (ETag), async/await parallel execution, API rate-limit semaphores, HITL gating  |

---

## Architecture Flow

Each node is a single-responsibility function. The pipeline is orchestrated by **LangGraph**, which enforces a typed state schema shared across all nodes. If a node writes a key not defined in the schema, it fails immediately rather than propagating silently.

```text
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
 [Write-back Node]       Posts formatted triage report to Sentinel incident with 'Pending Analyst Review' tag
         │
         ▼
 [HITL Interrupt]        Execution pauses. Awaits manual verification of LLM output.
         │
         ▼
[Close Review Node]      Executes Sentinel API closure only upon explicit human approval
```

## Designing for Failure

A SOAR pipeline that cannot handle failure is a liability, not an asset. To ensure enterprise resilience, I engineered this system with strict fault-tolerance mechanisms:

1. **Optimistic Concurrency Control (ETag):** In a real SOC, human analysts and automated rules access incidents simultaneously. By utilizing Azure ETags (`If-Match` headers), the pipeline guarantees it will never blindly overwrite an analyst's manual update if the incident state changed during the pipeline's execution window.
2. **Secretless Authentication:** Hardcoded secrets are an unacceptable attack vector. The pipeline utilizes Azure's `DefaultAzureCredential`, assuming the identity of the compute environment (Managed Identity) rather than relying on rotating client secrets.
3. **Deterministic State Transitions:** LLMs are inherently probabilistic, which is dangerous for state machines. By binding the LLM output to LangChain's `with_structured_output` and a strict `Pydantic` schema, the agent is forced to return strongly typed verdicts. If it fails, the node catches the validation error rather than crashing the downstream KQL generation.
4. **Graceful Degradation on CTI Failure:** Third-party threat intel APIs (VirusTotal, AbuseIPDB) frequently throttle or timeout. The scoring logic treats missing CTI data as a neutral baseline rather than defaulting to "benign," preventing transient network errors from causing false negatives.
