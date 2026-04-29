# Sentinel-Native Autonomous Triage Agent

![Python](https://img.shields.io/badge/Python-3.13-3776AB?style=flat-square&logo=python&logoColor=white)
![LangGraph](https://img.shields.io/badge/LangGraph-StateGraph-1C3C3C?style=flat-square)
![Microsoft Sentinel](https://img.shields.io/badge/Microsoft_Sentinel-REST_API-0078D4?style=flat-square&logo=microsoftazure&logoColor=white)
![Claude](https://img.shields.io/badge/Claude-4.6_Sonnet-D97757?style=flat-square&logo=anthropic&logoColor=white)
![Google Gemini](https://img.shields.io/badge/Gemini-2.5_Flash-4285F4?style=flat-square&logo=google&logoColor=white)
![VirusTotal](https://img.shields.io/badge/VirusTotal-API_v3-394EFF?style=flat-square)
![AbuseIPDB](https://img.shields.io/badge/AbuseIPDB-API_v2-8B0000?style=flat-square)
![asyncio](https://img.shields.io/badge/asyncio-Concurrent_Execution-2C5BB4?style=flat-square)
![aiohttp](https://img.shields.io/badge/aiohttp-Async_I/O-2C5BB4?style=flat-square)
![Pydantic](https://img.shields.io/badge/Pydantic-Structured_Output-E92063?style=flat-square)

**Type:** Cloud Security / Detection Engineering / AI Automation  
**Stack:** Microsoft Azure · Microsoft Sentinel · LangGraph · Pydantic · Managed Identities · Google Gemini · VirusTotal · AbuseIPDB
**Cost:** $0 (free tier across all services)  
**Code:** [sentinel-triage-agent](https://github.com/eabboa/sentinel-triage-agent)

**Objective:** A defensively engineered, zero-cost **SOAR architecture** designed to safely absorb Tier 1 benign-positive alarm fatigue without compromising true positive retention. It shifts the operational paradigm from reactive manual polling to deterministic, machine-speed orchestration.

_Note_: This project establishes the logic of cybersecurity automation. LLMs were actively used to bridge coding execution. LLMs are strictly bound as reasoning engines, constrained by code, to solve SOC bottlenecks under rigid production requirements.

_Status_: v0.3.0 Active,  Currently being **_updated_**.

---

## What I Built

Most SIEM integrations flow in one direction: a tool reads logs and produces output elsewhere. This project is **bidirectional**. Sentinel is both the source and the destination. 

The agent reads an incident, extracts raw alerts, and orchestrates asynchronous threat intelligence enrichment. It leverages a **RAG-based correction loop** to retrieve historical decisions, reasons about severity, and performs LLM-based deterministic classification. 

It then generates **schema-aware KQL hunting** queries and posts the structured verdict back into the incident record. Finally, conditional routing enables dynamic state execution, from silent closure of benign events to active, HITL-gated endpoint containment for critical threats.

That is the architecture SOAR platforms implement. This is a recreation of it for $0.

## What This Covers

| Area | Specifics |
|---|---|
| Cloud infrastructure | Azure tenant setup, Log Analytics Workspace, Microsoft Sentinel APIs. |
| Identity and access | Zero-secret architecture utilizing Azure Managed Identities (DefaultAzureCredential) and tightly scoped RBAC. |
| Resilient Orchestration | LangGraph StateGraph orchestration with conditional routing, minimizing token consumption, and bypassing irrelevant execution nodes mid-flight. |
| Adaptive Learning | RAG-based feedback loops capture analyst corrections, continually optimizing KQL generation and classification accuracy over time. |
| Deterministic AI | LangChain with_structured_output paired with rigid Pydantic schemas. LLM unreliability is mitigated by forcing 100% valid state transitions. |
| Asynchronous I/O | asyncio and aiohttp execute concurrent CTI enrichment (VirusTotal API v3, AbuseIPDB API v2) and multi-incident polling governed by rate-limit semaphores. |
| Active Containment | Azure REST API integration for automated, HITL-gated remediation (e.g., dynamic host isolation, IP blocking).  |

---

## Architecture Flow

Each node strictly adheres to the Single Responsibility Principle. The pipeline is bound by a typed state schema; any undocumented key mutation results in immediate failure, preventing silent downstream corruption.


```text
[Main Entry]       Asyncio.gather polls multiple incidents in concurrent with rate-limit Semaphores
         │
         ▼
    [Fetch Node]       Pull incident metadata and associated raw alerts via REST API
         │
         ▼
  [Summarize Node]     Condense raw alert data into a token-efficient summary (Deterministic, no LLM)
         │
         ▼
   [Extract Node]      Regex extracts IPs/Hashes/URLs; tightly-prompted LLM extracts usernames/hostnames
         │
         ▼
   [Enrich Node]       Concurrent async queries to AbuseIPDB (IPs) and VirusTotal (URLs, hashes)
         │
         ▼
  [Learning Node]      RAG retrieval of historical analyst corrections to ground the current prompt
         │
         ▼
  [Analyst Node]       LLM evaluates "state" against a strict Pydantic schema for deterministic transition
         │
         ├──► (If Benign/False Positive) ──► [Conditional Bypass to Write-back]
         │
         ▼ (If Suspicious/True Positive)
    [KQL Node]         Schema-gated KQL hunting queries restricted to active workspace tables
         │
         ▼
 [Write-back Node]     PUT request with Optimistic Concurrency Control (ETag) validation
         │
         ▼
 [HITL Interrupt]      Execution suspends. Awaits manual verification of state and recommended actions.
         │
         ├──► (Approve Containment) ──► [Containment Node] (Executes active isolation via Azure APIs)
         │
         ▼ (Approve Closure)
[Close Review Node]    Executes Sentinel API closure workflow
```

## Designing for Failure

A security automation tool that fails open or corrupts state is a liability. Applying the principle of inversion. Solving for what guarantees failure, then engineering it out, results in the following fault-tolerance mechanisms:

**Race Condition Immunity (Optimistic Concurrency Control):** Human analysts and automated rules interact with incidents simultaneously. Utilizing Azure ETags (If-Match headers) guarantees the pipeline will never blindly overwrite an analyst's manual update if the incident state mutated during the agent's execution window.

**Credential Compromise Elimination:** Hardcoded secrets are an unacceptable attack vector. The pipeline utilizes DefaultAzureCredential to inherit the identity of the compute environment, fully eliminating credential rotation and exposure risks.

**Probabilistic Containment:** LLMs are probabilistic, making them dangerous for autonomous state machines. By binding the LLM output to a strict Pydantic schema, the agent is forced into strongly typed outputs. Validation errors are caught at the node level, preventing cascading failures or hallucinatory KQL execution.

**Graceful Degradation on CTI Timeout:** Third-party threat intel APIs routinely throttle. The scoring logic treats missing or timed-out CTI data as a neutral baseline rather than defaulting to "benign," ensuring transient network errors never result in false negatives.
