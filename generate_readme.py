# ── Config ────────────────────────────────────────────────────────────────────

# Top-level folders to include (order preserved)
TRACKED_DIRS = [
    "Malware-Analysis",
    "Network-Forensics",
    "SIEM-Hunting",
    "Incident-Response",
    "Detection-Engineering",
]

# Folder-level descriptions (shown as the parent bullet subtitle)
DIR_META = {
    "Malware-Analysis": "Static & Dynamic triage of obfuscated payloads (e.g., Cryptbot, Loaders). IOC extraction and MITRE ATT&CK mapping.",
    "Network-Forensics": "PCAP analysis, C2 traffic identification, and protocol abuse detection.",
    "SIEM-Hunting":      "Splunk/ELK queries, Sigma rules, and brute-force detection.",
    "Incident-Response": "Forensic timeline reconstruction, live triage, and containment playbooks for active breaches.",
    "Detection-Engineering": "Custom YARA/Snort signatures, proactive alert creation, and false-positive tuning against adversary tradecraft.",
}