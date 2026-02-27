# FORENSIC EVIDENCE PACKAGE
## Case: INC-2024-1114-001 | Corporate Data Breach
### Target Organization: TargetCorp Pvt. Ltd.

---

## CASE SUMMARY
On the night of 2024-11-14, an insider threat actor (corporate admin account)
exfiltrated approximately 562MB of confidential employee and payroll data
to an anonymous cloud storage via a TOR exit node. A concurrent external
attack involving a RAT (Remote Access Trojan) was also detected.

---

## EVIDENCE FILES

### 1. system_access.log
**What it is:** Corporate server authentication and file system logs
**Key findings:**
- Admin login at 00:02 (suspicious — middle of night)
- Confidential files copied to hidden temp folder
- Data sent to 185.220.101.47 (TOR exit node, Germany)
- Log tampering attempted at 00:05
- Brute force attack from 203.0.113.42 (Russia) at 09:17
- Malware C2 communication from dev.service account at 14:23

**Good demo questions:**
- "What happened at midnight on November 14th?"
- "Which user accessed confidential files?"
- "Were any log tampering attempts detected?"

---

### 2. network_traffic.log
**What it is:** Firewall and network monitor logs
**Key findings:**
- 61MB outbound transfer to TOR node (185.220.101.47)
- Port scan from Russian IP (203.0.113.42)
- Regular C2 beaconing every 45 seconds to 91.108.4.100
- 500MB upload to mega.nz (data exfiltration)

**Good demo questions:**
- "What suspicious outbound connections were made?"
- "Is there evidence of C2 communication?"
- "How much data was exfiltrated?"

---

### 3. email_records.csv
**What it is:** Email server logs with threat classifications
**Key findings:**
- Phishing email targeting admin account (E001)
- Admin sent company data to anonymous ProtonMail (E004, E005)
- CEO impersonation / BEC fraud attempt (E006)
- Malware delivery via fake Adobe update (E008)

**Good demo questions:**
- "Which emails show signs of phishing?"
- "Did the admin send any suspicious emails?"
- "Was there a business email compromise attempt?"

---

### 4. malware_analysis.txt
**What it is:** Automated sandbox analysis of malware sample
**Key findings:**
- AGENT_TESLA RAT v3.6 identified
- Keylogger + credential stealer capabilities
- Process injection into explorer.exe
- Registry persistence mechanism
- Full IOC list with hashes, IPs, domains

**Good demo questions:**
- "What malware was found and what does it do?"
- "What are the indicators of compromise?"
- "How did the malware achieve persistence?"

---

### 5. location_tracking.log
**What it is:** Mobile device GPS and cell tower data
**Key findings:**
- Suspect was at home (Koramangala, Bangalore) during entire breach
- GPS coords: 12.971598, 77.594562
- Contradicts suspect's alibi
- Corroborates that breach was conducted from residential address

**Good demo questions:**
- "Where was the suspect during the breach?"
- "What GPS coordinates were found?"
- "Does the location data support or contradict the suspect's alibi?"

---

### 6. browser_history.csv
**What it is:** Chrome browser history from suspect's workstation
**Key findings:**
- Searched "how to exfiltrate data undetected" before breach
- Downloaded TOR browser
- Searched how to clear Windows event logs
- Created anonymous ProtonMail account
- Logged into MEGA cloud during exfiltration window
- Searched "how to destroy evidence on computer" after breach

**Good demo questions:**
- "What did the suspect search for before the incident?"
- "Is there evidence of premeditation?"
- "What cloud services were accessed?"

---

## ATTACK TIMELINE

```
21:30 — Suspect researches data exfiltration methods (browser)
21:38 — Downloads TOR browser (browser)
21:45 — Researches how to clear event logs (browser)
21:53 — Creates anonymous ProtonMail account (browser)
23:45 — Researches 7zip encryption (browser)
00:00 — Logs into MEGA cloud storage (browser)
00:02 — VPN login to corporate network (system log)
00:03 — Copies confidential files to hidden folder (system log)
00:04 — Uploads 61MB to TOR exit node (network log)
00:05 — Deletes temp files, attempts log tampering (system log)
00:06 — Searches "can they tell I stole files" (browser)
09:17 — External brute force attack (unrelated actor) (system log)
14:20 — Phishing email delivers AGENT_TESLA RAT (email log)
14:23 — RAT establishes C2 communication (network log)
14:30 — RAT exfiltrates 500MB via MEGA (network log)
```

---

## HOW TO USE IN DEMO

1. Upload all files to the ForensicAI system
2. Ask: **"Give me a complete summary of what happened"**
3. Ask: **"Who is the primary suspect and why?"**
4. Ask: **"What are all the IOCs found across all evidence?"**
5. Ask: **"Is there evidence of premeditation?"**
6. Switch to viewer role and ask: **"Show me GPS location data"** (will be blocked by guardrails)
7. Generate the PDF report

---

*All evidence is fictional and created for educational/demonstration purposes only.*
