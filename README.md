# PhishGuard SOC // Automated Phishing Intelligence & Threat Analysis Platform

An end-to-end cybersecurity platform designed for real-time automated email threat detection, static MIME inspection, and SOC incident reporting. PhishGuard intercepts emails via **IMAP IDLE** and an embedded **SMTP Gateway (Port 2525)**, performing multi-vector heuristic analysis mapped directly to the **MITRE ATT&CK Enterprise Matrix** and **OWASP Top 10**.

---

## Key Features

- **Real-Time Live Mailbox Ingestion (IMAP IDLE):** Automatically receives push notifications from Gmail, Outlook/Office 365, Yahoo, or custom IMAP servers with zero polling delay.
- **Embedded SMTP Gateway (Port 2525):** Network-level email sinkhole and middleware for raw transmission interception and envelope metadata extraction.
- **Multi-Vector Threat Detection Engine:**
  - **Header & Auth Verification:** Automated SPF, DKIM, and DMARC alignment validation, `Reply-To` mismatch detection, and root DNS MX record verification.
  - **Direct Malware Dropper Inspection:** Scans URL pathnames for executable payloads (`.exe`, `.scr`, `.bat`, `.vbs`, `.msi`, `.ps1`, `.iso`, `.docm`).
  - **URL & Link Security:** Detects visual anchor-text vs. `href` mismatches, suspicious TLDs (`.xyz`, `.top`, `.tk`), raw IP hostnames, and brand typosquatting.
  - **Attachment Scanner:** Flags dangerous scripts, macro-enabled documents, and deceptive double-extension files (`.pdf.exe`).
  - **Origin Attribution:** Traces `Received:` header hops to extract originating sender IP, Geolocation (Country, City), ISP, and Autonomous System Number (ASN).
  - **NLP Social Engineering Heuristics:** Flags urgency, credential harvesting patterns, and wire fraud/BEC keywords.
- **Threat Intelligence Integration:** Direct integration with the **VirusTotal v3 REST API** for live domain and reputation lookups.
- **Framework Mapping:** Standardizes all findings against:
  - **MITRE ATT&CK:** `T1566` (Phishing), `T1204` (User Execution), `T1036` (Masquerading).
  - **OWASP Top 10:** `A07:2021` (Identification & Auth Failures), `A03:2021` (Injection).
- **Interactive SOC Dashboard:** Dark-mode cyber UI with real-time Server-Sent Events (SSE), animated threat gauges (0–100), deep-dive tabs, and printable SOC Incident Reports.

---

## Tech Stack

- **Backend:** Node.js, Express.js
- **Protocols & Ingestion:** `imapflow` (IMAP IDLE / TLS 1.3), `smtp-server` (SMTP RFC 5321), `mailparser` (RFC 822 / 5322 MIME), `multer`
- **Threat Intel & APIs:** VirusTotal v3 REST API, Public DNS Resolver (`dns.promises`), IP Geolocation
- **Streaming:** Server-Sent Events (SSE)
- **Frontend:** Vanilla JavaScript (ES6+), Custom Glassmorphism Cyber Theme, Lucide Icons

---

## Getting Started

### 1. Prerequisites
- **Node.js** (v18 or higher)
- **npm** (v9 or higher)

### 2. Installation & Setup
```bash
# Clone the repository
git clone <YOUR_REPO_URL>
cd DetectionPhishEmail

# Install dependencies
npm install

# (Optional) Set VirusTotal API Key in your environment
export VIRUSTOTAL_API_KEY="your_api_key_here"  # Linux / macOS
$env:VIRUSTOTAL_API_KEY="your_api_key_here"    # Windows PowerShell
```

### 3. Run the Platform
```bash
npm start
```
* **Web Threat Dashboard:** [http://localhost:3000](http://localhost:3000)
* **SMTP Receiver Gateway:** Port `2525`

---

## Testing & Simulation

Run the built-in automated test suite to inject 5 realistic attack scenarios into the SMTP gateway:
```bash
node test_phish.js
```

| Scenario | Attack Vector Tested | Detected Technique |
| :--- | :--- | :--- |
| **1. Microsoft Credential Harvester** | Mismatched Links + Fake Password Expiry | `T1566.002` Spearphishing Link |
| **2. CEO Impersonation (BEC)** | Display Name Spoofing & Gift Card Fraud | `T1036.004` Masquerade Name |
| **3. Malicious Invoice** | Double-Extension Executable Attachment | `T1566.001` Spearphishing Attachment |
| **4. GitHub Security Alert** | Clean Benign Verification Baseline | Score: 0 (Safe) |
| **5. Direct Malware Dropper** | Executable Payload Link (`Ldrdubl2132.exe`) | `T1204.001` User Execution: Malicious Link |

---

## Security & Architecture Considerations

- **In-Memory Buffer Processing:** Untrusted email payloads and attachments are parsed ephemerally in RAM (`multer.memoryStorage()`) without writing malware binaries to disk.
- **XSS Sanitization:** All untrusted headers and email bodies are entity-escaped (`escapeHtml`) before DOM insertion.
- **Least Privilege:** Rejects master Google/Outlook account passwords in favor of scoped 16-character App Passwords.
- **SSRF Prevention:** Local network ranges (RFC 1918) are filtered before external geolocation queries.

---

## License
MIT License. Strictly for defensive cybersecurity research and authorized educational analysis.
