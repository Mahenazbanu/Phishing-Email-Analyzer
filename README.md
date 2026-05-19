# 🛡️ Phishing Email Analyzer

**Advanced Python tool to detect phishing indicators in email files (.eml)**  
Analyzes headers, body content, attachments, and URLs – then generates a risk‑scored report (TXT or PDF) with optional SMTP delivery.

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-production%20ready-brightgreen)

---

## ✨ Features

- **Header & Spoofing Analysis** – checks `From`, `Reply-To`, `Return-Path`, DMARC/SPF
- **Content Inspection**  
  - Suspicious/redirected URLs (follows short links)  
  - Urgency keywords (`urgent`, `ASAP`, `deadline`)  
  - Grammar & spelling errors (300+ rules via `language-tool-python`)
- **Attachment Scanning** – detects risky extensions (`.exe`, `.js`, `.vbs`, etc.)
- **Risk Scoring** – weighted algorithm → `Low`, `Medium`, `High`, `Critical`
- **Report Generation**  
  - `phishing_analyzer_text.py` → clean TXT report  
  - `phishing_analyzer_enhanced.py` → professional PDF report + **email delivery** via SMTP
- **Configurable** – `config.yaml` for custom risk weights & trusted domains

---

## 📦 Requirements

- Python **3.8+**
- Dependencies (install with pip):

```bash
pip install pyyaml requests beautifulsoup4 language-tool-python fpdf2
```

Note: phishing_analyzer_enhanced.py also requires fpdf2 (included above).
LanguageTool will download a ~500MB model on first run.

---

🚀 Quick Start

1. Clone the repository

```bash
git clone https://github.com/yourusername/Phishing-Email-Analyzer.git
cd Phishing-Email-Analyzer
```

2. Install dependencies

```bash
pip install -r requirements.txt   # (create one if needed, or use the line above)
```

3. Run analysis on an .eml file

TXT report (basic)

```bash
python phishing_analyzer_text.py sample_email.eml --verbose
```

PDF report with email delivery (enhanced)

```bash
python phishing_analyzer_enhanced.py suspicious.eml --send-to security@example.com
```

---

⚙️ Configuration

Create a config.yaml file in the same directory:

```yaml
analyzer:
  risk_weights:
    spoofing: 5
    suspicious_url: 3
    urgency: 2
    grammar: 1
    attachments: 4
  # add custom trusted domains if needed
```

For the enhanced version, set SMTP environment variables (or hardcode in the script):

```bash
export SMTP_HOST="smtp.office365.com"
export SMTP_PORT="587"
export SMTP_USER="analyzer@company.com"
export SMTP_PASSWORD="your-app-password"
```

Optionally place a company_logo.png in the working directory to appear on PDF reports.

---

📋 Example Report (TXT)

```
=== PHISHING ANALYSIS REPORT ===
Generated on: 2025-02-18 14:32:10
== RISK LEVEL ==
Risk Level: High
== SENDER ANALYSIS ==
- Spoofing suspicion: Reply-To differs from From
- DMARC authentication failed
== SUSPICIOUS LINKS ==
- Shortened URL: http://bit.ly/2xyz → http://malicious-site.com/login
== URGENCY INDICATORS ==
- urgent, immediately, deadline
...
```

---

🧪 Testing

Place a test .eml file in the samples/ directory and run:

```bash
python phishing_analyzer_text.py samples/phish_test.eml
```

For unit tests (if you extend the code):

```bash
pytest tests/
```

---

🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (git checkout -b feature/amazing-feature)
3. Commit your changes (git commit -m 'Add some amazing feature')
4. Push to the branch (git push origin feature/amazing-feature)
5. Open a Pull Request

---

📄 License

Distributed under the MIT License. See LICENSE for more information.

---

📧 Contact

Project Link: https://github.com/Mahenazbanu/Phishing-Email-Analyzer
Maintainer: Mahenazbanu

---

🙏 Acknowledgements

· LanguageTool for grammar checking
· BeautifulSoup for HTML parsing
· fpdf2 for PDF generation
