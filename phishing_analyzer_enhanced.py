"""
Phishing Email Analyzer v2 - Fully Enhanced & Production-Ready
Author: AI Assistant
Date: 2024-06-15
Version: 2.0
License: MIT
"""

import re
import os
import sys
import smtplib
import argparse
import logging
import time
import base64
from email import message_from_string
from email.header import decode_header
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Union
from html import escape
from pathlib import Path

# Optional imports
try:
    from fpdf import FPDF
    import yaml
    import requests
    import language_tool_python
    from bs4 import BeautifulSoup
except ImportError as e:
    print(f"Missing dependency: {e}. Install with:")
    print("pip install fpdf2 pyyaml requests language-tool-python beautifulsoup4")
    sys.exit(1)

# -------------------------------
# 🔧 Configuration Section
# -------------------------------
CONFIG_FILE = "config.yaml"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
TRUSTED_DOMAINS = ["yourcompany.com"]
SUSPICIOUS_EXTENSIONS = {".exe", ".js", ".vbs", ".bat", ".ps1", ".scr"}
LOGO_PATH = os.getenv("LOGO_PATH", "company_logo.png")

class Config:
    def __init__(self):
        """Load SMTP credentials and analyzer settings."""
        self.smtp_host = os.getenv("SMTP_HOST", "")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = os.getenv("SMTP_USER", "")
        self.smtp_pass = os.getenv("SMTP_PASSWORD", "")
        if not all([self.smtp_host, self.smtp_user, self.smtp_pass]):
            logging.warning("Incomplete SMTP configuration. Email sending may fail.")
        try:
            with open(CONFIG_FILE) as f:
                config_data = yaml.safe_load(f)
                if config_data and "analyzer" in config_data:
                    self.__dict__.update(config_data["analyzer"])
        except FileNotFoundError:
            logging.info("No config.yaml file found. Using defaults.")

config = Config()

# -------------------------------
# 📜 Logging Setup
# -------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("phishing_analyzer.log"),
        logging.StreamHandler()
    ]
)

# -------------------------------
# 🧠 Main Analyzer Class
# -------------------------------
class PhishingAnalyzer:
    def __init__(self):
        self.lt_tool = language_tool_python.LanguageTool('en-US')
        self.risk_weights = {
            "spoofing": 5,
            "suspicious_url": 3,
            "urgency": 2,
            "grammar": 1,
            "attachments": 4
        }

    # --- Core Functions ---
    def load_email(self, file_path: str) -> str:
        """Load .eml file with size validation."""
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"{file_path} does not exist.")
        if os.path.getsize(file_path) > MAX_FILE_SIZE:
            raise ValueError(f"File exceeds {MAX_FILE_SIZE // 1024 // 1024}MB limit")
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()

    def parse_email(self, email_text: str) -> Tuple[Dict, object]:
        """Parse headers and body from raw email."""
        msg = message_from_string(email_text)
        return (
            self._extract_headers(msg),
            msg
        )

    def _extract_headers(self, msg) -> Dict:
        """Extract and MIME-decode headers."""
        headers = {}
        for k, v in msg.items():
            headers[k] = self._decode_header(v)
        headers["All-Headers"] = escape(str(msg))
        return headers

    def _decode_header(self, header: str) -> str:
        """Decode MIME-encoded headers."""
        decoded_parts = []
        for part, charset in decode_header(header):
            if isinstance(part, bytes):
                decoded_parts.append(part.decode(charset or 'utf-8', errors='replace'))
            else:
                decoded_parts.append(part)
        return ' '.join(decoded_parts)

    def _extract_body(self, msg) -> str:
        """Extract plain text body safely, including HTML content."""
        body = ""
        for part in msg.walk():
            content_type = part.get_content_type()
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            charset = part.get_content_charset() or 'utf-8'
            decoded = payload.decode(charset, errors='replace')
            if content_type == "text/plain":
                body += decoded + "\n"
            elif content_type == "text/html":
                soup = BeautifulSoup(decoded, "html.parser")
                body += soup.get_text(separator="\n") + "\n"
        return body.strip()

    # --- Full Analysis Wrapper ---
    def full_analysis(self, headers: Dict, msg) -> Dict:
        """Run full phishing analysis on headers and message object."""
        body = self._extract_body(msg)
        sender_findings = self.analyze_sender(headers)
        content_findings = self.analyze_content(body, msg)
        risk_level, risk_details = self.calculate_risk({
            "sender": sender_findings,
            "content": content_findings
        })
        return {
            "sender": sender_findings,
            "content": content_findings,
            "risk": (risk_level, risk_details)
        }

    # --- Analysis Modules ---
    def analyze_sender(self, headers: Dict) -> List[str]:
        """Detect spoofed sender addresses and header inconsistencies."""
        findings = []
        from_addr = self._extract_email(headers.get("From", ""))
        domain = from_addr.split("@")[-1] if "@" in from_addr else ""
        if domain.lower() in TRUSTED_DOMAINS:
            return ["Sender domain is trusted"]

        checks = [
            ("Reply-To", "Reply-To differs from From"),
            ("Return-Path", "Return-Path mismatch"),
        ]

        for header, message in checks:
            target_email = self._extract_email(headers.get(header, ""))
            if target_email != from_addr:
                findings.append(f"Spoofing suspicion: {message}")

        auth_results = headers.get("Authentication-Results", "").lower()
        if "dmarc=fail" in auth_results:
            findings.append("DMARC authentication failed")
        if "spf=fail" in auth_results:
            findings.append("SPF validation failed")

        return findings

    def _extract_email(self, header: str) -> str:
        """Extract clean email address from header string."""
        match = re.search(r'<([^>]+)>', header)
        if match:
            return match.group(1).strip().lower()
        return header.strip().lower()

    def analyze_content(self, body: str, msg) -> Dict[str, List[str]]:
        """Run comprehensive content analysis."""
        return {
            "links": self._find_suspicious_links(body),
            "attachments": self._check_attachments(msg),
            "urgency": self._detect_urgency(body),
            "grammar": self._check_grammar(body)
        }

    def _find_suspicious_links(self, body: str) -> List[str]:
        """Find and resolve shortened URLs."""
        urls = re.findall(r'https?://\S+', body)
        findings = []
        headers = {'User-Agent': 'Mozilla/5.0'}

        for url in urls:
            try:
                resolved = requests.head(url, timeout=5, allow_redirects=True, headers=headers).url
            except Exception as e:
                logging.debug(f"URL resolution failed: {e}")
                resolved = url

            if resolved != url:
                findings.append(f"Shortened URL: {url} → {resolved}")
            elif re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
                findings.append(f"IP Address URL: {url}")
            elif any(url.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
                findings.append(f"Executable download link: {url}")

        return findings

    def _check_attachments(self, msg) -> List[str]:
        """Analyze email attachments for suspicious extensions."""
        findings = []
        for part in msg.walk():
            filename = part.get_filename()
            if filename:
                decoded = self._decode_header(filename)
                ext = os.path.splitext(decoded)[1].lower()
                if ext in SUSPICIOUS_EXTENSIONS:
                    findings.append(f"Suspicious attachment: {decoded}")
        return findings

    def _detect_urgency(self, body: str) -> List[str]:
        """Detect urgency-inducing language."""
        urgency_keywords = [
            r'\b(urgent|immediately|asap|critical|important|action required)\b',
            r'\b(must|need to|required|deadline|today|now)\b'
        ]
        findings = []
        for pattern in urgency_keywords:
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                findings.extend(matches)
        return findings

    def _check_grammar(self, body: str) -> List[str]:
        """Check grammar and spelling errors."""
        if not body.strip():
            return []
        matches = self.lt_tool.check(body)
        return [str(match) for match in matches[:10]]

    # --- Risk Assessment ---
    def calculate_risk(self, findings: Dict) -> Tuple[str, List[str]]:
        """Calculate weighted risk score based on findings."""
        score = 0
        details = []

        if any("spoofing" in f.lower() for f in findings["sender"]):
            score += self.risk_weights["spoofing"]
            details.append("Sender spoofing detected")

        if len(findings["content"]["links"]) > 0:
            score += self.risk_weights["suspicious_url"] * len(findings["content"]["links"])
            details.append(f"{len(findings['content']['links'])} suspicious links found")

        if len(findings["content"]["urgency"]) > 0:
            score += self.risk_weights["urgency"] * len(set(findings["content"]["urgency"]))
            details.append(f"{len(set(findings['content']['urgency']))} urgency indicators found")

        if len(findings["content"]["grammar"]) > 3:
            score += self.risk_weights["grammar"] * len(findings["content"]["grammar"])
            details.append(f"{len(findings['content']['grammar'])} grammar/spelling errors found")

        if len(findings["content"]["attachments"]) > 0:
            score += self.risk_weights["attachments"] * len(findings["content"]["attachments"])
            details.append(f"{len(findings['content']['attachments'])} suspicious attachments found")

        return self._risk_level(score), details

    def _risk_level(self, score: int) -> str:
        """Map numeric score to risk category."""
        if score >= 15:
            return "Critical"
        elif score >= 10:
            return "High"
        elif score >= 5:
            return "Medium"
        return "Low"

    # --- Report Generation ---
    class ReportPDF(FPDF):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.font_path = Path("DejaVuSans.ttf")
            if self.font_path.exists():
                self.add_font('DejaVu', '', str(self.font_path), uni=True)
                self.set_font('DejaVu', '', 10)
            else:
                logging.warning(f"Font file '{self.font_path}' not found. Using default font.")
                self.set_font("Arial")

        def header(self):
            if os.path.exists(LOGO_PATH):
                self.image(LOGO_PATH, x=10, y=8, w=30)
            self.set_font('Arial', 'B', 14)
            self.cell(0, 10, 'Phishing Analysis Report', ln=1, align='C')

        def add_findings(self, title: str, items: List[str]):
            """Add findings section to PDF."""
            if not items:
                return
            self.set_font('Arial', 'B', 12)
            self.cell(0, 10, title, ln=1)
            self.set_font('Arial', '', 10)
            for item in items:
                self.cell(0, 5, f"• {item}", ln=1)
            self.ln(5)

    def generate_report(self, findings: Dict) -> str:
        """Generate PDF report from findings."""
        pdf = self.ReportPDF()
        pdf.add_page()
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(0, 10, "Analysis Summary", ln=1)
        pdf.set_font("Arial", '', 10)
        pdf.cell(0, 5, f"Risk Level: {findings['risk'][0]}", ln=1)
        pdf.ln(5)

        pdf.add_findings("Sender Analysis", findings["sender"])
        pdf.add_findings("Suspicious Links", findings["content"]["links"])
        pdf.add_findings("Urgency Indicators", findings["content"]["urgency"])
        pdf.add_findings("Grammar Issues", findings["content"]["grammar"])
        pdf.add_findings("Suspicious Attachments", findings["content"]["attachments"])
        pdf.add_findings("Risk Factors", findings["risk"][1])

        report_path = f"phishing_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        pdf.output(report_path)
        logging.info(f"Report generated: {report_path}")
        return report_path

    # --- Email Sending ---
    def send_report(self, pdf_path: str, recipient: str):
        """Send report via SMTP with retry logic."""
        if not all([config.smtp_host, config.smtp_user, config.smtp_pass]):
            logging.error("SMTP credentials missing. Cannot send email.")
            return

        from_addr = config.smtp_user
        subject = "Phishing Analysis Report"

        try:
            with open(pdf_path, "rb") as f:
                pdf_data = f.read()
        except Exception as e:
            logging.error(f"Failed to read PDF: {e}")
            return

        boundary = "PhishingAnalysisReportBoundary"
        msg = f"""From: {from_addr}
To: {recipient}
Subject: {subject}
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="{boundary}"

--{boundary}
Content-Type: text/plain; charset="us-ascii"
Content-Transfer-Encoding: 7bit

Phishing Analysis Report attached.
--{boundary}
Content-Type: application/pdf; name="{os.path.basename(pdf_path)}"
Content-Transfer-Encoding: base64
Content-Disposition: attachment

{base64.b64encode(pdf_data).decode('utf-8')}
--{boundary}--
"""

        max_retries = 3
        for attempt in range(max_retries):
            try:
                with smtplib.SMTP(config.smtp_host, config.smtp_port) as server:
                    server.starttls()
                    server.login(config.smtp_user, config.smtp_pass)
                    server.sendmail(from_addr, recipient, msg)
                    logging.info(f"Report sent to {recipient}")
                    return
            except smtplib.SMTPException as e:
                if attempt == max_retries - 1:
                    logging.error(f"Failed to send email: {e}")
                else:
                    logging.warning(f"SMTP error: {e}, retrying...")
                    time.sleep(2 ** attempt)

# -------------------------------
# 🚀 Main Execution
# -------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enhanced Phishing Analyzer v3")
    parser.add_argument("file", help="Path to .eml file")
    parser.add_argument("--send-to", help="Email for report delivery")
    parser.add_argument("--verbose", action="store_true", help="Show debug details")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    analyzer = PhishingAnalyzer()
    try:
        email_content = analyzer.load_email(args.file)
        headers, msg = analyzer.parse_email(email_content)
        findings = analyzer.full_analysis(headers, msg)
        report_path = analyzer.generate_report(findings)
        if args.send_to:
            analyzer.send_report(report_path, args.send_to)
    except Exception as e:
        logging.error(f"Analysis failed: {e}")
        sys.exit(1)
