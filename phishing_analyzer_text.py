"""
Phishing Email Analyzer v1 - Text Report Only
Author: AI Assistant
Date: 2024-06-15
Version: 1.0
License: MIT
"""

import re
import os
import sys
import argparse
import logging
import time
from email import message_from_string
from email.header import decode_header
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Union
from html import escape
from pathlib import Path
from email.utils import parseaddr

# Attempt to import optional dependencies with detailed error messages
try:
    import yaml
except ImportError as e:
    print(f"Missing dependency: {e}. Install with:")
    print("pip install pyyaml==6.0")
    sys.exit(1)

try:
    import requests
except ImportError as e:
    print(f"Missing dependency: {e}. Install with:")
    print("pip install requests==2.31.0")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
except ImportError as e:
    print(f"Missing dependency: {e}. Install with:")
    print("pip install beautifulsoup4==4.12.3")
    sys.exit(1)

try:
    import language_tool_python
except ImportError as e:
    print(f"Missing dependency: {e}. Install with:")
    print("pip install language-tool-python==2.22")
    sys.exit(1)

# -------------------------------
# 🔧 Configuration Section
# -------------------------------
CONFIG_FILE = "config.yaml"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
TRUSTED_DOMAINS = ["yourcompany.com"]
SUSPICIOUS_EXTENSIONS = {".exe", ".js", ".vbs", ".bat", ".ps1", ".scr"}

class Config:
    def __init__(self):
        """Load analyzer settings."""
        self.risk_weights = {
            "spoofing": 5,
            "suspicious_url": 3,
            "urgency": 2,
            "grammar": 1,
            "attachments": 4
        }
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
        self.risk_weights = config.risk_weights

    # --- Core Functions ---
    def load_email(self, file_path: str) -> str:
        """Load .eml file with size validation."""
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"{file_path} does not exist.")
        if os.path.getsize(file_path) > MAX_FILE_SIZE:
            raise ValueError(f"File exceeds {MAX_FILE_SIZE // 1024 // 1024}MB limit")
        with open(file_path, 'r', encoding='utf-8') as f:
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
        _, email = parseaddr(header)
        return email.strip().lower()

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
            resolved = url  # Default value
            try:
                response = requests.head(url, timeout=5, allow_redirects=True, headers=headers)
                resolved = response.url
            except Exception as e:
                logging.debug(f"HEAD request failed: {e}, falling back to GET...")
                try:
                    response = requests.get(url, timeout=5, allow_redirects=True, headers=headers)
                    resolved = response.url
                except Exception as e:
                    logging.warning(f"URL resolution failed: {e}")
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
                for match in matches:
                    findings.append(match if isinstance(match, str) else match[0])
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

        link_count = len(findings["content"]["links"])
        if link_count > 0:
            score += self.risk_weights["suspicious_url"] * link_count
            details.append(f"{link_count} suspicious links found")

        urgency_count = len(set(findings["content"]["urgency"]))
        if urgency_count > 0:
            score += self.risk_weights["urgency"] * urgency_count
            details.append(f"{urgency_count} urgency indicators found")

        grammar_count = len(findings["content"]["grammar"])
        if grammar_count > 3:
            score += self.risk_weights["grammar"] * grammar_count
            details.append(f"{grammar_count} grammar/spelling errors found")

        attach_count = len(findings["content"]["attachments"])
        if attach_count > 0:
            score += self.risk_weights["attachments"] * attach_count
            details.append(f"{attach_count} suspicious attachments found")

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

    # --- TXT Report Generation ---
    def generate_txt_report(self, findings: Dict) -> str:
        """Generate structured .txt report."""
        report_path = f"phishing_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("=== PHISHING ANALYSIS REPORT ===\n")
            f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("== RISK LEVEL ==\n")
            f.write(f"Risk Level: {findings['risk'][0]}\n")
            f.write("== SENDER ANALYSIS ==\n")
            if findings["sender"]:
                for item in findings["sender"]:
                    f.write(f"- {item}\n")
            else:
                f.write("- No issues found.\n\n")
            f.write("== SUSPICIOUS LINKS ==\n")
            if findings["content"]["links"]:
                for item in findings["content"]["links"]:
                    f.write(f"- {item}\n")
            else:
                f.write("- No suspicious links found.\n\n")
            f.write("== URGENCY INDICATORS ==\n")
            if findings["content"]["urgency"]:
                for item in findings["content"]["urgency"]:
                    f.write(f"- {item}\n")
            else:
                f.write("- No urgency indicators found.\n\n")
            f.write("== GRAMMAR & SPELLING ISSUES ==\n")
            if findings["content"]["grammar"]:
                for item in findings["content"]["grammar"]:
                    f.write(f"- {item}\n")
            else:
                f.write("- No grammar issues found.\n\n")
            f.write("== SUSPICIOUS ATTACHMENTS ==\n")
            if findings["content"]["attachments"]:
                for item in findings["content"]["attachments"]:
                    f.write(f"- {item}\n")
            else:
                f.write("- No suspicious attachments found.\n\n")
            f.write("== RISK FACTORS ==\n")
            for item in findings["risk"][1]:
                f.write(f"- {item}\n")
        logging.info(f"TXT report generated: {report_path}")
        return report_path

# -------------------------------
# 🚀 Main Execution
# -------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enhanced Phishing Analyzer v3 - TXT Output Only")
    parser.add_argument("file", help="Path to .eml file")
    parser.add_argument("--verbose", action="store_true", help="Show debug details")
    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    analyzer = PhishingAnalyzer()
    try:
        email_content = analyzer.load_email(args.file)
        headers, msg = analyzer.parse_email(email_content)
        findings = analyzer.full_analysis(headers, msg)
        report_path = analyzer.generate_txt_report(findings)
    except Exception as e:
        logging.error(f"Analysis failed: {e}")
        sys.exit(1)
