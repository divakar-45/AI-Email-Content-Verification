import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse

class ContentVerificationEngine:
    def __init__(self):
        # AI/NLP & Rule-based dictionaries for psychological triggers
        self.urgency_keywords = [
            "urgent", "immediate action", "suspended", "within 24 hours", 
            "expire", "alert", "verify your account", "action required", "blocked"
        ]
        self.financial_keywords = [
            "wire transfer", "ifsc", "bank", "kyc", "statement", 
            "credit card", "credentials", "password", "payment"
        ]

    def analyze_content(self, msg) -> dict:
        # Extract body text and HTML
        body_text = ""
        html_content = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                if "attachment" not in content_disposition:
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            decoded_text = payload.decode('utf-8', errors='ignore')
                            if content_type == "text/plain":
                                body_text += decoded_text
                            elif content_type == "text/html":
                                html_content += decoded_text
                    except Exception:
                        pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    decoded_text = payload.decode('utf-8', errors='ignore')
                    if msg.get_content_type() == "text/html":
                        html_content = decoded_text
                    else:
                        body_text = decoded_text
            except Exception:
                body_text = str(msg.get_payload())

        # Combine text for analysis
        full_raw_text = (body_text + " " + html_content).lower()

        # 1. Psychological Urgency Detection Tool
        detected_urgency = [kw for kw in self.urgency_keywords if kw in full_raw_text]
        
        # 2. Financial & Credential Harvesting Trigger Tool
        detected_financial = [kw for kw in self.financial_keywords if kw in full_raw_text]

        # 3. Deceptive Hyperlink & Link Extraction Tool
        suspicious_links = []
        soup = BeautifulSoup(html_content or body_text, "html.parser")
        
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            anchor_text = a_tag.get_text(strip=True)
            parsed_url = urlparse(href)
            netloc = parsed_url.netloc

            is_raw_ip = bool(re.match(r'^\d{1,3}(?:\.\d{1,3}){3}', netloc))
            is_suspicious_extension = netloc.endswith(('.php', '.xyz', '.top', '.zip'))
            
            if is_raw_ip or is_suspicious_extension or not netloc:
                suspicious_links.append({
                    "anchor_text": anchor_text if anchor_text else "No Text / Direct Link",
                    "target_url": href,
                    "reason": "RAW_IP_OR_SUSPICIOUS_EXTENSION" if is_raw_ip else "UNTRUSTED_LANDING_DOMAIN"
                })

        # Calculate Content Risk Score
        content_risk = 0
        if detected_urgency:
            content_risk += 40
        if detected_financial:
            content_risk += 30
        if suspicious_links:
            content_risk += 30

        return {
            "content_risk_score": min(content_risk, 100),
            "detected_urgency": detected_urgency,
            "detected_financial_terms": detected_financial,
            "suspicious_links": suspicious_links,
            "text_preview": (body_text or html_content)[:350] + "..."
        }