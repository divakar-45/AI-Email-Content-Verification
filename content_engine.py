import re
from html.parser import HTMLParser

class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.current_href = None
        self.current_text = ""
        self.in_anchor = False

    def handle_starttag(self, tag, attrs):
        if tag.lower() == 'a':
            self.in_anchor = True
            for attr, value in attrs:
                if attr.lower() == 'href':
                    self.current_href = value

    def handle_data(self, data):
        if self.in_anchor:
            self.current_text += data

    def handle_endtag(self, tag):
        if tag.lower() == 'a':
            self.in_anchor = False
            self.links.append({"href": self.current_href or "", "text": self.current_text.strip()})
            self.current_href = None
            self.current_text = ""

class ContentVerificationEngine:
    def __init__(self):
        self.urgency_keywords = [
            "urgent", "immediate action", "suspend", "kyc", "verify now", 
            "account blocked", "expires today", "confirm your identity"
        ]
        self.financial_keywords = [
            "wire transfer", "bank details", "account number", "ifsc", 
            "upi id", "remittance", "invoice payment", "swift code"
        ]

    def analyze_content(self, msg) -> dict:
        body_text = ""
        html_content = ""

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
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
                    text = payload.decode('utf-8', errors='ignore')
                    if "<html" in text.lower() or "<a href" in text.lower():
                        html_content = text
                    else:
                        body_text = text
            except Exception:
                pass

        # 1. Parse Links & Check for IP-based or Mismatched Links
        suspicious_links = []
        if html_content:
            parser = LinkParser()
            parser.feed(html_content)
            for link in parser.links:
                href = link["href"]
                text = link["text"]
                
                # Check if href points directly to a raw IP instead of domain name
                if re.search(r'//[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', href):
                    suspicious_links.append({
                        "display_text": text if text else "[Image/Button Link]",
                        "destination_href": href,
                        "issue": "RAW_IP_DESTINATION_DETECTED"
                    })

        # 2. Keyword Scans for Psychological Urgency and Financial Wire Fraud
        full_corpus = (body_text + " " + html_content).lower()
        detected_urgency = [kw for kw in self.urgency_keywords if kw in full_corpus]
        detected_financial = [kw for kw in self.financial_keywords if kw in full_corpus]

        # 3. Content Risk Calculation
        content_risk_score = 0
        if detected_urgency:
            content_risk_score += 25
        if detected_financial:
            content_risk_score += 25
        if suspicious_links:
            content_risk_score += 40

        return {
            "content_risk_score": min(content_risk_score, 100),
            "detected_urgency": detected_urgency,
            "detected_financial_terms": detected_financial,
            "suspicious_links": suspicious_links,
            "text_preview": (body_text.strip() or html_content[:400])[:300] + "..."
        }