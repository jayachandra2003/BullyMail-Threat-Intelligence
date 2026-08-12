import re
import urllib.parse

class URLAnalyzer:
    """Safe Static URL & Link Security Analysis Engine (No Network Calls)"""
    
    # URL extraction regex
    URL_REGEX = re.compile(
        r'(https?://[^\s<>"\')]+|www\.[^\s<>"\')]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s<>"\')]*)?)',
        re.IGNORECASE
    )
    
    # Known shortening services (Categorized as SUSPICIOUS, NOT automatically malicious)
    SHORTENER_DOMAINS = {
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
        'adf.ly', 'bit.do', 'cutt.ly', 'rb.gy', 'shorturl.at', 'tiny.cc', 'bl.ink'
    }
    
    # Suspicious or high-risk top-level domains commonly abused in spam/phishing
    RISKY_TLDS = {
        '.xyz', '.top', '.work', '.click', '.loan', '.fit', '.gq', '.cf',
        '.tk', '.ml', '.ga', '.surf', '.rest', '.download', '.racing', '.stream'
    }
    
    # Suspicious path segments often linked to credential harvesting
    CREDENTIAL_PATHS = [
        'login', 'signin', 'auth', 'verify', 'update', 'account', 'secure',
        'validation', 'banking', 'portal', 'reset', 'password', 'webmail'
    ]
    
    # Non-standard or unusual ports
    SUSPICIOUS_PORTS = {8080, 8443, 8000, 8888, 1337, 3128, 4444, 9999}

    def extract_urls(self, text):
        """Extracts all valid URLs and potential web links from text."""
        if not text or not isinstance(text, str):
            return []
            
        candidates = self.URL_REGEX.findall(text)
        cleaned_urls = []
        
        for cand in candidates:
            cand = cand.strip().rstrip('.,;:!?)')
            # Filter out email addresses
            if '@' in cand and not cand.startswith(('http://', 'https://')):
                continue
            # Ensure it looks like a domain or URL
            if '.' in cand and len(cand) > 3:
                if not cand.startswith(('http://', 'https://')):
                    cand = 'http://' + cand
                if cand not in cleaned_urls:
                    cleaned_urls.append(cand)
                    
        return cleaned_urls

    def analyze_url(self, raw_url):
        """Performs safe static inspection of an individual URL."""
        reasons = []
        risk_score = 0.0
        
        try:
            parsed = urllib.parse.urlparse(raw_url)
            netloc = parsed.netloc.lower()
            path = parsed.path.lower()
            query = parsed.query.lower()
            scheme = parsed.scheme.lower()
            
            # Extract port if specified
            host = netloc
            port = None
            if ':' in netloc:
                parts = netloc.split(':')
                host = parts[0]
                try:
                    port = int(parts[1])
                except ValueError:
                    pass

            # 1. IP-Address Hostname Check
            is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host))
            if is_ip:
                reasons.append("Host is a direct raw IP address instead of a domain name")
                risk_score += 0.50

            # 2. URL Shortener Detection (Marked as SUSPICIOUS)
            is_shortened = any(host == s or host.endswith('.' + s) for s in self.SHORTENER_DOMAINS)
            if is_shortened:
                reasons.append("URL uses a shortening service that obscures destination")
                risk_score += 0.35

            # 3. Excessive Subdomains Check
            domain_parts = host.split('.')
            if len(domain_parts) >= 4 and not is_ip:
                reasons.append(f"Excessive subdomain depth ({len(domain_parts)} levels), possible impersonation nesting")
                risk_score += 0.30

            # 4. Punycode / Internationalized Domain Name (Homoglyphs)
            if host.startswith('xn--') or '.xn--' in host:
                reasons.append("Punycode (xn--) encoding detected — potential homoglyph deception")
                risk_score += 0.55

            # 5. Suspicious TLD Check
            for tld in self.RISKY_TLDS:
                if host.endswith(tld):
                    reasons.append(f"Uses high-abuse top-level domain ({tld})")
                    risk_score += 0.25
                    break

            # 6. Sensitive / Login Path Inspection
            matched_paths = [p for p in self.CREDENTIAL_PATHS if p in path or p in query]
            if matched_paths:
                reasons.append(f"Contains authentication/credential target path keyword(s): {', '.join(matched_paths)}")
                risk_score += 0.20

            # 7. Non-standard Port
            if port and port in self.SUSPICIOUS_PORTS:
                reasons.append(f"Uses non-standard web port ({port})")
                risk_score += 0.30

            # 8. Excessive URL Encoding / Obfuscation
            if raw_url.count('%') > 3:
                reasons.append("Contains excessive hex/URL encoding (%xx), indicating possible obfuscation")
                risk_score += 0.30

            # 9. HTTP vs HTTPS Assessment
            if scheme == 'http' and (is_ip or matched_paths or is_shortened):
                reasons.append("Insecure HTTP protocol used on sensitive/shortened target")
                risk_score += 0.15

        except Exception as e:
            reasons.append(f"Malformed URL structure ({str(e)})")
            risk_score += 0.25

        # Determine Classification
        if risk_score >= 0.70:
            risk_level = 'HIGH_RISK'
        elif risk_score >= 0.30:
            risk_level = 'SUSPICIOUS'
        else:
            risk_level = 'SAFE'
            
        if not reasons:
            reasons.append("Standard domain structure and protocol verified; no obvious static threat markers.")

        return {
            'url': raw_url,
            'display_url': raw_url if len(raw_url) <= 60 else raw_url[:57] + '...',
            'risk_level': risk_level,
            'threat_score': round(min(risk_score, 1.0), 3),
            'is_shortened': is_shortened if 'is_shortened' in locals() else False,
            'is_ip': is_ip if 'is_ip' in locals() else False,
            'reasons': reasons
        }

    def analyze_all(self, text):
        """Extracts and analyzes all URLs from email body text."""
        extracted_urls = self.extract_urls(text)
        results = [self.analyze_url(u) for u in extracted_urls]
        
        suspicious_count = sum(1 for r in results if r['risk_level'] in ('SUSPICIOUS', 'HIGH_RISK', 'MALICIOUS'))
        high_risk_count = sum(1 for r in results if r['risk_level'] in ('HIGH_RISK', 'MALICIOUS'))
        
        if high_risk_count > 0:
            overall_url_risk = 'HIGH_RISK'
        elif suspicious_count > 0:
            overall_url_risk = 'SUSPICIOUS'
        else:
            overall_url_risk = 'SAFE'
            
        return {
            'total_urls': len(results),
            'suspicious_count': suspicious_count,
            'high_risk_count': high_risk_count,
            'overall_risk': overall_url_risk,
            'urls': results
        }
