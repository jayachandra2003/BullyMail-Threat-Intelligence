import re
import urllib.parse

class DomainDetector:
    """Fake / Look-Alike Domain & Typosquatting Detection Engine"""
    
    # Common Target Brands / Academic Domains to Protect
    PROTECTED_DOMAINS = {
        'paypal.com': 'PayPal',
        'microsoft.com': 'Microsoft',
        'google.com': 'Google',
        'apple.com': 'Apple',
        'amazon.com': 'Amazon',
        'netflix.com': 'Netflix',
        'chase.com': 'Chase Bank',
        'wellsfargo.com': 'Wells Fargo',
        'harvard.edu': 'Harvard University',
        'stanford.edu': 'Stanford University',
        'mit.edu': 'MIT',
        'oxford.ac.uk': 'Oxford University',
        'cambridge.ac.uk': 'Cambridge University'
    }
    
    # Visual homoglyphs / character substitutions (Leetspeak / visual spoofing)
    SUBSTITUTIONS = {
        '0': 'o', '1': 'l', 'i': 'l', 'l': 'i', 'vv': 'w', 'rn': 'm',
        '3': 'e', '5': 's', '8': 'b', '@': 'a', 'v': 'u'
    }

    def extract_domain(self, url_or_domain):
        """Extracts the registered domain or base host from a URL or email address."""
        if not url_or_domain:
            return ""
        if '@' in url_or_domain:
            url_or_domain = url_or_domain.split('@')[-1].strip('>')
        if not url_or_domain.startswith(('http://', 'https://')):
            url_or_domain = 'http://' + url_or_domain
        try:
            parsed = urllib.parse.urlparse(url_or_domain)
            netloc = parsed.netloc.lower()
            return netloc.split(':')[0]
        except:
            return ""

    def normalize_homoglyphs(self, domain):
        """Normalizes common visual character substitutions."""
        norm = domain.lower()
        for k, v in self.SUBSTITUTIONS.items():
            norm = norm.replace(k, v)
        return norm

    def levenshtein_distance(self, s1, s2):
        """Calculates edit distance between two domain strings."""
        if len(s1) < len(s2):
            return self.levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
            
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
            
        return previous_row[-1]

    def check_domain(self, domain_or_url):
        """Checks if a domain is a look-alike or brand spoof."""
        host = self.extract_domain(domain_or_url)
        if not host:
            return {'is_suspicious': False, 'detected_domain': host, 'reason': ''}

        # 1. Exact match with protected brand -> Safe brand domain
        if host in self.PROTECTED_DOMAINS:
            return {'is_suspicious': False, 'detected_domain': host, 'brand': self.PROTECTED_DOMAINS[host], 'reason': 'Legitimate protected domain'}

        # 2. Check for brand name embedded in foreign subdomains or hyphenated domains
        # e.g., 'paypal-security.com' or 'paypal.verification.net'
        for legitimate_domain, brand in self.PROTECTED_DOMAINS.items():
            brand_keyword = legitimate_domain.split('.')[0]
            if brand_keyword in host and not host.endswith('.' + legitimate_domain):
                return {
                    'is_suspicious': True,
                    'detected_domain': host,
                    'impersonated_brand': brand,
                    'technique': 'Brand Embedding / Subdomain Spoofing',
                    'reason': f"Domain '{host}' contains protected brand '{brand}' keyword but does not belong to '{legitimate_domain}'"
                }

        # 3. Check for Character Substitutions / Typosquatting
        # e.g., 'paypa1.com', 'micros0ft.com'
        norm_host = self.normalize_homoglyphs(host)
        for legitimate_domain, brand in self.PROTECTED_DOMAINS.items():
            norm_legit = self.normalize_homoglyphs(legitimate_domain)
            
            # Direct substitution match (e.g. paypa1.com -> paypal.com)
            if norm_host == norm_legit and host != legitimate_domain:
                return {
                    'is_suspicious': True,
                    'detected_domain': host,
                    'impersonated_brand': brand,
                    'technique': 'Character Substitution / Homoglyph',
                    'reason': f"Domain '{host}' uses character substitutions to imitate legitimate brand '{brand}' ({legitimate_domain})"
                }
                
            # Close edit distance on the main label
            host_label = host.split('.')[0]
            legit_label = legitimate_domain.split('.')[0]
            if len(host_label) >= 4 and len(legit_label) >= 4:
                dist = self.levenshtein_distance(host_label, legit_label)
                if dist == 1 and host_label != legit_label:
                    return {
                        'is_suspicious': True,
                        'detected_domain': host,
                        'impersonated_brand': brand,
                        'technique': 'Typosquatting (Edit Distance = 1)',
                        'reason': f"Domain '{host}' closely mimics '{legitimate_domain}' with a 1-character difference"
                    }

        return {
            'is_suspicious': False,
            'detected_domain': host,
            'reason': 'No look-alike or typosquatting patterns detected'
        }
