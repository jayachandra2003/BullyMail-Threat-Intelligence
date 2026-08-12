class ExplainableAI:
    """Explainable AI (XAI) & Threat Evidence Generation Service"""

    @staticmethod
    def generate_explanation(detector_results):
        """Synthesizes human-interpretable evidence across all specialized threat detectors."""
        evidence_list = []
        
        # 1. Cyberbullying Evidence
        bullying = detector_results.get('bullying_analysis', {})
        if bullying.get('is_bullying'):
            matches = bullying.get('rule_based_matches', [])
            matched_cats = bullying.get('matched_categories', [])
            b_severity = bullying.get('severity', 'MEDIUM')
            
            # Map clean, professional category title
            if any('Violence' in c or 'Threat' in c for c in matched_cats) or b_severity == 'CRITICAL':
                title = 'Physical Harm or Intimidation Threat Detected'
                detail_prefix = 'Threat of violence or intimidation'
            elif any('Severe' in c for c in matched_cats) or b_severity == 'HIGH':
                title = 'Severe Abusive Language or Targeted Harassment'
                detail_prefix = 'Matched hostile expressions'
            elif any('Insult' in c or 'Demeaning' in c or 'Attack' in c for c in matched_cats):
                title = 'Targeted Personal Insult Detected'
                detail_prefix = 'Direct personal insult detected'
            elif any('Academic' in c for c in matched_cats):
                title = 'Academic Harassment & Undermining'
                detail_prefix = 'Academic invalidation detected'
            else:
                title = 'Abusive or Hostile Language Detected'
                detail_prefix = 'Matched hostile expressions'
                
            if matches:
                evidence_list.append({
                    'category': 'Cyberbullying',
                    'severity': b_severity,
                    'title': title,
                    'details': f"{detail_prefix}: {', '.join([repr(m) for m in matches[:4]])}"
                })
            else:
                top_words = bullying.get('top_features', [])
                word_str = ', '.join([w['word'] for w in top_words]) if top_words else ''
                evidence_list.append({
                    'category': 'Cyberbullying',
                    'severity': b_severity,
                    'title': 'Machine Learning Bullying Pattern Match',
                    'details': f"Text classification matched bullying semantics with {int(bullying.get('confidence', 0) * 100)}% confidence" + (f" (Influential terms: {word_str})" if word_str else "")
                })

        # 2. Phishing Evidence
        phishing = detector_results.get('phishing_analysis', {})
        if phishing.get('risk_level') in ('MEDIUM', 'HIGH', 'CRITICAL'):
            for indicator in phishing.get('indicators', []):
                evidence_list.append({
                    'category': 'Phishing',
                    'severity': indicator.get('severity', 'MEDIUM'),
                    'title': indicator.get('title', 'Phishing Indicator'),
                    'details': indicator.get('description', '')
                })

        # 3. URL / Link Security Evidence
        url_analysis = detector_results.get('url_analysis', {})
        for url_item in url_analysis.get('urls', []):
            if url_item.get('risk_level') in ('SUSPICIOUS', 'HIGH_RISK', 'MALICIOUS'):
                evidence_list.append({
                    'category': 'Link Security',
                    'severity': 'HIGH' if url_item.get('risk_level') in ('HIGH_RISK', 'MALICIOUS') else 'MEDIUM',
                    'title': f"Suspicious URL: {url_item.get('display_url', url_item.get('url'))}",
                    'details': f"Classification: {url_item.get('risk_level')} — {'; '.join(url_item.get('reasons', []))}"
                })

        # 4. Look-Alike / Domain Impersonation Evidence
        domain_analysis = detector_results.get('domain_analysis', {})
        if domain_analysis.get('is_suspicious'):
            evidence_list.append({
                'category': 'Domain Impersonation',
                'severity': 'HIGH',
                'title': f"Potential Look-Alike Domain: {domain_analysis.get('detected_domain')}",
                'details': domain_analysis.get('reason', 'Domain resembles a trusted entity or brand.')
            })

        # 5. Social Engineering Evidence
        social = detector_results.get('social_eng_analysis', {})
        if social.get('risk_level') in ('MEDIUM', 'HIGH', 'CRITICAL'):
            for tech in social.get('techniques', []):
                evidence_list.append({
                    'category': 'Social Engineering',
                    'severity': tech.get('severity', 'MEDIUM'),
                    'title': f"Psychological Vector: {tech.get('name')}",
                    'details': f"Trigger phrases: {', '.join([repr(p) for p in tech.get('evidence', [])[:3]])}"
                })

        # 6. Attachment / Malware Evidence
        malware = detector_results.get('malware_analysis', {})
        for att in malware.get('attachments', []):
            if att.get('risk_level') in ('SUSPICIOUS', 'HIGH_RISK', 'MALICIOUS'):
                evidence_list.append({
                    'category': 'Attachment Security',
                    'severity': 'CRITICAL' if att.get('risk_level') in ('HIGH_RISK', 'MALICIOUS') else 'MEDIUM',
                    'title': f"Risky File: {att.get('filename')}",
                    'details': f"Findings: {'; '.join(att.get('reasons', []))}"
                })

        # 7. Image Forensics Evidence
        img_analysis = detector_results.get('image_analysis', {})
        for img in img_analysis.get('images', []):
            if img.get('risk_level') in ('MEDIUM', 'HIGH'):
                evidence_list.append({
                    'category': 'Image Forensics',
                    'severity': img.get('risk_level'),
                    'title': f"Image Integrity Concern: {img.get('filename')}",
                    'details': f"Forensic findings: {'; '.join(img.get('findings', []))}"
                })

        return evidence_list
