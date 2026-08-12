import json
from datetime import datetime
from ..database.connection import fetch_one, fetch_all, execute_query

class AnalysisModel:
    """Data Access Object for Multi-Vector Email Threat Analyses"""
    
    @staticmethod
    def save_analysis(report_data):
        """Saves a unified threat analysis report to the database."""
        evidence_json = json.dumps(report_data.get('evidence', []))
        url_summary_json = json.dumps(report_data.get('url_analysis', {}).get('urls', []))
        domain_summary_json = json.dumps(report_data.get('domain_analysis', {}))
        attachment_summary_json = json.dumps(report_data.get('malware_analysis', {}).get('attachments', []))
        image_summary_json = json.dumps(report_data.get('image_analysis', {}).get('images', []))
        phishing_indicators_json = json.dumps(report_data.get('phishing_analysis', {}).get('indicators', []))
        social_techniques_json = json.dumps(report_data.get('social_eng_analysis', {}).get('techniques', []))
        bullying_matches_str = ', '.join(report_data.get('bullying_analysis', {}).get('rule_based_matches', []))
        
        query = '''
            INSERT INTO analyzed_emails (
                email_subject, email_from, email_to, email_text,
                overall_risk_level, overall_confidence, threat_score,
                is_bullying, confidence, rule_based_matches, rule_based_score,
                ml_prediction, ml_confidence, model_used,
                phishing_risk_level, phishing_confidence, phishing_indicators,
                urls_detected, suspicious_urls_count, url_analysis_summary,
                domain_analysis_summary,
                social_eng_risk_level, social_eng_confidence, social_eng_techniques,
                attachments_count, malware_risk_level, attachment_analysis_summary,
                images_count, image_risk_level, image_analysis_summary,
                evidence_summary, email_date
            ) VALUES (
                %s, %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s,
                %s,
                %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s,
                %s, %s
            )
        '''
        
        params = (
            report_data.get('email_subject', 'No Subject'),
            report_data.get('email_from', 'Unknown'),
            report_data.get('email_to', ''),
            report_data.get('email_text', ''),
            report_data.get('overall_risk_level', 'LOW'),
            report_data.get('overall_confidence', 0.0),
            report_data.get('threat_score', 0.0),
            
            1 if report_data.get('bullying_analysis', {}).get('is_bullying') else 0,
            report_data.get('bullying_analysis', {}).get('confidence', 0.0),
            bullying_matches_str,
            report_data.get('bullying_analysis', {}).get('rule_based_score', 0.0),
            1 if report_data.get('bullying_analysis', {}).get('ml_prediction') else 0,
            report_data.get('bullying_analysis', {}).get('ml_confidence', 0.0),
            report_data.get('bullying_analysis', {}).get('model_used', 'Hybrid'),
            
            report_data.get('phishing_analysis', {}).get('risk_level', 'LOW'),
            report_data.get('phishing_analysis', {}).get('confidence', 0.0),
            phishing_indicators_json,
            
            report_data.get('url_analysis', {}).get('total_urls', 0),
            report_data.get('url_analysis', {}).get('suspicious_count', 0),
            url_summary_json,
            
            domain_summary_json,
            
            report_data.get('social_eng_analysis', {}).get('risk_level', 'LOW'),
            report_data.get('social_eng_analysis', {}).get('confidence', 0.0),
            social_techniques_json,
            
            report_data.get('malware_analysis', {}).get('total_attachments', 0),
            report_data.get('malware_analysis', {}).get('risk_level', 'LOW'),
            attachment_summary_json,
            
            report_data.get('image_analysis', {}).get('total_images', 0),
            report_data.get('image_analysis', {}).get('risk_level', 'LOW'),
            image_summary_json,
            
            evidence_json,
            datetime.now()
        )
        
        return execute_query(query, params)

    @staticmethod
    def get_by_id(analysis_id):
        row = fetch_one("SELECT * FROM analyzed_emails WHERE id = %s", (analysis_id,))
        if not row:
            return None
        
        # Parse JSON fields safely
        def _safe_json(val, default):
            if isinstance(val, (dict, list)):
                return val
            if not val:
                return default
            try:
                return json.loads(val)
            except:
                return default

        row['url_analysis_summary'] = _safe_json(row.get('url_analysis_summary'), [])
        row['domain_analysis_summary'] = _safe_json(row.get('domain_analysis_summary'), {})
        row['attachment_analysis_summary'] = _safe_json(row.get('attachment_analysis_summary'), [])
        row['image_analysis_summary'] = _safe_json(row.get('image_analysis_summary'), [])
        row['phishing_indicators'] = _safe_json(row.get('phishing_indicators'), [])
        row['social_eng_techniques'] = _safe_json(row.get('social_eng_techniques'), [])
        row['evidence_summary'] = _safe_json(row.get('evidence_summary'), [])
        return row

    @staticmethod
    def get_history(limit=50, offset=0, risk_filter=None, search=None):
        query = "SELECT * FROM analyzed_emails"
        conditions = []
        params = []
        
        if risk_filter and risk_filter.upper() in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
            conditions.append("overall_risk_level = %s")
            params.append(risk_filter.upper())
            
        if search:
            conditions.append("(email_subject LIKE %s OR email_from LIKE %s OR email_text LIKE %s)")
            term = f"%{search}%"
            params.extend([term, term, term])
            
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
            
        query += " ORDER BY created_at DESC LIMIT %s"
        params.append(limit)
        
        rows = fetch_all(query, tuple(params))
        
        # Format rows for UI
        for r in rows:
            if not r.get('overall_risk_level'):
                r['overall_risk_level'] = 'HIGH' if r.get('is_bullying') else 'LOW'
        return rows

    @staticmethod
    def get_dashboard_stats():
        total_row = fetch_one("SELECT COUNT(*) as total FROM analyzed_emails")
        total = total_row['total'] if total_row else 0
        
        if total == 0:
            return {
                'total_analyses': 0,
                'bullying_detected': 0,
                'phishing_detected': 0,
                'suspicious_urls': 0,
                'malware_detected': 0,
                'social_eng_detected': 0,
                'suspicious_images': 0,
                'high_risk_total': 0,
                'detection_rate': 0.0,
                'risk_distribution': {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0},
                'recent_activity': 0,
                'model_count': 0,
                'dataset_count': 0
            }
            
        bullying_row = fetch_one("SELECT COUNT(*) as cnt FROM analyzed_emails WHERE is_bullying = 1")
        phishing_row = fetch_one("SELECT COUNT(*) as cnt FROM analyzed_emails WHERE phishing_risk_level IN ('HIGH', 'CRITICAL')")
        url_row = fetch_one("SELECT SUM(suspicious_urls_count) as cnt FROM analyzed_emails")
        malware_row = fetch_one("SELECT COUNT(*) as cnt FROM analyzed_emails WHERE malware_risk_level IN ('HIGH', 'CRITICAL')")
        social_row = fetch_one("SELECT COUNT(*) as cnt FROM analyzed_emails WHERE social_eng_risk_level IN ('HIGH', 'CRITICAL')")
        image_row = fetch_one("SELECT COUNT(*) as cnt FROM analyzed_emails WHERE image_risk_level IN ('HIGH', 'CRITICAL')")
        high_risk_row = fetch_one("SELECT COUNT(*) as cnt FROM analyzed_emails WHERE overall_risk_level IN ('HIGH', 'CRITICAL')")
        
        # Risk distribution breakdown
        low_row = fetch_one("SELECT COUNT(*) as cnt FROM analyzed_emails WHERE overall_risk_level = 'LOW'")
        med_row = fetch_one("SELECT COUNT(*) as cnt FROM analyzed_emails WHERE overall_risk_level = 'MEDIUM'")
        high_cnt_row = fetch_one("SELECT COUNT(*) as cnt FROM analyzed_emails WHERE overall_risk_level = 'HIGH'")
        crit_row = fetch_one("SELECT COUNT(*) as cnt FROM analyzed_emails WHERE overall_risk_level = 'CRITICAL'")
        
        model_row = fetch_one("SELECT COUNT(*) as cnt FROM model_history")
        dataset_row = fetch_one("SELECT COUNT(*) as cnt FROM dataset_history")
        
        b_count = bullying_row['cnt'] if bullying_row else 0
        p_count = phishing_row['cnt'] if phishing_row else 0
        u_count = int(url_row['cnt'] or 0) if url_row else 0
        m_count = malware_row['cnt'] if malware_row else 0
        s_count = social_row['cnt'] if social_row else 0
        img_count = image_row['cnt'] if image_row else 0
        hr_count = high_risk_row['cnt'] if high_risk_row else (b_count)
        
        return {
            'total_analyses': total,
            'bullying_detected': b_count,
            'phishing_detected': p_count,
            'suspicious_urls': u_count,
            'malware_detected': m_count,
            'social_eng_detected': s_count,
            'suspicious_images': img_count,
            'high_risk_total': hr_count,
            'detection_rate': round((hr_count / total * 100) if total > 0 else 0, 2),
            'risk_distribution': {
                'LOW': low_row['cnt'] if low_row else 0,
                'MEDIUM': med_row['cnt'] if med_row else 0,
                'HIGH': high_cnt_row['cnt'] if high_cnt_row else 0,
                'CRITICAL': crit_row['cnt'] if crit_row else 0
            },
            'recent_activity': total,
            'model_count': model_row['cnt'] if model_row else 0,
            'dataset_count': dataset_row['cnt'] if dataset_row else 0
        }
