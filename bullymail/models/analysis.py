import json
from datetime import datetime
from ..database.connection import fetch_one, fetch_all, execute_query

class AnalysisModel:
    """Data Access Object for Multi-Vector Email Threat Analyses (Tenant Scoped)"""
    
    @staticmethod
    def _get_table_columns():
        """Returns set of existing column names for analyzed_emails table."""
        try:
            from ..database.connection import get_engine_type
            engine = get_engine_type()
            if engine == 'mysql':
                rows = fetch_all("DESCRIBE analyzed_emails")
                return {r['Field'] for r in rows} if rows else set()
            else:
                rows = fetch_all("PRAGMA table_info(analyzed_emails)")
                return {r['name'] for r in rows} if rows else set()
        except Exception:
            return set()

    @staticmethod
    def save_analysis(report_data, institution_id=1, user_id=None, email_config_id=None):
        """Saves a unified threat analysis report to the database with tenant/user/mailbox ownership."""
        evidence_json = json.dumps(report_data.get('evidence', []))
        url_summary_json = json.dumps(report_data.get('url_analysis', {}).get('urls', []))
        domain_summary_json = json.dumps(report_data.get('domain_analysis', {}))
        attachment_summary_json = json.dumps(report_data.get('malware_analysis', {}).get('attachments', []))
        image_summary_json = json.dumps(report_data.get('image_analysis', {}).get('images', []))
        phishing_indicators_json = json.dumps(report_data.get('phishing_analysis', {}).get('indicators', []))
        social_techniques_json = json.dumps(report_data.get('social_eng_analysis', {}).get('techniques', []))
        bullying_matches_str = ', '.join(report_data.get('bullying_analysis', {}).get('rule_based_matches', []))
        explanation_json = json.dumps(report_data.get('bullying_analysis', {}).get('explanation', {}))
        top_factors_json = json.dumps(report_data.get('top_risk_factors', report_data.get('evidence', [])))
        
        malware = report_data.get('malware_analysis', {})
        image = report_data.get('image_analysis', {})

        def _clean(s):
            if not isinstance(s, str):
                return s
            import re
            cleaned = re.sub(r'[\u2000-\u200f\u2028-\u202f\ud800-\udfff]', ' ', s)
            return cleaned.encode('utf-8', errors='ignore').decode('utf-8', errors='ignore')

        col_map = {
            'institution_id': institution_id or 1,
            'user_id': user_id,
            'email_config_id': email_config_id,
            'email_subject': _clean(report_data.get('email_subject', 'No Subject')),
            'email_from': _clean(report_data.get('email_from', 'Unknown')),
            'email_to': _clean(report_data.get('email_to', '')),
            'email_text': _clean(report_data.get('email_text', '')),
            'overall_risk_level': report_data.get('overall_risk_level', 'LOW'),
            'overall_confidence': report_data.get('overall_confidence', 0.0),
            'threat_score': report_data.get('threat_score', 0.0),
            'is_bullying': 1 if report_data.get('bullying_analysis', {}).get('is_bullying') else 0,
            'confidence': report_data.get('bullying_analysis', {}).get('confidence', 0.0),
            'rule_based_matches': bullying_matches_str,
            'rule_based_score': report_data.get('bullying_analysis', {}).get('rule_based_score', 0.0),
            'ml_prediction': 1 if report_data.get('bullying_analysis', {}).get('ml_prediction') else 0,
            'ml_confidence': report_data.get('bullying_analysis', {}).get('ml_confidence', 0.0),
            'model_used': report_data.get('bullying_analysis', {}).get('model_used', 'Hybrid'),
            'phishing_risk_level': report_data.get('phishing_analysis', {}).get('risk_level', 'LOW'),
            'phishing_confidence': report_data.get('phishing_analysis', {}).get('confidence', 0.0),
            'phishing_indicators': phishing_indicators_json,
            'urls_detected': report_data.get('url_analysis', {}).get('total_urls', 0),
            'suspicious_urls_count': report_data.get('url_analysis', {}).get('suspicious_count', 0),
            'url_analysis_summary': url_summary_json,
            'domain_analysis_summary': domain_summary_json,
            'social_eng_risk_level': report_data.get('social_eng_analysis', {}).get('risk_level', 'LOW'),
            'social_eng_confidence': report_data.get('social_eng_analysis', {}).get('confidence', 0.0),
            'social_eng_techniques': social_techniques_json,
            'attachments_count': malware.get('total_attachments', 0),
            'malware_detected': 1 if malware.get('malware_detected') else 0,
            'malicious_attachments_count': malware.get('malicious_count', 0),
            'attachment_risk_level': malware.get('risk_level', 'LOW'),
            'attachment_findings': attachment_summary_json,
            'images_count': image.get('total_images', 0),
            'suspicious_images_count': image.get('suspicious_count', 0),
            'image_forensics_summary': image_summary_json,
            'explanation': explanation_json,
            'top_risk_factors': top_factors_json,
            'email_date': datetime.now()
        }

        existing_cols = AnalysisModel._get_table_columns()
        if existing_cols:
            filtered_cols = {k: v for k, v in col_map.items() if k in existing_cols}
        else:
            filtered_cols = col_map

        keys = list(filtered_cols.keys())
        vals = [filtered_cols[k] for k in keys]
        cols_str = ", ".join(keys)
        placeholders_str = ", ".join(["%s"] * len(keys))

        query = f"INSERT INTO analyzed_emails ({cols_str}) VALUES ({placeholders_str})"
        return execute_query(query, tuple(vals))

    @staticmethod
    def get_by_id(analysis_id, institution_id=1, user_id=None, role=None):
        if role == 'admin' or user_id is None:
            if institution_id is not None:
                row = fetch_one("SELECT * FROM analyzed_emails WHERE id = %s AND institution_id = %s", (analysis_id, institution_id))
            else:
                row = fetch_one("SELECT * FROM analyzed_emails WHERE id = %s", (analysis_id,))
        else:
            row = fetch_one("SELECT * FROM analyzed_emails WHERE id = %s AND institution_id = %s AND user_id = %s", (analysis_id, institution_id or 1, user_id))

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

        # Ensure overall risk and confidence fields are populated
        is_bull = bool(row.get('is_bullying'))
        overall_risk = row.get('overall_risk_level')
        if not overall_risk or overall_risk == 'UNKNOWN':
            overall_risk = 'HIGH' if is_bull else 'LOW'
        row['overall_risk_level'] = overall_risk

        overall_conf = row.get('overall_confidence')
        if overall_conf is None or overall_conf == 0.0:
            overall_conf = row.get('confidence') or row.get('ml_confidence') or (0.85 if is_bull else 0.15)
        row['overall_confidence'] = float(overall_conf)

        if row.get('threat_score') is None or row.get('threat_score') == 0.0:
            row['threat_score'] = round(float(overall_conf), 2)

        # Build nested vector analyses expected by UI drawer:
        bull_conf = float(row.get('confidence') or row.get('ml_confidence') or 0.0)
        row['bullying_analysis'] = {
            'is_bullying': is_bull,
            'confidence': bull_conf,
            'severity': 'HIGH' if is_bull else 'LOW',
            'rule_based_matches': [m.strip() for m in (row.get('rule_based_matches') or '').split(',') if m.strip()],
            'rule_based_score': float(row.get('rule_based_score') or 0.0),
            'ml_prediction': bool(row.get('ml_prediction')),
            'ml_confidence': float(row.get('ml_confidence') or 0.0),
            'model_used': row.get('model_used') or 'Hybrid'
        }

        p_risk = row.get('phishing_risk_level') or ('HIGH' if row.get('phishing_indicators') else 'LOW')
        p_conf = float(row.get('phishing_confidence') or (0.85 if p_risk != 'LOW' else 0.0))
        p_indicators = row['phishing_indicators'] if isinstance(row.get('phishing_indicators'), list) else []
        row['phishing_analysis'] = {
            'risk_level': p_risk,
            'confidence': p_conf,
            'indicators': p_indicators
        }

        urls_list = row['url_analysis_summary'] if isinstance(row.get('url_analysis_summary'), list) else []
        sus_urls = int(row.get('suspicious_urls_count') or len([u for u in urls_list if isinstance(u, dict) and u.get('is_suspicious')]))
        tot_urls = int(row.get('urls_detected') or len(urls_list))
        row['url_analysis'] = {
            'total_urls': tot_urls,
            'suspicious_count': sus_urls,
            'urls': urls_list
        }

        s_risk = row.get('social_eng_risk_level') or 'LOW'
        s_conf = float(row.get('social_eng_confidence') or (0.80 if s_risk != 'LOW' else 0.0))
        s_tech = row['social_eng_techniques'] if isinstance(row.get('social_eng_techniques'), list) else []
        row['social_eng_analysis'] = {
            'risk_level': s_risk,
            'confidence': s_conf,
            'techniques': s_tech
        }

        m_risk = row.get('attachment_risk_level') or ('HIGH' if row.get('malware_detected') else 'LOW')
        m_count = int(row.get('attachments_count') or 0)
        row['malware_analysis'] = {
            'risk_level': m_risk,
            'malware_detected': bool(row.get('malware_detected')),
            'total_attachments': m_count,
            'malicious_count': int(row.get('malicious_attachments_count') or 0),
            'attachments': row['attachment_analysis_summary'] if isinstance(row.get('attachment_analysis_summary'), list) else []
        }

        img_count = int(row.get('images_count') or 0)
        img_sus = int(row.get('suspicious_images_count') or 0)
        img_risk = 'HIGH' if img_sus > 0 else 'LOW'
        row['image_analysis'] = {
            'risk_level': img_risk,
            'total_images': img_count,
            'suspicious_count': img_sus,
            'images': row['image_analysis_summary'] if isinstance(row.get('image_analysis_summary'), list) else []
        }

        ev_list = row['evidence_summary'] if isinstance(row.get('evidence_summary'), list) else []
        if not ev_list:
            if is_bull:
                matches_str = row.get('rule_based_matches') or 'NLP linguistic threat pattern'
                ev_list.append({
                    'category': 'Cyberbullying',
                    'severity': 'HIGH',
                    'title': 'Language Pattern Flagged for Cyberbullying',
                    'details': f'ML Classifier ({row.get("model_used", "Hybrid")}) confidence: {round(bull_conf * 100, 1)}%. Matches: {matches_str}.'
                })
            if p_risk in ('HIGH', 'CRITICAL'):
                ev_list.append({
                    'category': 'Phishing',
                    'severity': p_risk,
                    'title': 'Phishing Indicators Identified',
                    'details': 'Sender domain or message heuristics exhibit high-risk phishing vectors.'
                })
            if sus_urls > 0:
                ev_list.append({
                    'category': 'Link Safety',
                    'severity': 'HIGH',
                    'title': f'{sus_urls} Suspicious URL(s) Detected',
                    'details': 'Hyperlinks flagged for suspicious redirect or credential harvesting risk.'
                })
        row['evidence'] = ev_list

        return row

    @staticmethod
    def get_history(limit=50, offset=0, risk_filter=None, search=None, institution_id=1, user_id=None, role=None):
        query = "SELECT * FROM analyzed_emails"
        conditions = []
        params = []
        
        inst_id = institution_id if institution_id is not None else 1
        conditions.append("institution_id = %s")
        params.append(inst_id)

        if role != 'admin' and user_id is not None:
            conditions.append("user_id = %s")
            params.append(user_id)

        existing_cols = AnalysisModel._get_table_columns()

        if risk_filter and risk_filter.upper() in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
            if 'overall_risk_level' in existing_cols:
                conditions.append("overall_risk_level = %s")
                params.append(risk_filter.upper())
            elif risk_filter.upper() in ('HIGH', 'CRITICAL'):
                conditions.append("is_bullying = 1")
            elif risk_filter.upper() == 'LOW':
                conditions.append("is_bullying = 0")
            
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
            if r.get('overall_confidence') is None:
                r['overall_confidence'] = r.get('confidence') or r.get('ml_confidence') or 0.85
        return rows

    @staticmethod
    def get_mailbox_emails(mailbox_id, institution_id=1, limit=50, search=None, risk_filter=None):
        """Retrieves emails belonging strictly to the specified mailbox (Mailbox Isolation Enforced)."""
        query = "SELECT * FROM analyzed_emails"
        conditions = ["institution_id = %s"]
        params = [institution_id or 1]

        # Mailbox isolation filter: match direct email_config_id OR linked ingested_messages email_config_id
        conditions.append("(email_config_id = %s OR id IN (SELECT analysis_id FROM ingested_messages WHERE email_config_id = %s AND analysis_id IS NOT NULL))")
        params.extend([mailbox_id, mailbox_id])

        existing_cols = AnalysisModel._get_table_columns()

        if risk_filter and risk_filter.upper() in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
            if 'overall_risk_level' in existing_cols:
                conditions.append("overall_risk_level = %s")
                params.append(risk_filter.upper())
            elif risk_filter.upper() in ('HIGH', 'CRITICAL'):
                conditions.append("is_bullying = 1")
            elif risk_filter.upper() == 'LOW':
                conditions.append("is_bullying = 0")

        if search:
            conditions.append("(email_subject LIKE %s OR email_from LIKE %s OR email_text LIKE %s)")
            term = f"%{search}%"
            params.extend([term, term, term])

        query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY created_at DESC LIMIT %s"
        params.append(limit)

        rows = fetch_all(query, tuple(params))

        for r in rows:
            if not r.get('overall_risk_level'):
                r['overall_risk_level'] = 'HIGH' if r.get('is_bullying') else 'LOW'
            if r.get('overall_confidence') is None:
                r['overall_confidence'] = r.get('confidence') or r.get('ml_confidence') or 0.85
        return rows

    @staticmethod
    def get_dashboard_stats(institution_id=1, user_id=None, role=None):
        inst_id = institution_id if institution_id is not None else 1

        if role != 'admin' and user_id is not None:
            inst_clause = "WHERE institution_id = %s AND user_id = %s"
            params_base = (inst_id, user_id)
        else:
            inst_clause = "WHERE institution_id = %s"
            params_base = (inst_id,)

        existing_cols = AnalysisModel._get_table_columns()

        total_row = fetch_one(f"SELECT COUNT(*) as total FROM analyzed_emails {inst_clause}", params_base)
        total = total_row['total'] if total_row else 0
        
        if total == 0:
            try:
                model_row = fetch_one("SELECT COUNT(*) as cnt FROM model_history")
                model_count = model_row['cnt'] if model_row else 0
            except Exception:
                model_count = 0

            try:
                dataset_row = fetch_one("SELECT COUNT(*) as cnt FROM dataset_history")
                dataset_count = dataset_row['cnt'] if dataset_row else 0
            except Exception:
                dataset_count = 0

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
                'model_count': model_count,
                'dataset_count': dataset_count
            }

        # Cyberbullying
        b_row = fetch_one(f"SELECT COUNT(*) as cnt FROM analyzed_emails {inst_clause} AND is_bullying = 1", params_base)
        b_count = b_row['cnt'] if b_row else 0

        # Phishing (strictly phishing_risk_level IN MEDIUM, HIGH, CRITICAL)
        if 'phishing_risk_level' in existing_cols:
            p_row = fetch_one(f"SELECT COUNT(*) as cnt FROM analyzed_emails {inst_clause} AND phishing_risk_level IN ('MEDIUM', 'HIGH', 'CRITICAL')", params_base)
            p_count = p_row['cnt'] if p_row else 0
        else:
            p_count = 0

        # Suspicious / Risky URLs (count of analyses with suspicious_urls_count > 0)
        if 'suspicious_urls_count' in existing_cols:
            u_row = fetch_one(f"SELECT COUNT(*) as cnt FROM analyzed_emails {inst_clause} AND suspicious_urls_count > 0", params_base)
            u_count = u_row['cnt'] if u_row else 0
        else:
            u_count = 0

        # Malware (malware_detected = 1 or attachment_risk_level IN MEDIUM, HIGH, CRITICAL)
        if 'attachment_risk_level' in existing_cols:
            m_row = fetch_one(f"SELECT COUNT(*) as cnt FROM analyzed_emails {inst_clause} AND (malware_detected = 1 OR attachment_risk_level IN ('MEDIUM', 'HIGH', 'CRITICAL'))", params_base)
            m_count = m_row['cnt'] if m_row else 0
        else:
            m_row = fetch_one(f"SELECT COUNT(*) as cnt FROM analyzed_emails {inst_clause} AND malware_detected = 1", params_base)
            m_count = m_row['cnt'] if m_row else 0

        # Social Engineering (social_eng_risk_level IN MEDIUM, HIGH, CRITICAL)
        if 'social_eng_risk_level' in existing_cols:
            s_row = fetch_one(f"SELECT COUNT(*) as cnt FROM analyzed_emails {inst_clause} AND social_eng_risk_level IN ('MEDIUM', 'HIGH', 'CRITICAL')", params_base)
            s_count = s_row['cnt'] if s_row else 0
        else:
            s_count = 0

        # Suspicious Images
        if 'suspicious_images_count' in existing_cols:
            img_row = fetch_one(f"SELECT COALESCE(SUM(suspicious_images_count), 0) as cnt FROM analyzed_emails {inst_clause}", params_base)
            img_count = int(img_row['cnt'] or 0) if img_row else 0
        else:
            img_count = 0

        # High Risk Total
        if 'overall_risk_level' in existing_cols:
            hr_row = fetch_one(f"SELECT COUNT(*) as cnt FROM analyzed_emails {inst_clause} AND overall_risk_level IN ('HIGH', 'CRITICAL')", params_base)
            hr_count = hr_row['cnt'] if hr_row else (b_count + p_count + s_count + m_count)
        else:
            hr_row = fetch_one(f"SELECT COUNT(*) as cnt FROM analyzed_emails {inst_clause} AND (is_bullying = 1 OR social_eng_risk_level IN ('MEDIUM', 'HIGH', 'CRITICAL') OR attachment_risk_level IN ('MEDIUM', 'HIGH', 'CRITICAL') OR malware_detected = 1)", params_base)
            hr_count = hr_row['cnt'] if hr_row else (b_count + p_count + s_count + m_count)

        # Risk Distribution
        if 'overall_risk_level' in existing_cols:
            low_row = fetch_one(f"SELECT COUNT(*) as cnt FROM analyzed_emails {inst_clause} AND overall_risk_level = 'LOW'", params_base)
            med_row = fetch_one(f"SELECT COUNT(*) as cnt FROM analyzed_emails {inst_clause} AND overall_risk_level = 'MEDIUM'", params_base)
            high_cnt_row = fetch_one(f"SELECT COUNT(*) as cnt FROM analyzed_emails {inst_clause} AND overall_risk_level = 'HIGH'", params_base)
            crit_row = fetch_one(f"SELECT COUNT(*) as cnt FROM analyzed_emails {inst_clause} AND overall_risk_level = 'CRITICAL'", params_base)
            risk_dist = {
                'LOW': low_row['cnt'] if low_row else 0,
                'MEDIUM': med_row['cnt'] if med_row else 0,
                'HIGH': high_cnt_row['cnt'] if high_cnt_row else 0,
                'CRITICAL': crit_row['cnt'] if crit_row else 0
            }
        else:
            high_cnt = hr_count
            low_cnt = max(0, total - high_cnt)
            risk_dist = {'LOW': low_cnt, 'MEDIUM': 0, 'HIGH': high_cnt, 'CRITICAL': 0}

        try:
            model_row = fetch_one("SELECT COUNT(*) as cnt FROM model_history")
            model_count = model_row['cnt'] if model_row else 0
        except Exception:
            model_count = 0

        try:
            dataset_row = fetch_one("SELECT COUNT(*) as cnt FROM dataset_history")
            dataset_count = dataset_row['cnt'] if dataset_row else 0
        except Exception:
            dataset_count = 0

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
            'risk_distribution': risk_dist,
            'recent_activity': total,
            'model_count': model_count,
            'dataset_count': dataset_count
        }
