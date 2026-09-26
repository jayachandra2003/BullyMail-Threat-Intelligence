from ..database.connection import fetch_one, fetch_all, execute_query

class InstitutionModel:
    """
    Data Access Object for Institutions (Tenants).
    Supports tenant boundary provisioning, retrieval, and institution-scoped telemetry calculations.
    """

    @staticmethod
    def create_institution(name: str, domain: str, code: str = None,
                           org_type: str = 'university', contact_name: str = None,
                           contact_email: str = None, status: str = 'ACTIVE',
                           settings: str = '{}') -> int:
        """
        Creates a new institution with unique name and domain.
        Returns newly auto-incremented institution_id.
        """
        clean_name = (name or '').strip()
        clean_domain = (domain or '').strip().lower()
        clean_code = (code or '').strip().upper()
        clean_type = (org_type or 'university').strip().lower()
        clean_cname = (contact_name or '').strip() or None
        clean_cemail = (contact_email or '').strip().lower() or None
        clean_status = (status or 'ACTIVE').strip().upper()
        clean_settings = settings if isinstance(settings, str) else '{}'

        if not clean_name:
            raise ValueError("Institution name cannot be empty.")
        if not clean_domain:
            raise ValueError("Institution domain cannot be empty.")

        if not clean_code:
            # Auto-generate a clean uppercase code prefix (e.g., "University A" -> "UNIV-A")
            parts = [p[0] for p in clean_name.split() if p]
            clean_code = "".join(parts[:4]).upper() if parts else "INST"
            if len(clean_code) < 3:
                clean_code = clean_name[:4].upper()

        # Check domain collision
        existing = fetch_one("SELECT id FROM institutions WHERE domain = %s", (clean_domain,))
        if existing:
            raise ValueError(f"An institution with domain '{clean_domain}' already exists.")

        inst_id = execute_query(
            "INSERT INTO institutions (name, domain, code, status, org_type, contact_name, contact_email, settings) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (clean_name, clean_domain, clean_code, clean_status, clean_type, clean_cname, clean_cemail, clean_settings)
        )
        return inst_id

    @staticmethod
    def get_by_id(inst_id: int):
        """Retrieves institution record by ID."""
        if not inst_id:
            return None
        return fetch_one(
            "SELECT id, name, domain, code, status, org_type, contact_name, contact_email, settings, created_at, updated_at "
            "FROM institutions WHERE id = %s",
            (inst_id,)
        )

    @staticmethod
    def get_by_domain(domain: str):
        """Retrieves institution record by domain."""
        if not domain:
            return None
        return fetch_one(
            "SELECT id, name, domain, code, status, org_type, contact_name, contact_email, settings, created_at, updated_at "
            "FROM institutions WHERE domain = %s",
            (domain.strip().lower(),)
        )

    @staticmethod
    def list_all():
        """Lists all registered institutions."""
        return fetch_all(
            "SELECT id, name, domain, code, status, org_type, contact_name, contact_email, created_at, updated_at "
            "FROM institutions ORDER BY id ASC"
        )

    @staticmethod
    def list_pending():
        """Lists institutions pending platform owner approval."""
        return fetch_all(
            "SELECT id, name, domain, code, status, org_type, contact_name, contact_email, created_at "
            "FROM institutions WHERE status = 'PENDING_APPROVAL' ORDER BY id ASC"
        )

    @staticmethod
    def update_status(inst_id: int, status: str) -> bool:
        """Updates organization approval status (e.g., ACTIVE, REJECTED, SUSPENDED)."""
        if not inst_id:
            return False
        clean_status = (status or '').strip().upper()
        return execute_query(
            "UPDATE institutions SET status = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
            (clean_status, inst_id)
        ) > 0

    @staticmethod
    def update_settings(inst_id: int, settings: str) -> bool:
        """Updates organization settings JSON string."""
        if not inst_id:
            return False
        import json
        if isinstance(settings, dict):
            settings_str = json.dumps(settings)
        else:
            settings_str = str(settings or '{}')
        return execute_query(
            "UPDATE institutions SET settings = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
            (settings_str, inst_id)
        ) > 0

    @staticmethod
    def update_institution(inst_id: int, name: str = None, org_type: str = None,
                           contact_name: str = None, contact_email: str = None) -> bool:
        """Updates organization profile metadata."""
        if not inst_id:
            return False
        updates = []
        params = []
        if name:
            updates.append("name = %s")
            params.append(name.strip())
        if org_type:
            updates.append("org_type = %s")
            params.append(org_type.strip().lower())
        if contact_name is not None:
            updates.append("contact_name = %s")
            params.append(contact_name.strip() or None)
        if contact_email is not None:
            updates.append("contact_email = %s")
            params.append(contact_email.strip().lower() or None)

        if not updates:
            return False

        params.append(inst_id)
        return execute_query(
            f"UPDATE institutions SET {', '.join(updates)}, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
            tuple(params)
        ) > 0

    @staticmethod
    def get_platform_stats() -> dict:
        """Calculates platform-wide overview metrics for the Platform Owner."""
        org_total = fetch_one("SELECT COUNT(*) AS cnt FROM institutions")
        total_orgs = org_total['cnt'] if isinstance(org_total, dict) else (org_total[0] if org_total else 0)

        org_act = fetch_one("SELECT COUNT(*) AS cnt FROM institutions WHERE status = 'ACTIVE'")
        active_orgs = org_act['cnt'] if isinstance(org_act, dict) else (org_act[0] if org_act else 0)

        org_pend = fetch_one("SELECT COUNT(*) AS cnt FROM institutions WHERE status = 'PENDING_APPROVAL'")
        pending_orgs = org_pend['cnt'] if isinstance(org_pend, dict) else (org_pend[0] if org_pend else 0)

        mem_total = fetch_one("SELECT COUNT(*) AS cnt FROM organization_members")
        total_members = mem_total['cnt'] if isinstance(mem_total, dict) else (mem_total[0] if mem_total else 0)

        mb_total = fetch_one("SELECT COUNT(*) AS cnt FROM email_config")
        total_mailboxes = mb_total['cnt'] if isinstance(mb_total, dict) else (mb_total[0] if mb_total else 0)

        an_total = fetch_one("SELECT COUNT(*) AS cnt FROM analyzed_emails")
        total_emails = an_total['cnt'] if isinstance(an_total, dict) else (an_total[0] if an_total else 0)

        threat_total = fetch_one("SELECT COUNT(*) AS cnt FROM analyzed_emails WHERE overall_risk_level != 'LOW'")
        total_threats = threat_total['cnt'] if isinstance(threat_total, dict) else (threat_total[0] if threat_total else 0)

        crit = fetch_one("SELECT COUNT(*) AS cnt FROM analyzed_emails WHERE overall_risk_level = 'CRITICAL'")
        critical_count = crit['cnt'] if isinstance(crit, dict) else (crit[0] if crit else 0)

        high = fetch_one("SELECT COUNT(*) AS cnt FROM analyzed_emails WHERE overall_risk_level = 'HIGH'")
        high_count = high['cnt'] if isinstance(high, dict) else (high[0] if high else 0)

        med = fetch_one("SELECT COUNT(*) AS cnt FROM analyzed_emails WHERE overall_risk_level = 'MEDIUM'")
        medium_count = med['cnt'] if isinstance(med, dict) else (med[0] if med else 0)

        cb = fetch_one("SELECT COUNT(*) AS cnt FROM analyzed_emails WHERE is_bullying = 1")
        cb_count = cb['cnt'] if isinstance(cb, dict) else (cb[0] if cb else 0)

        ph = fetch_one("SELECT COUNT(*) AS cnt FROM analyzed_emails WHERE phishing_risk_level != 'LOW'")
        ph_count = ph['cnt'] if isinstance(ph, dict) else (ph[0] if ph else 0)

        return {
            'total_organizations': total_orgs,
            'total_institutions': total_orgs,
            'active_organizations': active_orgs,
            'active_institutions': active_orgs,
            'pending_organizations': pending_orgs,
            'pending_institutions': pending_orgs,
            'total_members': total_members,
            'total_mailboxes': total_mailboxes,
            'total_emails': total_emails,
            'total_threats': total_threats,
            'critical_count': critical_count,
            'high_count': high_count,
            'medium_count': medium_count,
            'vector_breakdown': {
                'cyberbullying': cb_count,
                'phishing': ph_count
            }
        }

    @staticmethod
    def get_stats(inst_id: int) -> dict:
        """Calculates security overview metrics strictly for a single institution."""
        if not inst_id:
            return {
                'total_mailboxes': 0,
                'total_emails': 0,
                'total_threats': 0,
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'clean_count': 0,
                'vector_breakdown': {
                    'cyberbullying': 0,
                    'phishing': 0,
                    'malicious_links': 0,
                    'social_engineering': 0,
                    'malware': 0,
                    'image_forensics': 0
                },
                'last_sync': None
            }

        mb_row = fetch_one("SELECT COUNT(*) AS cnt FROM email_config WHERE institution_id = %s", (inst_id,))
        total_mailboxes = mb_row['cnt'] if isinstance(mb_row, dict) else (mb_row[0] if mb_row else 0)

        mb_act_row = fetch_one("SELECT COUNT(*) AS cnt FROM email_config WHERE institution_id = %s AND status = 'active'", (inst_id,))
        active_mailboxes = mb_act_row['cnt'] if isinstance(mb_act_row, dict) else (mb_act_row[0] if mb_act_row else 0)

        ing_row = fetch_one("SELECT COUNT(*) AS cnt FROM ingested_messages WHERE institution_id = %s", (inst_id,))
        ing_cnt = ing_row['cnt'] if isinstance(ing_row, dict) else (ing_row[0] if ing_row else 0)

        an_row = fetch_one("SELECT COUNT(*) AS cnt FROM analyzed_emails WHERE institution_id = %s", (inst_id,))
        an_cnt = an_row['cnt'] if isinstance(an_row, dict) else (an_row[0] if an_row else 0)

        cfg_row = fetch_one("SELECT COALESCE(SUM(total_ingested_count), 0) AS cnt FROM email_config WHERE institution_id = %s", (inst_id,))
        cfg_cnt = cfg_row['cnt'] if isinstance(cfg_row, dict) else (cfg_row[0] if cfg_row else 0)

        total_emails = max(ing_cnt, an_cnt, cfg_cnt)

        tr_row = fetch_one("SELECT COUNT(*) AS cnt FROM analyzed_emails WHERE institution_id = %s AND overall_risk_level != 'LOW'", (inst_id,))
        total_threats = tr_row['cnt'] if isinstance(tr_row, dict) else (tr_row[0] if tr_row else 0)

        crit_row = fetch_one("SELECT COUNT(*) AS cnt FROM analyzed_emails WHERE institution_id = %s AND overall_risk_level = 'CRITICAL'", (inst_id,))
        critical_count = crit_row['cnt'] if isinstance(crit_row, dict) else (crit_row[0] if crit_row else 0)

        high_row = fetch_one("SELECT COUNT(*) AS cnt FROM analyzed_emails WHERE institution_id = %s AND overall_risk_level = 'HIGH'", (inst_id,))
        high_count = high_row['cnt'] if isinstance(high_row, dict) else (high_row[0] if high_row else 0)

        med_row = fetch_one("SELECT COUNT(*) AS cnt FROM analyzed_emails WHERE institution_id = %s AND overall_risk_level = 'MEDIUM'", (inst_id,))
        medium_count = med_row['cnt'] if isinstance(med_row, dict) else (med_row[0] if med_row else 0)

        clean_row = fetch_one("SELECT COUNT(*) AS cnt FROM analyzed_emails WHERE institution_id = %s AND overall_risk_level = 'LOW'", (inst_id,))
        clean_count = clean_row['cnt'] if isinstance(clean_row, dict) else (clean_row[0] if clean_row else 0)

        cb_row = fetch_one("SELECT COUNT(*) AS cnt FROM analyzed_emails WHERE institution_id = %s AND is_bullying = 1", (inst_id,))
        cb_count = cb_row['cnt'] if isinstance(cb_row, dict) else (cb_row[0] if cb_row else 0)

        ph_row = fetch_one("SELECT COUNT(*) AS cnt FROM analyzed_emails WHERE institution_id = %s AND phishing_risk_level != 'LOW'", (inst_id,))
        ph_count = ph_row['cnt'] if isinstance(ph_row, dict) else (ph_row[0] if ph_row else 0)

        link_row = fetch_one("SELECT COUNT(*) AS cnt FROM analyzed_emails WHERE institution_id = %s AND suspicious_urls_count > 0", (inst_id,))
        link_count = link_row['cnt'] if isinstance(link_row, dict) else (link_row[0] if link_row else 0)

        se_row = fetch_one("SELECT COUNT(*) AS cnt FROM analyzed_emails WHERE institution_id = %s AND social_eng_risk_level != 'LOW'", (inst_id,))
        se_count = se_row['cnt'] if isinstance(se_row, dict) else (se_row[0] if se_row else 0)

        mw_row = fetch_one("SELECT COUNT(*) AS cnt FROM analyzed_emails WHERE institution_id = %s AND (malware_detected = 1 OR malicious_attachments_count > 0)", (inst_id,))
        mw_count = mw_row['cnt'] if isinstance(mw_row, dict) else (mw_row[0] if mw_row else 0)

        img_row = fetch_one("SELECT COUNT(*) AS cnt FROM analyzed_emails WHERE institution_id = %s AND suspicious_images_count > 0", (inst_id,))
        img_count = img_row['cnt'] if isinstance(img_row, dict) else (img_row[0] if img_row else 0)

        ls_row = fetch_one("SELECT MAX(last_synced_at) AS last_sync FROM email_config WHERE institution_id = %s", (inst_id,))
        last_sync = ls_row['last_sync'] if isinstance(ls_row, dict) else (ls_row[0] if ls_row else None)

        return {
            'total_mailboxes': total_mailboxes,
            'active_mailboxes': active_mailboxes,
            'total_emails': total_emails,
            'total_threats': total_threats,
            'critical_count': critical_count,
            'high_count': high_count,
            'medium_count': medium_count,
            'clean_count': clean_count,
            'vector_breakdown': {
                'cyberbullying': cb_count,
                'phishing': ph_count,
                'malicious_links': link_count,
                'social_engineering': se_count,
                'malware': mw_count,
                'image_forensics': img_count
            },
            'last_sync': str(last_sync) if last_sync else None
        }
