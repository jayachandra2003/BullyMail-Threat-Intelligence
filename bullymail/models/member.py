import csv
import io
import re
from ..database.connection import fetch_one, fetch_all, execute_query

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')

class OrganizationMemberModel:
    """
    Data Access Object for Organization Members.
    Supports students, faculty, staff for universities and employees/staff for enterprises.
    Enforces strict tenant boundaries on all operations.
    """

    @staticmethod
    def normalize_email(email: str) -> str:
        return email.strip().lower() if email else ""

    @staticmethod
    def validate_email(email: str) -> bool:
        if not email or not isinstance(email, str):
            return False
        return bool(EMAIL_REGEX.match(email.strip()))

    @classmethod
    def add_member(cls, institution_id: int, full_name: str, email: str,
                   member_id: str = None, department: str = None,
                   member_type: str = 'member', status: str = 'ACTIVE',
                   identifier: str = None) -> int:
        if not institution_id:
            raise ValueError("Institution ID is required.")
        clean_name = (full_name or '').strip()
        if not clean_name:
            raise ValueError("Member full name cannot be empty.")
        clean_email = cls.normalize_email(email)
        if not cls.validate_email(clean_email):
            raise ValueError(f"Invalid email address: '{email}'")

        clean_mid = (identifier or member_id or '').strip() or None
        clean_dept = (department or '').strip() or None
        clean_type = (member_type or 'member').strip().lower()
        clean_status = (status or 'ACTIVE').strip().upper()

        existing = fetch_one(
            "SELECT id FROM organization_members WHERE institution_id = %s AND email = %s",
            (institution_id, clean_email)
        )
        if existing:
            raise ValueError(f"A member with email '{clean_email}' already exists in this organization.")

        return execute_query(
            "INSERT INTO organization_members "
            "(institution_id, member_id, full_name, email, department, member_type, status) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (institution_id, clean_mid, clean_name, clean_email, clean_dept, clean_type, clean_status)
        )

    @classmethod
    def get_by_id(cls, member_pk: int, institution_id: int = None):
        if not member_pk:
            return None
        if institution_id:
            row = fetch_one(
                "SELECT id, institution_id, member_id, full_name, email, department, member_type, status, created_at, updated_at "
                "FROM organization_members WHERE id = %s AND institution_id = %s",
                (member_pk, institution_id)
            )
        else:
            row = fetch_one(
                "SELECT id, institution_id, member_id, full_name, email, department, member_type, status, created_at, updated_at "
                "FROM organization_members WHERE id = %s",
                (member_pk,)
            )
        if row and isinstance(row, dict):
            row['identifier'] = row.get('member_id')
        return row

    @classmethod
    def get_by_email(cls, email: str, institution_id: int):
        clean_email = cls.normalize_email(email)
        if not clean_email or not institution_id:
            return None
        row = fetch_one(
            "SELECT id, institution_id, member_id, full_name, email, department, member_type, status, created_at, updated_at "
            "FROM organization_members WHERE institution_id = %s AND email = %s",
            (institution_id, clean_email)
        )
        if row and isinstance(row, dict):
            row['identifier'] = row.get('member_id')
        return row

    @classmethod
    def list_members(cls, institution_id: int, search: str = None,
                     department: str = None, member_type: str = None,
                     status: str = None, limit: int = 200, offset: int = 0):
        if not institution_id:
            return []

        conditions = ["institution_id = %s"]
        params = [institution_id]

        if search:
            s = f"%{search.strip()}%"
            conditions.append("(full_name LIKE %s OR email LIKE %s OR member_id LIKE %s)")
            params.extend([s, s, s])

        if department:
            conditions.append("department = %s")
            params.append(department.strip())

        if member_type:
            conditions.append("member_type = %s")
            params.append(member_type.strip().lower())

        if status:
            conditions.append("status = %s")
            params.append(status.strip().upper())

        where_clause = " WHERE " + " AND ".join(conditions)
        sql = (
            f"SELECT id, institution_id, member_id, full_name, email, department, member_type, status, created_at, updated_at "
            f"FROM organization_members {where_clause} ORDER BY id DESC LIMIT %s OFFSET %s"
        )
        params.extend([limit, offset])
        rows = fetch_all(sql, tuple(params))
        for r in rows:
            if isinstance(r, dict):
                r['identifier'] = r.get('member_id')
        return rows

    @classmethod
    def count_members(cls, institution_id: int, search: str = None,
                      department: str = None, member_type: str = None,
                      status: str = None) -> int:
        if not institution_id:
            return 0

        conditions = ["institution_id = %s"]
        params = [institution_id]

        if search:
            s = f"%{search.strip()}%"
            conditions.append("(full_name LIKE %s OR email LIKE %s OR member_id LIKE %s)")
            params.extend([s, s, s])

        if department:
            conditions.append("department = %s")
            params.append(department.strip())

        if member_type:
            conditions.append("member_type = %s")
            params.append(member_type.strip().lower())

        if status:
            conditions.append("status = %s")
            params.append(status.strip().upper())

        where_clause = " WHERE " + " AND ".join(conditions)
        row = fetch_one(f"SELECT COUNT(*) as cnt FROM organization_members {where_clause}", tuple(params))
        return row['cnt'] if isinstance(row, dict) else (row[0] if row else 0)

    @classmethod
    def update_member(cls, member_pk: int, institution_id: int, **fields) -> bool:
        if not member_pk or not institution_id:
            return False

        if 'identifier' in fields and 'member_id' not in fields:
            fields['member_id'] = fields.pop('identifier')

        allowed = {'full_name', 'email', 'member_id', 'department', 'member_type', 'status'}
        updates = []
        params = []

        for k, v in fields.items():
            if k in allowed and v is not None:
                if k == 'email':
                    v = cls.normalize_email(v)
                    if not cls.validate_email(v):
                        raise ValueError(f"Invalid email: '{v}'")
                    # Check duplicate
                    dup = fetch_one(
                        "SELECT id FROM organization_members WHERE institution_id = %s AND email = %s AND id != %s",
                        (institution_id, v, member_pk)
                    )
                    if dup:
                        raise ValueError(f"Email '{v}' is already used by another member.")
                elif k == 'full_name':
                    v = str(v).strip()
                    if not v:
                        raise ValueError("Full name cannot be empty.")
                elif k == 'status':
                    v = str(v).strip().upper()
                elif k == 'member_type':
                    v = str(v).strip().lower()
                else:
                    v = str(v).strip() or None

                updates.append(f"{k} = %s")
                params.append(v)

        if not updates:
            return False

        params.extend([member_pk, institution_id])
        sql = f"UPDATE organization_members SET {', '.join(updates)}, updated_at = CURRENT_TIMESTAMP WHERE id = %s AND institution_id = %s"
        return execute_query(sql, tuple(params)) > 0

    @classmethod
    def delete_member(cls, member_pk: int, institution_id: int) -> bool:
        if not member_pk or not institution_id:
            return False
        return execute_query(
            "DELETE FROM organization_members WHERE id = %s AND institution_id = %s",
            (member_pk, institution_id)
        ) > 0

    @classmethod
    def import_csv(cls, institution_id: int, file_stream_or_text) -> dict:
        """
        Parses a CSV file and inserts/updates members for the institution.
        Accepts io.StringIO, file stream, or string.
        Returns: { 'imported': int, 'updated': int, 'errors': list[str], 'total_rows': int }
        """
        if not institution_id:
            raise ValueError("Institution ID is required for member CSV import.")

        if isinstance(file_stream_or_text, str):
            stream = io.StringIO(file_stream_or_text)
        elif hasattr(file_stream_or_text, 'read'):
            raw = file_stream_or_text.read()
            if isinstance(raw, bytes):
                raw = raw.decode('utf-8', errors='replace')
            stream = io.StringIO(raw)
        else:
            raise ValueError("Invalid CSV stream or text provided.")

        reader = csv.DictReader(stream)
        if not reader.fieldnames:
            return {'imported': 0, 'updated': 0, 'errors': ["CSV is empty or missing headers."], 'total_rows': 0}

        # Normalize header keys
        header_map = {}
        for h in reader.fieldnames:
            clean_h = (h or '').strip().lower().replace(' ', '_').replace('-', '_')
            if clean_h in ('name', 'full_name', 'member_name', 'student_name', 'employee_name'):
                header_map['full_name'] = h
            elif clean_h in ('email', 'email_address', 'mail'):
                header_map['email'] = h
            elif clean_h in ('id', 'member_id', 'student_id', 'employee_id', 'roll_no', 'emp_id'):
                header_map['member_id'] = h
            elif clean_h in ('department', 'dept', 'division', 'branch'):
                header_map['department'] = h
            elif clean_h in ('role', 'type', 'member_type', 'category'):
                header_map['member_type'] = h
            elif clean_h in ('status', 'state'):
                header_map['status'] = h

        if 'email' not in header_map or 'full_name' not in header_map:
            return {
                'imported': 0,
                'updated': 0,
                'errors': [f"CSV must contain 'name' and 'email' columns. Found columns: {list(reader.fieldnames)}"],
                'total_rows': 0
            }

        imported_count = 0
        updated_count = 0
        errors = []
        row_num = 1

        for row in reader:
            row_num += 1
            raw_name = row.get(header_map.get('full_name', ''), '').strip()
            raw_email = row.get(header_map.get('email', ''), '').strip()
            raw_mid = row.get(header_map.get('member_id', ''), '').strip() or None
            raw_dept = row.get(header_map.get('department', ''), '').strip() or None
            raw_type = row.get(header_map.get('member_type', ''), '').strip().lower() or 'member'
            raw_status = row.get(header_map.get('status', ''), '').strip().upper() or 'ACTIVE'

            if not raw_name:
                errors.append(f"Row {row_num}: Name is required.")
                continue

            clean_email = cls.normalize_email(raw_email)
            if not cls.validate_email(clean_email):
                errors.append(f"Row {row_num}: Invalid email '{raw_email}'.")
                continue

            existing = cls.get_by_email(clean_email, institution_id)
            if existing:
                try:
                    cls.update_member(
                        existing['id'],
                        institution_id,
                        full_name=raw_name,
                        member_id=raw_mid or existing.get('member_id'),
                        department=raw_dept or existing.get('department'),
                        member_type=raw_type,
                        status=raw_status
                    )
                    updated_count += 1
                except Exception as ex:
                    errors.append(f"Row {row_num} ({clean_email}): {str(ex)}")
            else:
                try:
                    cls.add_member(
                        institution_id=institution_id,
                        full_name=raw_name,
                        email=clean_email,
                        member_id=raw_mid,
                        department=raw_dept,
                        member_type=raw_type,
                        status=raw_status
                    )
                    imported_count += 1
                except Exception as ex:
                    errors.append(f"Row {row_num} ({clean_email}): {str(ex)}")

        return {
            'imported': imported_count,
            'updated': updated_count,
            'errors': errors[:50],  # cap returned errors
            'total_rows': row_num - 1
        }
