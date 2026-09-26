import json
from flask import Blueprint, request, jsonify, Response
from ..models.member import OrganizationMemberModel
from ..models.institution import InstitutionModel
from .auth import require_role

members_bp = Blueprint('members', __name__)

def _resolve_member_inst_id(current_user, req_inst_id=None):
    """
    Enforces strict tenant isolation for member operations.
    Returns: (institution_id, error_tuple_or_None)
    """
    user_role = (current_user.get('role') or 'analyst').lower().strip()
    user_inst = current_user.get('institution_id')

    if user_role in ('platform_owner', 'super_admin'):
        if req_inst_id is not None:
            try:
                t_id = int(req_inst_id)
                inst = InstitutionModel.get_by_id(t_id)
                if not inst:
                    return None, ("Organization not found", 404)
                return t_id, None
            except (ValueError, TypeError):
                return None, ("Invalid organization ID", 400)
        return user_inst or 1, None

    if not user_inst:
        return None, ("Forbidden: Account is not associated with an approved organization", 403)

    user_inst = int(user_inst)
    if req_inst_id is not None:
        try:
            if int(req_inst_id) != user_inst:
                return None, ("Forbidden: Access to specified organization is denied", 403)
        except (ValueError, TypeError):
            return None, ("Invalid organization ID", 400)

    return user_inst, None

# =========================================================================
# 1. MEMBER CRUD & LISTING
# =========================================================================

@members_bp.route('/api/members', methods=['GET'])
@members_bp.route('/api/organizations/<int:org_id>/members', methods=['GET'])
@require_role('platform_owner', 'org_admin')
def list_members(current_user, org_id=None):
    """Lists members belonging strictly to current_user['institution_id']."""
    try:
        req_inst = org_id if org_id is not None else (request.args.get('organization_id') or request.args.get('institution_id'))
        inst_id, err = _resolve_member_inst_id(current_user, req_inst)
        if err:
            msg, code = err
            return jsonify({'success': False, 'error': msg}), code

        search = request.args.get('search')
        dept = request.args.get('department')
        m_type = request.args.get('member_type') or request.args.get('role')
        status = request.args.get('status')

        try:
            limit = min(max(1, int(request.args.get('limit', 50))), 200)
        except (ValueError, TypeError):
            limit = 50

        try:
            page = max(1, int(request.args.get('page', 1)))
        except (ValueError, TypeError):
            page = 1

        offset = (page - 1) * limit

        members = OrganizationMemberModel.list_members(
            institution_id=inst_id,
            search=search,
            department=dept,
            member_type=m_type,
            status=status,
            limit=limit,
            offset=offset
        )
        total = OrganizationMemberModel.count_members(
            institution_id=inst_id,
            search=search,
            department=dept,
            member_type=m_type,
            status=status
        )

        return jsonify({
            'success': True,
            'members': members,
            'total': total,
            'page': page,
            'limit': limit,
            'organization_id': inst_id,
            'institution_id': inst_id
        })
    except Exception as e:
        return jsonify({'success': False, 'error': f"Failed to list members: {e}"}), 500

@members_bp.route('/api/members', methods=['POST'])
@members_bp.route('/api/organizations/<int:org_id>/members', methods=['POST'])
@require_role('platform_owner', 'org_admin')
def add_member(current_user, org_id=None):
    """Adds a new member to the organization."""
    try:
        data = request.get_json(silent=True) or {}
        req_inst = org_id if org_id is not None else (data.get('organization_id') or data.get('institution_id') or request.args.get('organization_id') or request.args.get('institution_id'))
        inst_id, err = _resolve_member_inst_id(current_user, req_inst)
        if err:
            msg, code = err
            return jsonify({'success': False, 'error': msg}), code

        full_name = (data.get('name') or data.get('full_name') or '').strip()
        email = (data.get('email') or '').strip()
        member_id = data.get('member_id') or data.get('identifier')
        department = data.get('department')
        member_type = data.get('role') or data.get('member_type') or 'member'
        status = data.get('status', 'ACTIVE')

        if not full_name or not email:
            return jsonify({'success': False, 'error': 'Full name and email are required.'}), 400

        new_id = OrganizationMemberModel.add_member(
            institution_id=inst_id,
            full_name=full_name,
            email=email,
            member_id=member_id,
            department=department,
            member_type=member_type,
            status=status
        )
        return jsonify({
            'success': True,
            'message': 'Member added successfully.',
            'member_id': new_id,
            'id': new_id,
            'organization_id': inst_id,
            'institution_id': inst_id
        }), 201
    except ValueError as ve:
        return jsonify({'success': False, 'error': str(ve)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': f"Failed to add member: {e}"}), 500

@members_bp.route('/api/members/<int:member_id>', methods=['GET'])
@members_bp.route('/api/organizations/<int:org_id>/members/<int:member_id>', methods=['GET'])
@require_role('platform_owner', 'org_admin')
def get_member(current_user, member_id, org_id=None):
    """Retrieves a single member by ID (Tenant Scoped)."""
    try:
        req_inst = org_id if org_id is not None else request.args.get('institution_id')
        inst_id, err = _resolve_member_inst_id(current_user, req_inst)
        if err:
            msg, code = err
            return jsonify({'success': False, 'error': msg}), code

        member = OrganizationMemberModel.get_by_id(member_id, institution_id=inst_id)
        if not member:
            return jsonify({'success': False, 'error': 'Member not found.'}), 404

        return jsonify({'success': True, 'member': member})
    except Exception as e:
        return jsonify({'success': False, 'error': f"Failed to retrieve member: {e}"}), 500

@members_bp.route('/api/members/<int:member_id>', methods=['PUT'])
@members_bp.route('/api/organizations/<int:org_id>/members/<int:member_id>', methods=['PUT'])
@require_role('platform_owner', 'org_admin')
def update_member(current_user, member_id, org_id=None):
    """Updates member details (Tenant Scoped)."""
    try:
        data = request.get_json(silent=True) or {}
        req_inst = org_id if org_id is not None else data.get('institution_id')
        inst_id, err = _resolve_member_inst_id(current_user, req_inst)
        if err:
            msg, code = err
            return jsonify({'success': False, 'error': msg}), code

        # Check existing
        existing = OrganizationMemberModel.get_by_id(member_id, institution_id=inst_id)
        if not existing:
            return jsonify({'success': False, 'error': 'Member not found.'}), 404

        full_name = data.get('name') or data.get('full_name')
        member_type = data.get('role') or data.get('member_type')
        clean_mid = data.get('identifier') or data.get('member_id')

        success = OrganizationMemberModel.update_member(
            member_id,
            inst_id,
            full_name=full_name,
            email=data.get('email'),
            member_id=clean_mid,
            department=data.get('department'),
            member_type=member_type,
            status=data.get('status')
        )
        return jsonify({'success': success, 'message': 'Member updated successfully.' if success else 'No changes applied.'})
    except ValueError as ve:
        return jsonify({'success': False, 'error': str(ve)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': f"Failed to update member: {e}"}), 500

@members_bp.route('/api/members/<int:member_id>', methods=['DELETE'])
@members_bp.route('/api/organizations/<int:org_id>/members/<int:member_id>', methods=['DELETE'])
@require_role('platform_owner', 'org_admin')
def delete_member(current_user, member_id, org_id=None):
    """Deletes a member from the organization (Tenant Scoped)."""
    try:
        req_inst = org_id if org_id is not None else request.args.get('institution_id')
        inst_id, err = _resolve_member_inst_id(current_user, req_inst)
        if err:
            msg, code = err
            return jsonify({'success': False, 'error': msg}), code

        existing = OrganizationMemberModel.get_by_id(member_id, institution_id=inst_id)
        if not existing:
            return jsonify({'success': False, 'error': 'Member not found.'}), 404

        success = OrganizationMemberModel.delete_member(member_id, inst_id)
        return jsonify({'success': success, 'message': 'Member deleted successfully.' if success else 'Failed to delete member.'})
    except Exception as e:
        return jsonify({'success': False, 'error': f"Failed to delete member: {e}"}), 500

# =========================================================================
# 2. BATCH CSV IMPORT & TEMPLATE
# =========================================================================

@members_bp.route('/api/members/import-csv', methods=['POST'])
@require_role('platform_owner', 'org_admin')
def import_members_csv(current_user):
    """Bulk imports members via CSV file upload (Tenant Scoped)."""
    try:
        req_inst = request.form.get('institution_id') or request.args.get('institution_id')
        inst_id, err = _resolve_member_inst_id(current_user, req_inst)
        if err:
            msg, code = err
            return jsonify({'success': False, 'error': msg}), code

        if 'file' in request.files:
            uploaded_file = request.files['file']
            if not uploaded_file.filename:
                return jsonify({'success': False, 'error': 'No file selected.'}), 400
            result = OrganizationMemberModel.import_csv(inst_id, uploaded_file)
        elif request.data:
            result = OrganizationMemberModel.import_csv(inst_id, request.data.decode('utf-8', errors='replace'))
        else:
            return jsonify({'success': False, 'error': 'CSV file or content is required.'}), 400

        return jsonify({
            'success': True,
            'message': f"Imported {result['imported']} members, updated {result['updated']} existing records.",
            **result
        })
    except ValueError as ve:
        return jsonify({'success': False, 'error': str(ve)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': f"CSV import error: {e}"}), 500

@members_bp.route('/api/members/template-csv', methods=['GET'])
@require_role('platform_owner', 'org_admin')
def download_member_template(current_user):
    """Returns downloadable sample CSV template for bulk member onboarding."""
    sample_csv = (
        "full_name,email,member_type,department,identifier\r\n"
        "\"Alex Rivera\",\"alex.rivera@example.edu\",\"student\",\"Computer Science\",\"STU-1001\"\r\n"
        "\"Dr. Sarah Chen\",\"sarah.chen@example.edu\",\"faculty\",\"Information Security\",\"FAC-2001\"\r\n"
        "\"Marcus Vance\",\"marcus.vance@example.edu\",\"staff\",\"Administration\",\"EMP-3001\"\r\n"
    )
    return Response(
        sample_csv,
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment;filename=bullymail_members_template.csv'}
    )

# =========================================================================
# 3. ORGANIZATION SETTINGS & METADATA
# =========================================================================

@members_bp.route('/api/org/settings', methods=['GET'])
@require_role('platform_owner', 'org_admin')
def get_org_settings(current_user):
    """Retrieves organization profile and settings (Tenant Scoped)."""
    try:
        req_inst = request.args.get('institution_id')
        inst_id, err = _resolve_member_inst_id(current_user, req_inst)
        if err:
            msg, code = err
            return jsonify({'success': False, 'error': msg}), code

        org = InstitutionModel.get_by_id(inst_id)
        if not org:
            return jsonify({'success': False, 'error': 'Organization not found.'}), 404

        settings_dict = {}
        if org.get('settings'):
            try:
                settings_dict = json.loads(org['settings']) if isinstance(org['settings'], str) else org['settings']
            except Exception:
                settings_dict = {}

        return jsonify({
            'success': True,
            'organization': {
                'id': org['id'],
                'name': org['name'],
                'domain': org['domain'],
                'code': org.get('code'),
                'status': org.get('status'),
                'org_type': org.get('org_type', 'university'),
                'contact_name': org.get('contact_name'),
                'contact_email': org.get('contact_email'),
                'settings': settings_dict,
                'created_at': str(org.get('created_at')) if org.get('created_at') else None
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': f"Failed to retrieve organization settings: {e}"}), 500

@members_bp.route('/api/org/settings', methods=['PUT', 'POST'])
@require_role('platform_owner', 'org_admin')
def update_org_settings(current_user):
    """Updates organization profile and settings (Tenant Scoped)."""
    try:
        data = request.get_json() or {}
        req_inst = data.get('institution_id') or request.args.get('institution_id')
        inst_id, err = _resolve_member_inst_id(current_user, req_inst)
        if err:
            msg, code = err
            return jsonify({'success': False, 'error': msg}), code

        name = data.get('name')
        org_type = data.get('org_type')
        contact_name = data.get('contact_name')
        contact_email = data.get('contact_email')
        settings = data.get('settings')

        if name or org_type or contact_name is not None or contact_email is not None:
            InstitutionModel.update_institution(
                inst_id=inst_id,
                name=name,
                org_type=org_type,
                contact_name=contact_name,
                contact_email=contact_email
            )

        if settings is not None:
            InstitutionModel.update_settings(inst_id, settings)

        return jsonify({'success': True, 'message': 'Organization settings updated successfully.'})
    except Exception as e:
        return jsonify({'success': False, 'error': f"Failed to update organization settings: {e}"}), 500
