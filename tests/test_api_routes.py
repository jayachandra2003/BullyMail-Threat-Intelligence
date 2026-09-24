import pytest

def test_home_page(client):
    res = client.get('/')
    assert res.status_code == 200

def test_dashboard_unauthorized(client):
    res = client.get('/dashboard')
    # Should redirect to login
    assert res.status_code == 302

def test_dashboard_authorized(auth_client):
    res = auth_client.get('/dashboard')
    assert res.status_code == 200

def test_quick_demo_analyze_api(client):
    res = client.post('/api/quick-demo-analyze', json={
        'email_text': 'You are useless and should drop out immediately.'
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert data['result']['bullying_analysis']['is_bullying'] is True

def test_quick_demo_analyze_profane_abuse_api(client):
    res = client.post('/api/quick-demo-analyze', json={
        'email_text': 'motherfucker'
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert data['result']['bullying_analysis']['is_bullying'] is True
    assert data['result']['overall_risk_level'] in ('HIGH', 'CRITICAL')

def test_authenticated_analyze_email_api(auth_client):
    res = auth_client.post('/api/analyze-email', json={
        'email_text': 'Please review the lecture notes posted on the portal.',
        'email_subject': 'Lecture Slides'
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'report' in data

def test_authenticated_analyze_idiot_sample_api(auth_client):
    res = auth_client.post('/api/analyze-email', json={
        'email_subject': 'Your Unacceptable Performance',
        'email_from': 'advisor@university.edu',
        'email_text': 'idiot'
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    report = data['report']
    assert report['bullying_analysis']['is_bullying'] is True
    assert report['bullying_analysis']['severity'] == 'MEDIUM'
    assert report['overall_risk_level'] == 'MEDIUM'
    assert len(report['evidence']) >= 1
    assert report['evidence'][0]['title'] == 'Targeted Personal Insult Detected'

def test_system_stats_api(auth_client):
    res = auth_client.get('/api/system-stats')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'stats' in data

def test_favicon_route(client):
    res = client.get('/favicon.ico')
    assert res.status_code == 200
    assert 'svg' in res.content_type

def test_health_route(client):
    res = client.get('/health')
    assert res.status_code == 200
    data = res.get_json()
    assert data['status'] == 'ok'
    assert 'BullyMail' in data['service']

def test_robots_txt_route(client):
    res = client.get('/robots.txt')
    assert res.status_code == 200
    assert 'text/plain' in res.content_type
    assert b'Disallow: /api/' in res.data

def test_sitemap_xml_route(client):
    res = client.get('/sitemap.xml')
    assert res.status_code == 200
    assert 'application/xml' in res.content_type
    assert b'<urlset' in res.data

def test_privacy_policy_route(client):
    res = client.get('/privacy')
    assert res.status_code == 200
    assert b'Privacy Policy' in res.data

def test_terms_conditions_route(client):
    res = client.get('/terms')
    assert res.status_code == 200
    assert b'Terms &amp; Conditions' in res.data or b'Terms & Conditions' in res.data

def test_custom_404_template_route(client):
    res = client.get('/non-existent-page-path-123')
    assert res.status_code == 404
    assert b'Target Resource Not Found' in res.data

def test_index_page_seo_and_social_tags(client):
    res = client.get('/')
    assert res.status_code == 200
    assert b'meta name="twitter:card"' in res.data
    assert b'meta property="og:title"' in res.data


