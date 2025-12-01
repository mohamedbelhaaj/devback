import pytest
from playwright.sync_api import Page, expect
import json

def test_report_detail_view(page: Page, analyst_user, threat_report):
    """Test viewing report details"""
    # Login
    page.goto('/accounts/login/')
    page.fill('#id_username', analyst_user.username)
    page.fill('#id_password', 'testpassword123')
    page.click('button[type="submit"]')
    
    # Navigate to report detail
    page.goto(f'/reports/{threat_report.id}/')
    
    # Verify all sections are present
    expect(page.locator('.report-header')).to_be_visible()
    expect(page.locator('.analysis-results')).to_be_visible()
    expect(page.locator('.threat-assessment')).to_be_visible()
    expect(page.locator('.report-metadata')).to_be_visible()
    
    # Verify report data
    expect(page.locator('.input-value')).to_contain_text(threat_report.input_value)
    expect(page.locator('.severity-badge')).to_contain_text(threat_report.severity.capitalize())
    expect(page.locator('.threat-score')).to_contain_text(str(threat_report.threat_score))

def test_report_status_update(page: Page, admin_user, threat_report):
    """Test updating report status"""
    # Login as admin
    page.goto('/accounts/login/')
    page.fill('#id_username', admin_user.username)
    page.fill('#id_password', 'testpassword123')
    page.click('button[type="submit"]')
    
    page.goto(f'/reports/{threat_report.id}/')
    
    # Update status
    page.select_option('#status-select', 'reviewed')
    page.fill('#admin-notes', 'Reviewed and confirmed malicious')
    page.click('#update-status-btn')
    
    # Verify update
    expect(page.locator('.alert-success')).to_contain_text('Status updated')
    expect(page.locator('.report-status')).to_contain_text('Reviewed')
    expect(page.locator('.admin-notes')).to_contain_text('Reviewed and confirmed')

def test_generate_pdf_report(page: Page, analyst_user, threat_report):
    """Test PDF report generation"""
    # Login
    page.goto('/accounts/login/')
    page.fill('#id_username', analyst_user.username)
    page.fill('#id_password', 'testpassword123')
    page.click('button[type="submit"]')
    
    page.goto(f'/reports/{threat_report.id}/')
    
    # Click generate PDF
    with page.expect_download() as download_info:
        page.click('#generate-pdf-btn')
    
    download = download_info.value
    expect(download.suggested_filename).to_contain('.pdf')
    
    # Verify success message
    expect(page.locator('.alert-success')).to_contain_text('PDF generated')

def test_virus_total_data_display(page: Page, analyst_user):
    """Test display of VirusTotal data"""
    # Create report with VT data
    vt_data = {
        'data': {
            'attributes': {
                'last_analysis_stats': {
                    'malicious': 25,
                    'suspicious': 10,
                    'undetected': 5,
                    'harmless': 60
                },
                'reputation': -10
            }
        }
    }
    
    report = ThreatReport.objects.create(
        analyst=analyst_user,
        input_type='ip',
        input_value='1.1.1.1',
        engine_used='vt',
        vt_data=vt_data,
        severity='critical',
        malicious_count=25,
        suspicious_count=10,
        threat_score=95.0
    )
    
    # Login and view report
    page.goto('/accounts/login/')
    page.fill('#id_username', analyst_user.username)
    page.fill('#id_password', 'testpassword123')
    page.click('button[type="submit"]')
    
    page.goto(f'/reports/{report.id}/')
    
    # Verify VT data display
    expect(page.locator('.vt-stats')).to_be_visible()
    expect(page.locator('.malicious-count')).to_contain_text('25')
    expect(page.locator('.suspicious-count')).to_contain_text('10')
    expect(page.locator('.reputation-score')).to_contain_text('-10')