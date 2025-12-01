import pytest
from playwright.sync_api import Page, expect

def test_csv_export(page: Page, admin_user):
    """Test CSV export functionality"""
    # Create some reports
    from vt_analyzer.models import ThreatReport, ThreatIntelligenceLog
    
    for i in range(5):
        report = ThreatReport.objects.create(
            analyst=admin_user,
            input_type='ip',
            input_value=f'192.168.{i}.1',
            engine_used='vt',
            severity='medium',
            threat_score=50.0 + i
        )
        
        ThreatIntelligenceLog.objects.create(
            report=report,
            indicator=report.input_value,
            indicator_type=report.input_type,
            threat_score=report.threat_score,
            severity=report.severity,
            malicious_count=report.malicious_count,
            suspicious_count=report.suspicious_count,
            analyst=admin_user.username
        )
    
    # Login as admin
    page.goto('/accounts/login/')
    page.fill('#id_username', admin_user.username)
    page.fill('#id_password', 'testpassword123')
    page.click('button[type="submit"]')
    
    # Navigate to export page
    page.goto('/export/csv/')
    
    # Set date range
    page.fill('#start_date', '2024-01-01')
    page.fill('#end_date', '2024-12-31')
    
    # Select export type
    page.select_option('#export_type', 'threat_intelligence')
    
    # Export CSV
    with page.expect_download() as download_info:
        page.click('#export-csv-btn')
    
    download = download_info.value
    expect(download.suggested_filename).to_contain('.csv')
    
    # Verify success message
    expect(page.locator('.alert-success')).to_contain_text('CSV exported successfully')