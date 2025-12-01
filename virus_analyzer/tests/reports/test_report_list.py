import pytest
from playwright.sync_api import Page, expect

def test_report_list_view(page: Page, analyst_user, threat_report):
    """Test viewing list of threat reports"""
    # Login
    page.goto('/accounts/login/')
    page.fill('#id_username', analyst_user.username)
    page.fill('#id_password', 'testpassword123')
    page.click('button[type="submit"]')
    
    # Navigate to reports list
    page.click('a[href="/reports/"]')
    
    # Verify reports table
    expect(page.locator('.reports-table')).to_be_visible()
    expect(page.locator('table tbody tr')).to_have_count_at_least(1)
    
    # Verify report data
    expect(page.locator('table')).to_contain_text(threat_report.input_value)
    expect(page.locator('table')).to_contain_text(threat_report.severity.capitalize())
    expect(page.locator('table')).to_contain_text(threat_report.status.capitalize())

def test_report_filtering(page: Page, analyst_user):
    """Test filtering reports by severity and status"""
    # Login
    page.goto('/accounts/login/')
    page.fill('#id_username', analyst_user.username)
    page.fill('#id_password', 'testpassword123')
    page.click('button[type="submit"]')
    
    page.goto('/reports/')
    
    # Filter by high severity
    page.select_option('#severity-filter', 'high')
    page.click('#apply-filters-btn')
    
    # Verify URL contains filter parameter
    expect(page).to_have_url(re.compile(r'severity=high'))
    
    # Verify only high severity reports shown
    severity_cells = page.locator('.severity-cell')
    for i in range(severity_cells.count()):
        expect(severity_cells.nth(i)).to_contain_text('High')

def test_report_search(page: Page, analyst_user, threat_report):
    """Test searching reports"""
    # Login
    page.goto('/accounts/login/')
    page.fill('#id_username', analyst_user.username)
    page.fill('#id_password', 'testpassword123')
    page.click('button[type="submit"]')
    
    page.goto('/reports/')
    
    # Search by IP address
    page.fill('#search-input', threat_report.input_value)
    page.click('#search-btn')
    
    # Verify search results
    expect(page.locator('table')).to_contain_text(threat_report.input_value)
    expect(page.locator('.search-results-count')).to_contain_text('1 result')

def test_report_pagination(page: Page, analyst_user):
    """Test report list pagination"""
    # Create multiple reports
    for i in range(15):
        ThreatReport.objects.create(
            analyst=analyst_user,
            input_type='ip',
            input_value=f'10.0.0.{i}',
            engine_used='vt',
            severity='medium',
            status='pending'
        )
    
    # Login
    page.goto('/accounts/login/')
    page.fill('#id_username', analyst_user.username)
    page.fill('#id_password', 'testpassword123')
    page.click('button[type="submit"]')
    
    page.goto('/reports/?page_size=10')
    
    # Verify pagination controls
    expect(page.locator('.pagination')).to_be_visible()
    expect(page.locator('.page-link')).to_have_count_at_least(3)
    
    # Test next page
    page.click('.pagination .next-page')
    expect(page).to_have_url(re.compile(r'page=2'))
    expect(page.locator('table tbody tr')).to_have_count(5)  # 15 total, 10 per page