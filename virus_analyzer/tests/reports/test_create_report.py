import pytest
from playwright.sync_api import Page, expect
import time

def test_create_ip_report(page: Page, analyst_user):
    """Test creating a new IP threat report"""
    # Login
    page.goto('/accounts/login/')
    page.fill('#id_username', analyst_user.username)
    page.fill('#id_password', 'testpassword123')
    page.click('button[type="submit"]')
    
    # Navigate to create report
    page.click('a[href="/reports/create/"]')
    
    # Fill report form
    page.select_option('#id_input_type', 'ip')
    page.fill('#id_input_value', '8.8.8.8')
    page.select_option('#id_engine_used', 'vt')
    page.fill('#id_notes', 'Testing Google DNS IP')
    
    # Submit form
    page.click('#submit-report-btn')
    
    # Verify success message and redirection
    expect(page.locator('.alert-success')).to_contain_text('Report created successfully')
    expect(page).to_have_url(re.compile(r'/reports/\w+/'))
    
    # Verify report details
    expect(page.locator('.report-type')).to_contain_text('IP Address')
    expect(page.locator('.report-value')).to_contain_text('8.8.8.8')

def test_create_url_report_with_file(page: Page, analyst_user):
    """Test creating a URL report with file upload"""
    # Login
    page.goto('/accounts/login/')
    page.fill('#id_username', analyst_user.username)
    page.fill('#id_password', 'testpassword123')
    page.click('button[type="submit"]')
    
    page.click('a[href="/reports/create/"]')
    
    # Select URL type
    page.select_option('#id_input_type', 'url')
    page.fill('#id_input_value', 'https://malicious-test.com/path')
    
    # Upload file
    page.set_input_files('#id_file_upload', 'tests/fixtures/test_file.txt')
    
    page.fill('#id_notes', 'Suspicious URL with file evidence')
    page.click('#submit-report-btn')
    
    expect(page.locator('.alert-success')).to_be_visible()

def test_report_validation_errors(page: Page, analyst_user):
    """Test form validation errors"""
    # Login
    page.goto('/accounts/login/')
    page.fill('#id_username', analyst_user.username)
    page.fill('#id_password', 'testpassword123')
    page.click('button[type="submit"]')
    
    page.click('a[href="/reports/create/"]')
    
    # Submit empty form
    page.click('#submit-report-btn')
    
    # Verify validation errors
    expect(page.locator('.errorlist')).to_contain_text('This field is required')
    expect(page.locator('#id_input_type + .invalid-feedback')).to_be_visible()  