import pytest
from playwright.sync_api import Page, expect

def test_notification_bell(page: Page, analyst_user):
    """Test notification bell and dropdown"""
    # Create some notifications
    from vt_analyzer.models import Notification, ThreatReport
    
    report = ThreatReport.objects.create(
        analyst=analyst_user,
        input_type='ip',
        input_value='10.0.1.1',
        engine_used='vt',
        severity='high'
    )
    
    Notification.objects.create(
        recipient=analyst_user,
        notification_type='new_report',
        title='New Report Created',
        message='A new threat report has been created',
        report=report
    )
    
    # Login
    page.goto('/accounts/login/')
    page.fill('#id_username', analyst_user.username)
    page.fill('#id_password', 'testpassword123')
    page.click('button[type="submit"]')
    
    # Check notification bell
    expect(page.locator('.notification-bell')).to_be_visible()
    expect(page.locator('.notification-count')).to_contain_text('1')
    
    # Click bell
    page.click('.notification-bell')
    
    # Verify dropdown shows notification
    expect(page.locator('.notification-dropdown')).to_be_visible()
    expect(page.locator('.notification-item')).to_contain_text('New Report Created')
    
    # Mark as read
    page.click('.notification-item .mark-read-btn')
    
    # Verify count updates
    expect(page.locator('.notification-count')).not_to_be_visible()