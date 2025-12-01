import pytest
from playwright.sync_api import Page, expect

def test_create_mitigation_action(page: Page, admin_user, threat_report):
    """Test creating a mitigation action"""
    # Login as admin
    page.goto('/accounts/login/')
    page.fill('#id_username', admin_user.username)
    page.fill('#id_password', 'testpassword123')
    page.click('button[type="submit"]')
    
    # Go to report detail
    page.goto(f'/reports/{threat_report.id}/')
    
    # Click mitigation tab
    page.click('#mitigation-tab')
    
    # Create new action
    page.click('#new-mitigation-btn')
    
    # Fill action form
    page.select_option('#id_action_type', 'block_ip')
    page.fill('#id_target_value', threat_report.input_value)
    page.select_option('#id_aws_region', 'us-east-1')
    page.fill('#id_description', 'Block malicious IP in security group')
    
    page.click('#submit-action-btn')
    
    # Verify action created
    expect(page.locator('.alert-success')).to_contain_text('Mitigation action created')
    expect(page.locator('.actions-table')).to_contain_text('block_ip')
    expect(page.locator('.actions-table')).to_contain_text('pending')

def test_mitigation_action_status_update(page: Page, admin_user):
    """Test updating mitigation action status"""
    # Create action first
    report = ThreatReport.objects.create(
        analyst=admin_user,
        input_type='ip',
        input_value='10.0.0.100',
        engine_used='vt',
        severity='high'
    )
    
    action = MitigationAction.objects.create(
        report=report,
        action_type='block_ip',
        target_value='10.0.0.100',
        initiated_by=admin_user,
        description='Test action',
        status='in_progress'
    )
    
    # Login as admin
    page.goto('/accounts/login/')
    page.fill('#id_username', admin_user.username)
    page.fill('#id_password', 'testpassword123')
    page.click('button[type="submit"]')
    
    # Navigate to actions list
    page.goto('/mitigation/actions/')
    
    # Update status
    page.locator(f'#action-{action.id} .status-dropdown').select_option('completed')
    page.locator(f'#action-{action.id} .update-status-btn').click()
    
    # Verify update
    expect(page.locator('.alert-success')).to_be_visible()
    expect(page.locator(f'#action-{action.id} .status-badge')).to_contain_text('completed')

def test_auto_mitigation_trigger(page: Page, admin_user, aws_configuration):
    """Test auto-mitigation for high severity reports"""
    # Create critical report
    report = ThreatReport.objects.create(
        analyst=admin_user,
        input_type='ip',
        input_value='192.168.100.1',
        engine_used='vt',
        severity='critical',
        malicious_count=20,
        threat_score=95.0,
        status='pending'
    )
    
    # Login as admin
    page.goto('/accounts/login/')
    page.fill('#id_username', admin_user.username)
    page.fill('#id_password', 'testpassword123')
    page.click('button[type="submit"]')
    
    page.goto(f'/reports/{report.id}/')
    
    # Check if auto-mitigation suggestion appears
    expect(page.locator('.auto-mitigation-alert')).to_be_visible()
    expect(page.locator('.auto-mitigation-alert')).to_contain_text('Auto-mitigation available')
    
    # Click auto-mitigate button
    page.click('#auto-mitigate-btn')
    
    # Confirm in modal
    page.click('#confirm-mitigation-modal .btn-primary')
    
    # Verify action created
    expect(page.locator('.alert-success')).to_contain_text('Auto-mitigation initiated')
    expect(page.locator('.mitigation-history')).to_contain_text('block_ip')