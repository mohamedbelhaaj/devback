import pytest
from playwright.sync_api import Page, expect

def test_aws_configuration_creation(page: Page, admin_user):
    """Test creating AWS configuration"""
    # Login as admin
    page.goto('/accounts/login/')
    page.fill('#id_username', admin_user.username)
    page.fill('#id_password', 'testpassword123')
    page.click('button[type="submit"]')
    
    # Navigate to AWS config
    page.click('a[href="/aws/config/create/"]')
    
    # Fill configuration form
    page.fill('#id_name', 'Production AWS Config')
    page.fill('#id_aws_access_key', 'AKIAIOSFODNN7EXAMPLE')
    page.fill('#id_aws_secret_key', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')
    page.select_option('#id_aws_region', 'us-east-1')
    page.fill('#id_vpc_id', 'vpc-12345678')
    page.fill('#id_security_group_id', 'sg-12345678')
    
    # Enable auto-block
    page.check('#id_auto_block_enabled')
    page.fill('#id_auto_block_threshold', '15')
    
    page.click('#save-config-btn')
    
    # Verify success
    expect(page.locator('.alert-success')).to_contain_text('Configuration saved')
    expect(page.locator('.config-name')).to_contain_text('Production AWS Config')

def test_aws_config_test_connection(page: Page, admin_user, aws_configuration):
    """Test AWS connection testing"""
    # Login as admin
    page.goto('/accounts/login/')
    page.fill('#id_username', admin_user.username)
    page.fill('#id_password', 'testpassword123')
    page.click('button[type="submit"]')
    
    page.goto(f'/aws/config/{aws_configuration.id}/')
    
    # Test connection
    page.click('#test-connection-btn')
    
    # Verify connection result
    expect(page.locator('.connection-status')).to_be_visible()
    # Note: This might show error with dummy credentials, but we're testing UI flow

def test_aws_academy_session_token(page: Page, admin_user):
    """Test AWS Academy session token configuration"""
    # Login as admin
    page.goto('/accounts/login/')
    page.fill('#id_username', admin_user.username)
    page.fill('#id_password', 'testpassword123')
    page.click('button[type="submit"]')
    
    page.click('a[href="/aws/config/create/"]')
    
    # Fill with session token
    page.fill('#id_name', 'AWS Academy Config')
    page.fill('#id_aws_access_key', 'ASIAIOSFODNN7EXAMPLE')
    page.fill('#id_aws_secret_key', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')
    page.fill('#id_aws_session_token', 'VeryLongSessionTokenString' * 50)
    page.select_option('#id_aws_region', 'us-east-1')
    
    page.click('#save-config-btn')
    
    expect(page.locator('.alert-success')).to_be_visible()
    expect(page.locator('.session-token-indicator')).to_contain_text('Using Session Token')