import pytest
from playwright.sync_api import Page, expect

def test_successful_login(page: Page, analyst_user):
    """Test successful login with valid credentials"""
    page.goto('/accounts/login/')
    
    # Fill login form
    page.fill('#id_username', analyst_user.username)
    page.fill('#id_password', 'testpassword123')
    page.click('button[type="submit"]')
    
    # Verify redirection to dashboard
    expect(page).to_have_url('/dashboard/')
    expect(page.locator('.user-greeting')).to_contain_text(f'Welcome, {analyst_user.username}')

def test_login_with_invalid_credentials(page: Page):
    """Test login with invalid credentials"""
    page.goto('/accounts/login/')
    
    page.fill('#id_username', 'nonexistent')
    page.fill('#id_password', 'wrongpassword')
    page.click('button[type="submit"]')
    
    # Verify error message
    expect(page.locator('.alert-danger')).to_contain_text('Invalid username or password')
    expect(page).to_have_url('/accounts/login/')

def test_logout(page: Page, analyst_user):
    """Test logout functionality"""
    # Login first
    page.goto('/accounts/login/')
    page.fill('#id_username', analyst_user.username)
    page.fill('#id_password', 'testpassword123')
    page.click('button[type="submit"]')
    
    # Click logout
    page.click('#logout-btn')
    
    # Verify redirected to login page
    expect(page).to_have_url('/accounts/login/')
    expect(page.locator('.alert-info')).to_contain_text('You have been logged out')