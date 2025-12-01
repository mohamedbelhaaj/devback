import re
import pytest
from playwright.sync_api import Page, expect
from datetime import datetime, timedelta

def test_create_task(page: Page, admin_user, threat_report):
    """Test creating a task from a report"""
    # Login as admin
    page.goto('/accounts/login/')
    page.fill('#id_username', admin_user.username)
    page.fill('#id_password', 'testpassword123')
    page.click('button[type="submit"]')
    
    # Go to report detail
    page.goto(f'/reports/{threat_report.id}/')
    
    # Click create task button
    page.click('#create-task-btn')
    
    # Fill task form
    page.fill('#id_title', 'Investigate IP further')
    page.fill('#id_description', 'Perform deep investigation on this IP address')
    page.select_option('#id_priority', 'high')
    
    # Set due date (tomorrow)
    tomorrow = (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d')
    page.fill('#id_due_date', tomorrow)
    
    # Assign to analyst
    page.select_option('#id_assigned_to', 'analyst_test')
    
    page.click('#save-task-btn')
    
    # Verify task created
    expect(page.locator('.alert-success')).to_contain_text('Task created')
    expect(page.locator('.task-title')).to_contain_text('Investigate IP further')
    expect(page.locator('.task-priority')).to_contain_text('High')

def test_task_list_view(page: Page, analyst_user):
    """Test viewing and filtering tasks"""
    # Login
    page.goto('/accounts/login/')
    page.fill('#id_username', analyst_user.username)
    page.fill('#id_password', 'testpassword123')
    page.click('button[type="submit"]')
    
    # Navigate to tasks
    page.click('a[href="/tasks/"]')
    
    # Verify tasks table
    expect(page.locator('.tasks-table')).to_be_visible()
    
    # Filter by priority
    page.select_option('#priority-filter', 'high')
    page.click('#apply-task-filters')
    
    # Verify filtering
    expect(page).to_have_url(re.compile(r'priority=high'))
    
    # Search tasks
    page.fill('#task-search', 'investigation')
    page.click('#task-search-btn')
    
    expect(page.locator('.search-results')).to_be_visible()

def test_task_status_update(page: Page, analyst_user):
    """Test updating task status"""
    # Create a task assigned to analyst
    from vt_analyzer.models import Task
    task = Task.objects.create(
        title='Test Task',
        description='Test description',
        priority='medium',
        status='open',
        created_by=analyst_user,
        assigned_to=analyst_user
    )
    
    # Login
    page.goto('/accounts/login/')
    page.fill('#id_username', analyst_user.username)
    page.fill('#id_password', 'testpassword123')
    page.click('button[type="submit"]')
    
    page.goto(f'/tasks/{task.id}/')
    
    # Update status to in progress
    page.select_option('#status-select', 'in_progress')
    page.fill('#progress-notes', 'Starting investigation')
    page.click('#update-status-btn')
    
    # Verify update
    expect(page.locator('.alert-success')).to_contain_text('Status updated')
    expect(page.locator('.task-status')).to_contain_text('In Progress')
    expect(page.locator('.progress-notes')).to_contain_text('Starting investigation')
    
    # Mark as completed
    page.select_option('#status-select', 'completed')
    page.fill('#completion-notes', 'Task completed successfully')
    page.click('#update-status-btn')
    
    expect(page.locator('.task-status')).to_contain_text('Completed')
    expect(page.locator('.completed-at')).to_be_visible()

def test_task_dashboard(page: Page, analyst_user):
    """Test task dashboard widgets"""
    # Create tasks with different statuses
    from vt_analyzer.models import Task
    
    Task.objects.create(
        title='Urgent Task',
        description='Urgent investigation',
        priority='urgent',
        status='open',
        created_by=analyst_user,
        assigned_to=analyst_user
    )
    
    Task.objects.create(
        title='In Progress Task',
        description='Ongoing work',
        priority='high',
        status='in_progress',
        created_by=analyst_user,
        assigned_to=analyst_user
    )
    
    # Login
    page.goto('/accounts/login/')
    page.fill('#id_username', analyst_user.username)
    page.fill('#id_password', 'testpassword123')
    page.click('button[type="submit"]')
    
    # Go to dashboard
    page.goto('/dashboard/')
    
    # Verify task widgets
    expect(page.locator('.task-stats-widget')).to_be_visible()
    expect(page.locator('.urgent-tasks')).to_contain_text('1')
    expect(page.locator('.in-progress-tasks')).to_contain_text('1')
    
    # Verify recent tasks list
    expect(page.locator('.recent-tasks')).to_be_visible()
    expect(page.locator('.recent-tasks li')).to_have_count_at_least(2)