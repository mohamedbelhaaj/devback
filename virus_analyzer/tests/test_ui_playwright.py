import pytest
from playwright.sync_api import Page, expect
from django.contrib.auth import get_user_model
from django.test import LiveServerTestCase
from vt_analyzer.models import ThreatReport, Task, Notification

User = get_user_model()


class PlaywrightTestCase(LiveServerTestCase):
    """Base class for Playwright tests with Django LiveServer"""
    
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.live_server_url = cls.live_server_url
    
    def setUp(self):
        """Create test users"""
        self.analyst = User.objects.create_user(
            username='analyst_test',
            email='analyst@test.com',
            password='testpass123',
            role='analyst'
        )
        
        self.admin = User.objects.create_user(
            username='admin_test',
            email='admin@test.com',
            password='testpass123',
            role='admin'
        )


class TestAuthentication(PlaywrightTestCase):
    """Tests for authentication flows"""
    
    def test_login_success(self, page: Page):
        """Test successful login as analyst"""
        # Navigate to login page
        page.goto(f"{self.live_server_url}/login/")
        
        # Fill login form
        page.fill('input[name="username"]', 'analyst_test')
        page.fill('input[name="password"]', 'testpass123')
        
        # Click login button
        page.click('button[type="submit"]')
        
        # Verify redirect to dashboard
        expect(page).to_have_url(f"{self.live_server_url}/dashboard/")
        
        # Verify welcome message
        expect(page.locator('text=Welcome, analyst_test')).to_be_visible()
    
    def test_login_invalid_credentials(self, page: Page):
        """Test login with invalid credentials"""
        page.goto(f"{self.live_server_url}/login/")
        
        page.fill('input[name="username"]', 'wrong_user')
        page.fill('input[name="password"]', 'wrong_pass')
        page.click('button[type="submit"]')
        
        # Verify error message
        expect(page.locator('text=Invalid credentials')).to_be_visible()
    
    def test_logout(self, page: Page):
        """Test logout functionality"""
        # Login first
        self._login(page, 'analyst_test', 'testpass123')
        
        # Click logout
        page.click('a[href="/logout/"]')
        
        # Verify redirect to login
        expect(page).to_have_url(f"{self.live_server_url}/login/")
    
    def _login(self, page: Page, username: str, password: str):
        """Helper method to login"""
        page.goto(f"{self.live_server_url}/login/")
        page.fill('input[name="username"]', username)
        page.fill('input[name="password"]', password)
        page.click('button[type="submit"]')


class TestThreatAnalysis(PlaywrightTestCase):
    """Tests for threat analysis functionality"""
    
    def test_analyze_ip_address(self, page: Page):
        """Test analyzing an IP address"""
        self._login(page, 'analyst_test', 'testpass123')
        
        # Navigate to analysis page
        page.goto(f"{self.live_server_url}/analyze/")
        
        # Select IP type
        page.select_option('select[name="input_type"]', 'ip')
        
        # Enter IP address
        page.fill('input[name="input_value"]', '8.8.8.8')
        
        # Select engine
        page.check('input[value="vt"]')
        
        # Submit form
        page.click('button[type="submit"]')
        
        # Wait for results
        page.wait_for_selector('.analysis-results', timeout=10000)
        
        # Verify results are displayed
        expect(page.locator('.threat-score')).to_be_visible()
        expect(page.locator('.severity-badge')).to_be_visible()
    
    def test_analyze_url(self, page: Page):
        """Test analyzing a URL"""
        self._login(page, 'analyst_test', 'testpass123')
        
        page.goto(f"{self.live_server_url}/analyze/")
        
        page.select_option('select[name="input_type"]', 'url')
        page.fill('input[name="input_value"]', 'https://example.com')
        page.check('input[value="vt"]')
        
        page.click('button[type="submit"]')
        
        # Verify URL analysis results
        expect(page.locator('text=URL Analysis Results')).to_be_visible()
    
    def test_analyze_file_upload(self, page: Page):
        """Test file upload and analysis"""
        self._login(page, 'analyst_test', 'testpass123')
        
        page.goto(f"{self.live_server_url}/analyze/")
        
        page.select_option('select[name="input_type"]', 'file')
        
        # Upload a test file
        page.set_input_files('input[type="file"]', 'tests/fixtures/test_file.txt')
        
        page.click('button[type="submit"]')
        
        # Verify upload success
        expect(page.locator('text=File uploaded successfully')).to_be_visible()
    
    def test_view_report_details(self, page: Page):
        """Test viewing detailed report"""
        # Create a test report
        report = ThreatReport.objects.create(
            analyst=self.analyst,
            input_type='ip',
            input_value='192.168.1.1',
            engine_used='vt',
            severity='high',
            threat_score=85.5
        )
        
        self._login(page, 'analyst_test', 'testpass123')
        
        # Navigate to report
        page.goto(f"{self.live_server_url}/reports/{report.id}/")
        
        # Verify report details
        expect(page.locator('text=192.168.1.1')).to_be_visible()
        expect(page.locator('text=High')).to_be_visible()
        expect(page.locator('text=85.5')).to_be_visible()
    
    def _login(self, page: Page, username: str, password: str):
        page.goto(f"{self.live_server_url}/login/")
        page.fill('input[name="username"]', username)
        page.fill('input[name="password"]', password)
        page.click('button[type="submit"]')


class TestDashboard(PlaywrightTestCase):
    """Tests for dashboard functionality"""
    
    def test_dashboard_statistics(self, page: Page):
        """Test dashboard displays correct statistics"""
        # Create test data
        ThreatReport.objects.create(
            analyst=self.analyst,
            input_type='ip',
            input_value='192.168.1.1',
            engine_used='vt',
            severity='critical'
        )
        
        self._login(page, 'analyst_test', 'testpass123')
        
        page.goto(f"{self.live_server_url}/dashboard/")
        
        # Verify statistics cards
        expect(page.locator('.stat-card').nth(0)).to_contain_text('1')
        expect(page.locator('text=Critical')).to_be_visible()
    
    def test_dashboard_charts(self, page: Page):
        """Test dashboard charts are rendered"""
        self._login(page, 'analyst_test', 'testpass123')
        
        page.goto(f"{self.live_server_url}/dashboard/")
        
        # Verify chart canvas elements exist
        expect(page.locator('canvas#severityChart')).to_be_visible()
        expect(page.locator('canvas#timelineChart')).to_be_visible()
    
    def test_recent_reports_list(self, page: Page):
        """Test recent reports are displayed"""
        # Create multiple reports
        for i in range(5):
            ThreatReport.objects.create(
                analyst=self.analyst,
                input_type='ip',
                input_value=f'192.168.1.{i}',
                engine_used='vt'
            )
        
        self._login(page, 'analyst_test', 'testpass123')
        
        page.goto(f"{self.live_server_url}/dashboard/")
        
        # Verify 5 reports are listed
        reports = page.locator('.report-item')
        expect(reports).to_have_count(5)
    
    def _login(self, page: Page, username: str, password: str):
        page.goto(f"{self.live_server_url}/login/")
        page.fill('input[name="username"]', username)
        page.fill('input[name="password"]', password)
        page.click('button[type="submit"]')


class TestTaskManagement(PlaywrightTestCase):
    """Tests for task management"""
    
    def test_create_task(self, page: Page):
        """Test creating a new task"""
        report = ThreatReport.objects.create(
            analyst=self.analyst,
            input_type='ip',
            input_value='192.168.1.1',
            engine_used='vt'
        )
        
        self._login(page, 'analyst_test', 'testpass123')
        
        page.goto(f"{self.live_server_url}/reports/{report.id}/")
        
        # Click create task button
        page.click('button:has-text("Create Task")')
        
        # Fill task form
        page.fill('input[name="title"]', 'Investigate IP source')
        page.fill('textarea[name="description"]', 'Check firewall logs')
        page.select_option('select[name="priority"]', 'high')
        
        page.click('button[type="submit"]')
        
        # Verify task created
        expect(page.locator('text=Task created successfully')).to_be_visible()
    
    def test_update_task_status(self, page: Page):
        """Test updating task status"""
        report = ThreatReport.objects.create(
            analyst=self.analyst,
            input_type='ip',
            input_value='192.168.1.1',
            engine_used='vt'
        )
        
        task = Task.objects.create(
            report=report,
            title='Test Task',
            description='Test',
            priority='medium',
            created_by=self.analyst,
            assigned_to=self.analyst
        )
        
        self._login(page, 'analyst_test', 'testpass123')
        
        page.goto(f"{self.live_server_url}/tasks/{task.id}/")
        
        # Update status
        page.select_option('select[name="status"]', 'in_progress')
        page.click('button:has-text("Update Status")')
        
        # Verify update
        expect(page.locator('text=Status updated')).to_be_visible()
    
    def _login(self, page: Page, username: str, password: str):
        page.goto(f"{self.live_server_url}/login/")
        page.fill('input[name="username"]', username)
        page.fill('input[name="password"]', password)
        page.click('button[type="submit"]')


class TestMitigationActions(PlaywrightTestCase):
    """Tests for mitigation actions"""
    
    def test_block_ip_action(self, page: Page):
        """Test blocking an IP address"""
        report = ThreatReport.objects.create(
            analyst=self.analyst,
            input_type='ip',
            input_value='192.168.1.100',
            engine_used='vt',
            severity='critical'
        )
        
        self._login(page, 'admin_test', 'testpass123')
        
        page.goto(f"{self.live_server_url}/reports/{report.id}/")
        
        # Click mitigation button
        page.click('button:has-text("Take Action")')
        
        # Select block IP action
        page.select_option('select[name="action_type"]', 'block_ip')
        page.fill('textarea[name="description"]', 'Blocking malicious IP')
        
        page.click('button:has-text("Execute")')
        
        # Verify action initiated
        expect(page.locator('text=Mitigation action initiated')).to_be_visible()
    
    def test_mitigation_requires_admin(self, page: Page):
        """Test mitigation actions require admin role"""
        report = ThreatReport.objects.create(
            analyst=self.analyst,
            input_type='ip',
            input_value='192.168.1.100',
            engine_used='vt'
        )
        
        # Login as analyst (not admin)
        self._login(page, 'analyst_test', 'testpass123')
        
        page.goto(f"{self.live_server_url}/reports/{report.id}/")
        
        # Verify mitigation button is not visible
        expect(page.locator('button:has-text("Take Action")')).not_to_be_visible()
    
    def _login(self, page: Page, username: str, password: str):
        page.goto(f"{self.live_server_url}/login/")
        page.fill('input[name="username"]', username)
        page.fill('input[name="password"]', password)
        page.click('button[type="submit"]')


class TestNotifications(PlaywrightTestCase):
    """Tests for notifications"""
    
    def test_notification_display(self, page: Page):
        """Test notifications are displayed"""
        # Create notification
        Notification.objects.create(
            recipient=self.analyst,
            notification_type='new_report',
            title='New Threat Detected',
            message='A critical threat has been detected'
        )
        
        self._login(page, 'analyst_test', 'testpass123')
        
        page.goto(f"{self.live_server_url}/dashboard/")
        
        # Click notification bell
        page.click('.notification-bell')
        
        # Verify notification appears
        expect(page.locator('text=New Threat Detected')).to_be_visible()
    
    def test_mark_notification_as_read(self, page: Page):
        """Test marking notification as read"""
        notification = Notification.objects.create(
            recipient=self.analyst,
            notification_type='task_assigned',
            title='Task Assigned',
            message='You have been assigned a new task'
        )
        
        self._login(page, 'analyst_test', 'testpass123')
        
        page.goto(f"{self.live_server_url}/notifications/")
        
        # Click mark as read
        page.click(f'button[data-notification-id="{notification.id}"]')
        
        # Verify notification marked as read
        expect(page.locator('.notification-unread')).to_have_count(0)
    
    def _login(self, page: Page, username: str, password: str):
        page.goto(f"{self.live_server_url}/login/")
        page.fill('input[name="username"]', username)
        page.fill('input[name="password"]', password)
        page.click('button[type="submit"]')


class TestSearch(PlaywrightTestCase):
    """Tests for search functionality"""
    
    def test_search_reports(self, page: Page):
        """Test searching through reports"""
        # Create test reports
        ThreatReport.objects.create(
            analyst=self.analyst,
            input_type='ip',
            input_value='192.168.1.1',
            engine_used='vt',
            severity='high'
        )
        
        self._login(page, 'analyst_test', 'testpass123')
        
        page.goto(f"{self.live_server_url}/reports/")
        
        # Search for IP
        page.fill('input[name="search"]', '192.168.1.1')
        page.click('button:has-text("Search")')
        
        # Verify search results
        expect(page.locator('text=192.168.1.1')).to_be_visible()
    
    def test_filter_by_severity(self, page: Page):
        """Test filtering reports by severity"""
        ThreatReport.objects.create(
            analyst=self.analyst,
            input_type='ip',
            input_value='192.168.1.1',
            engine_used='vt',
            severity='critical'
        )
        
        self._login(page, 'analyst_test', 'testpass123')
        
        page.goto(f"{self.live_server_url}/reports/")
        
        # Select critical filter
        page.select_option('select[name="severity"]', 'critical')
        page.click('button:has-text("Filter")')
        
        # Verify filtered results
        expect(page.locator('.severity-badge:has-text("Critical")')).to_be_visible()
    
    def _login(self, page: Page, username: str, password: str):
        page.goto(f"{self.live_server_url}/login/")
        page.fill('input[name="username"]', username)
        page.fill('input[name="password"]', password)
        page.click('button[type="submit"]')


class TestResponsiveDesign(PlaywrightTestCase):
    """Tests for responsive design"""
    
    def test_mobile_navigation(self, page: Page):
        """Test mobile menu works correctly"""
        # Set mobile viewport
        page.set_viewport_size({"width": 375, "height": 667})
        
        self._login(page, 'analyst_test', 'testpass123')
        
        page.goto(f"{self.live_server_url}/dashboard/")
        
        # Click hamburger menu
        page.click('.mobile-menu-button')
        
        # Verify menu opens
        expect(page.locator('.mobile-menu')).to_be_visible()
    
    def test_tablet_layout(self, page: Page):
        """Test tablet layout"""
        # Set tablet viewport
        page.set_viewport_size({"width": 768, "height": 1024})
        
        self._login(page, 'analyst_test', 'testpass123')
        
        page.goto(f"{self.live_server_url}/dashboard/")
        
        # Verify layout adjusts
        expect(page.locator('.sidebar')).to_be_visible()
    
    def _login(self, page: Page, username: str, password: str):
        page.goto(f"{self.live_server_url}/login/")
        page.fill('input[name="username"]', username)
        page.fill('input[name="password"]', password)
        page.click('button[type="submit"]')