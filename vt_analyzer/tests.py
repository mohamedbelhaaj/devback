from django.test import TestCase
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta
import uuid
import json

from .models import (
    User, ThreatReport, AWSConfiguration, MitigationAction,
    Task, Notification, ThreatIntelligenceLog
)

User = get_user_model()


class UserModelTest(TestCase):
    """Tests for the User model"""
    
    def setUp(self):
        self.analyst = User.objects.create_user(
            username='analyst1',
            email='analyst@test.com',
            password='testpass123',
            role='analyst',
            department='Security',
            phone='+1234567890'
        )
        
        self.admin = User.objects.create_user(
            username='admin1',
            email='admin@test.com',
            password='testpass123',
            role='admin'
        )
    
    def test_user_creation(self):
        """Test user is created with correct attributes"""
        self.assertEqual(self.analyst.username, 'analyst1')
        self.assertEqual(self.analyst.role, 'analyst')
        self.assertEqual(self.analyst.department, 'Security')
        self.assertEqual(self.analyst.phone, '+1234567890')
    
    def test_user_role_choices(self):
        """Test user role is limited to valid choices"""
        self.assertIn(self.analyst.role, ['analyst', 'admin'])
        self.assertEqual(self.admin.role, 'admin')
    
    def test_user_db_table(self):
        """Test custom database table name"""
        self.assertEqual(User._meta.db_table, 'vt_analyzer_user')


class ThreatReportModelTest(TestCase):
    """Tests for the ThreatReport model"""
    
    def setUp(self):
        self.analyst = User.objects.create_user(
            username='analyst1',
            email='analyst@test.com',
            password='testpass123',
            role='analyst'
        )
        
        self.vt_data = {
            'data': {
                'attributes': {
                    'last_analysis_stats': {
                        'malicious': 15,
                        'suspicious': 5,
                        'undetected': 30,
                        'harmless': 50
                    }
                }
            }
        }
        
        self.report = ThreatReport.objects.create(
            analyst=self.analyst,
            input_type='ip',
            input_value='192.168.1.1',
            engine_used='vt',
            vt_data=self.vt_data
        )
    
    def test_report_creation(self):
        """Test threat report is created correctly"""
        self.assertEqual(self.report.input_type, 'ip')
        self.assertEqual(self.report.input_value, '192.168.1.1')
        self.assertEqual(self.report.engine_used, 'vt')
        self.assertEqual(self.report.status, 'pending')
        self.assertIsInstance(self.report.id, uuid.UUID)
    
    def test_calculate_threat_score_vt_critical(self):
        """Test threat score calculation for critical severity (VT)"""
        self.report.calculate_threat_score()
        
        self.assertEqual(self.report.severity, 'critical')
        self.assertEqual(self.report.malicious_count, 15)
        self.assertEqual(self.report.suspicious_count, 5)
        self.assertEqual(self.report.undetected_count, 30)
        self.assertGreater(self.report.threat_score, 0)
    
    def test_calculate_threat_score_vt_high(self):
        """Test threat score calculation for high severity (VT)"""
        self.report.vt_data['data']['attributes']['last_analysis_stats']['malicious'] = 7
        self.report.calculate_threat_score()
        
        self.assertEqual(self.report.severity, 'high')
        self.assertEqual(self.report.malicious_count, 7)
    
    def test_calculate_threat_score_vt_medium(self):
        """Test threat score calculation for medium severity (VT)"""
        self.report.vt_data['data']['attributes']['last_analysis_stats']['malicious'] = 3
        self.report.calculate_threat_score()
        
        self.assertEqual(self.report.severity, 'medium')
    
    def test_calculate_threat_score_vt_low(self):
        """Test threat score calculation for low severity (VT)"""
        self.report.vt_data['data']['attributes']['last_analysis_stats'] = {
            'malicious': 0,
            'suspicious': 3,
            'undetected': 50,
            'harmless': 47
        }
        self.report.calculate_threat_score()
        
        self.assertEqual(self.report.severity, 'low')
    
    def test_calculate_threat_score_vt_info(self):
        """Test threat score calculation for info severity (VT)"""
        self.report.vt_data['data']['attributes']['last_analysis_stats'] = {
            'malicious': 0,
            'suspicious': 0,
            'undetected': 50,
            'harmless': 50
        }
        self.report.calculate_threat_score()
        
        self.assertEqual(self.report.severity, 'info')
        self.assertEqual(self.report.threat_score, 0)
    
    def test_calculate_threat_score_otx(self):
        """Test threat score calculation for OTX engine"""
        otx_report = ThreatReport.objects.create(
            analyst=self.analyst,
            input_type='domain',
            input_value='malicious.com',
            engine_used='otx',
            otx_data={'pulse_count': 25}
        )
        
        otx_report.calculate_threat_score()
        
        self.assertEqual(otx_report.severity, 'critical')
        self.assertEqual(otx_report.threat_score, 90)
    
    def test_report_str_representation(self):
        """Test string representation of report"""
        expected = f"IP: 192.168.1.1 - info"
        self.assertEqual(str(self.report), expected)
    
    def test_report_ordering(self):
        """Test reports are ordered by creation date (newest first)"""
        # Create a newer report after self.report
        newer_report = ThreatReport.objects.create(
            analyst=self.analyst,
            input_type='url',
            input_value='http://test.com',
            engine_used='vt'
        )
        
        reports = ThreatReport.objects.all()
        # Newer report should be first
        self.assertEqual(reports[0], newer_report)
        self.assertEqual(reports[1], self.report)


class AWSConfigurationModelTest(TestCase):
    """Tests for the AWSConfiguration model"""
    
    def setUp(self):
        self.admin = User.objects.create_user(
            username='admin1',
            email='admin@test.com',
            password='testpass123',
            role='admin'
        )
        
        self.aws_config = AWSConfiguration.objects.create(
            owner=self.admin,
            name='Production AWS',
            aws_access_key='AKIAIOSFODNN7EXAMPLE',
            aws_secret_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            aws_region='us-east-1',
            vpc_id='vpc-12345678',
            security_group_id='sg-12345678',
            auto_block_enabled=True,
            auto_block_threshold=10
        )
    
    def test_aws_config_creation(self):
        """Test AWS configuration is created correctly"""
        self.assertEqual(self.aws_config.name, 'Production AWS')
        self.assertEqual(self.aws_config.aws_region, 'us-east-1')
        self.assertTrue(self.aws_config.is_active)
        self.assertTrue(self.aws_config.auto_block_enabled)
    
    def test_aws_config_with_session_token(self):
        """Test AWS configuration with session token (AWS Academy)"""
        config = AWSConfiguration.objects.create(
            owner=self.admin,
            name='AWS Academy',
            aws_session_token='FwoGZXIvYXdzEBYaD...',
            aws_region='us-west-2'
        )
        
        self.assertIsNotNone(config.aws_session_token)
        self.assertEqual(config.aws_region, 'us-west-2')
    
    def test_aws_config_str_representation(self):
        """Test string representation of AWS config"""
        expected = f"Production AWS - us-east-1 ({self.admin.username})"
        self.assertEqual(str(self.aws_config), expected)
    
    def test_aws_config_without_owner(self):
        """Test AWS configuration without owner (global config)"""
        global_config = AWSConfiguration.objects.create(
            name='Global Config',
            aws_region='eu-west-1'
        )
        
        expected = "Global Config - eu-west-1 (Global)"
        self.assertEqual(str(global_config), expected)


class MitigationActionModelTest(TestCase):
    """Tests for the MitigationAction model"""
    
    def setUp(self):
        self.analyst = User.objects.create_user(
            username='analyst1',
            email='analyst@test.com',
            password='testpass123'
        )
        
        self.report = ThreatReport.objects.create(
            analyst=self.analyst,
            input_type='ip',
            input_value='192.168.1.1',
            engine_used='vt'
        )
        
        self.mitigation = MitigationAction.objects.create(
            report=self.report,
            action_type='block_ip',
            target_value='192.168.1.1',
            initiated_by=self.analyst,
            description='Blocking malicious IP'
        )
    
    def test_mitigation_creation(self):
        """Test mitigation action is created correctly"""
        self.assertEqual(self.mitigation.action_type, 'block_ip')
        self.assertEqual(self.mitigation.target_value, '192.168.1.1')
        self.assertEqual(self.mitigation.status, 'pending')
        self.assertIsInstance(self.mitigation.id, uuid.UUID)
    
    def test_mitigation_action_types(self):
        """Test various mitigation action types"""
        action_types = [
            'block_ip_waf',
            'block_ip_nacl',
            'isolate_instance',
            'geo_block'
        ]
        
        for action_type in action_types:
            mitigation = MitigationAction.objects.create(
                action_type=action_type,
                target_value='test',
                initiated_by=self.analyst,
                description=f'Test {action_type}'
            )
            self.assertEqual(mitigation.action_type, action_type)
    
    def test_mitigation_str_representation(self):
        """Test string representation of mitigation action"""
        expected = "block_ip - 192.168.1.1 (pending)"
        self.assertEqual(str(self.mitigation), expected)
    
    def test_mitigation_status_update(self):
        """Test updating mitigation status"""
        self.mitigation.status = 'completed'
        self.mitigation.completed_at = timezone.now()
        self.mitigation.save()
        
        self.assertEqual(self.mitigation.status, 'completed')
        self.assertIsNotNone(self.mitigation.completed_at)


class TaskModelTest(TestCase):
    """Tests for the Task model"""
    
    def setUp(self):
        self.analyst = User.objects.create_user(
            username='analyst1',
            email='analyst@test.com',
            password='testpass123'
        )
        
        self.admin = User.objects.create_user(
            username='admin1',
            email='admin@test.com',
            password='testpass123',
            role='admin'
        )
        
        self.report = ThreatReport.objects.create(
            analyst=self.analyst,
            input_type='ip',
            input_value='192.168.1.1',
            engine_used='vt'
        )
        
        self.task = Task.objects.create(
            report=self.report,
            title='Investigate IP address',
            description='Check source of malicious traffic',
            priority='high',
            created_by=self.analyst,
            assigned_to=self.admin,
            due_date=timezone.now() + timedelta(days=1)
        )
    
    def test_task_creation(self):
        """Test task is created correctly"""
        self.assertEqual(self.task.title, 'Investigate IP address')
        self.assertEqual(self.task.priority, 'high')
        self.assertEqual(self.task.status, 'open')
        self.assertEqual(self.task.assigned_to, self.admin)
    
    def test_task_priority_ordering(self):
        """Test tasks are ordered by priority"""
        urgent_task = Task.objects.create(
            report=self.report,
            title='Urgent task',
            description='Urgent',
            priority='urgent',
            created_by=self.analyst
        )
        
        tasks = Task.objects.all()
        self.assertEqual(tasks[0], urgent_task)
    
    def test_task_str_representation(self):
        """Test string representation of task"""
        expected = "Investigate IP address - high (open)"
        self.assertEqual(str(self.task), expected)
    
    def test_task_completion(self):
        """Test task completion"""
        self.task.status = 'completed'
        self.task.completed_at = timezone.now()
        self.task.save()
        
        self.assertEqual(self.task.status, 'completed')
        self.assertIsNotNone(self.task.completed_at)


class NotificationModelTest(TestCase):
    """Tests for the Notification model"""
    
    def setUp(self):
        self.analyst = User.objects.create_user(
            username='analyst1',
            email='analyst@test.com',
            password='testpass123'
        )
        
        self.report = ThreatReport.objects.create(
            analyst=self.analyst,
            input_type='ip',
            input_value='192.168.1.1',
            engine_used='vt'
        )
        
        self.notification = Notification.objects.create(
            recipient=self.analyst,
            notification_type='new_report',
            title='New Threat Report',
            message='A new threat report has been created',
            report=self.report
        )
    
    def test_notification_creation(self):
        """Test notification is created correctly"""
        self.assertEqual(self.notification.notification_type, 'new_report')
        self.assertEqual(self.notification.recipient, self.analyst)
        self.assertFalse(self.notification.is_read)
    
    def test_notification_str_representation(self):
        """Test string representation of notification"""
        expected = f"new_report - {self.analyst.username}"
        self.assertEqual(str(self.notification), expected)
    
    def test_notification_read_status(self):
        """Test marking notification as read"""
        self.notification.is_read = True
        self.notification.save()
        
        self.assertTrue(self.notification.is_read)
    
    def test_notification_ordering(self):
        """Test notifications are ordered by creation date (newest first)"""
        # Create a newer notification after self.notification
        newer_notification = Notification.objects.create(
            recipient=self.analyst,
            notification_type='task_assigned',
            title='Task Assigned',
            message='You have been assigned a task'
        )
        
        notifications = Notification.objects.all()
        # Newer notification should be first
        self.assertEqual(notifications[0], newer_notification)
        self.assertEqual(notifications[1], self.notification)


class ThreatIntelligenceLogModelTest(TestCase):
    """Tests for the ThreatIntelligenceLog model"""
    
    def setUp(self):
        self.analyst = User.objects.create_user(
            username='analyst1',
            email='analyst@test.com',
            password='testpass123'
        )
        
        self.report = ThreatReport.objects.create(
            analyst=self.analyst,
            input_type='ip',
            input_value='192.168.1.1',
            engine_used='vt',
            severity='high',
            threat_score=75.5,
            malicious_count=10,
            suspicious_count=5
        )
        
        self.log = ThreatIntelligenceLog.objects.create(
            report=self.report,
            indicator='192.168.1.1',
            indicator_type='ip',
            threat_score=75.5,
            severity='high',
            malicious_count=10,
            suspicious_count=5,
            country='US',
            asn='AS15169',
            pulse_count=15,
            vt_positives=10,
            analyst=self.analyst.username,
            notes='Suspicious activity detected'
        )
    
    def test_log_creation(self):
        """Test threat intelligence log is created correctly"""
        self.assertEqual(self.log.indicator, '192.168.1.1')
        self.assertEqual(self.log.indicator_type, 'ip')
        self.assertEqual(self.log.threat_score, 75.5)
        self.assertEqual(self.log.severity, 'high')
    
    def test_log_str_representation(self):
        """Test string representation of log"""
        expected = "192.168.1.1 - high"
        self.assertEqual(str(self.log), expected)
    
    def test_log_one_to_one_relationship(self):
        """Test one-to-one relationship with ThreatReport"""
        self.assertEqual(self.log.report, self.report)
        self.assertEqual(self.report.threatintelligencelog, self.log)
    
    def test_log_ordering(self):
        """Test logs are ordered by timestamp (newest first)"""
        # Create another report and log
        report2 = ThreatReport.objects.create(
            analyst=self.analyst,
            input_type='domain',
            input_value='malicious.com',
            engine_used='otx'
        )
        
        newer_log = ThreatIntelligenceLog.objects.create(
            report=report2,
            indicator='malicious.com',
            indicator_type='domain',
            threat_score=50.0,
            severity='medium',
            malicious_count=5,
            suspicious_count=3,
            analyst=self.analyst.username
        )
        
        logs = ThreatIntelligenceLog.objects.all()
        # Newer log should be first
        self.assertEqual(logs[0], newer_log)
        self.assertEqual(logs[1], self.log)