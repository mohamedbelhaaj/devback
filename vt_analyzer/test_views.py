import json
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock, Mock
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

from vt_analyzer.models import (
    ThreatReport, Task, MitigationAction, 
    AWSConfiguration, Notification
)

User = get_user_model()


class BaseTestCase(APITestCase):
    """Classe de base pour les tests avec setup commun"""
    
    def setUp(self):
        """Configuration initiale pour tous les tests"""
        # Créer des utilisateurs de test
        self.admin_user = User.objects.create_user(
            username='admin_test',
            password='admin_password',
            email='admin@test.com',
            role='admin'
        )
        
        self.analyst_user = User.objects.create_user(
            username='analyst_test',
            password='analyst_password',
            email='analyst@test.com',
            role='analyst'
        )
        
        # Créer des clients API
        self.admin_client = APIClient()
        self.analyst_client = APIClient()
        self.unauthenticated_client = APIClient()
        
        # Authentifier les clients
        self._authenticate_client(self.admin_client, self.admin_user)
        self._authenticate_client(self.analyst_client, self.analyst_user)
    
    def _authenticate_client(self, client, user):
        """Authentifie un client avec JWT"""
        refresh = RefreshToken.for_user(user)
        client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')


# ===================================================================
# TESTS - AUTHENTICATION
# ===================================================================

class CustomLoginViewTest(APITestCase):
    """Tests pour la vue de connexion"""
    
    def setUp(self):
        self.url = '/api/auth/login/'  # Ajustez selon votre urls.py
        self.user = User.objects.create_user(
            username='testuser',
            password='testpassword',
            role='analyst'
        )
    
    def test_login_success(self):
        """Test de connexion réussie"""
        data = {
            'username': 'testuser',
            'password': 'testpassword'
        }
        response = self.client.post(self.url, data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
        self.assertIn('user', response.data)
        self.assertEqual(response.data['user']['username'], 'testuser')
    
    def test_login_invalid_credentials(self):
        """Test de connexion avec identifiants invalides"""
        data = {
            'username': 'testuser',
            'password': 'wrongpassword'
        }
        response = self.client.post(self.url, data)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('error', response.data)
    
    def test_login_missing_fields(self):
        """Test de connexion avec champs manquants"""
        response = self.client.post(self.url, {})
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


# ===================================================================
# TESTS - ANALYST VIEWS
# ===================================================================

class AnalyzeViewTest(BaseTestCase):
    """Tests pour la vue d'analyse de menaces"""
    
    def setUp(self):
        super().setUp()
        self.url = '/api/analyst/analyze/'  # Ajustez selon votre urls.py
    
    @patch('vt_analyzer.views.vt_scan_url')
    @patch('vt_analyzer.views.detect_input_type')
    def test_analyze_url_success(self, mock_detect, mock_vt_scan):
        """Test d'analyse d'URL réussie"""
        mock_detect.return_value = 'url'
        mock_vt_scan.return_value = {
            'data': {'attributes': {'last_analysis_stats': {'malicious': 5}}}
        }
        
        data = {
            'input_value': 'https://malicious-site.com',
            'engine_choice': 'vt'
        }
        
        response = self.analyst_client.post(self.url, data)
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('id', response.data)
        self.assertEqual(response.data['input_type'], 'url')
        mock_vt_scan.assert_called_once()
    
    @patch('vt_analyzer.views.vt_scan_ip')
    @patch('vt_analyzer.views.get_ip_info')
    @patch('vt_analyzer.views.detect_input_type')
    def test_analyze_ip_with_ipinfo(self, mock_detect, mock_ipinfo, mock_vt_scan):
        """Test d'analyse d'IP avec enrichissement IPInfo"""
        mock_detect.return_value = 'ip'
        mock_vt_scan.return_value = {
            'data': {'attributes': {'last_analysis_stats': {'malicious': 3}}}
        }
        mock_ipinfo.return_value = {
            'country': 'US',
            'city': 'New York'
        }
        
        data = {
            'input_value': '192.168.1.1',
            'engine_choice': 'vt'
        }
        
        response = self.analyst_client.post(self.url, data)
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['input_type'], 'ip')
        mock_ipinfo.assert_called_once_with('192.168.1.1')
    
    def test_analyze_missing_input(self):
        """Test d'analyse sans entrée"""
        response = self.analyst_client.post(self.url, {})
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
    
    @patch('vt_analyzer.views.detect_input_type')
    def test_analyze_unknown_input_type(self, mock_detect):
        """Test d'analyse avec type d'entrée inconnu"""
        mock_detect.return_value = 'unknown'
        
        data = {'input_value': 'invalid_input'}
        response = self.analyst_client.post(self.url, data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_analyze_without_permission(self):
        """Test d'analyse sans permission analyst"""
        response = self.unauthenticated_client.post(self.url, {})
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    @patch('vt_analyzer.views.vt_scan_url')
    @patch('vt_analyzer.views.detect_input_type')
    def test_analyze_with_error(self, mock_detect, mock_vt_scan):
        """Test d'analyse avec erreur de l'API"""
        mock_detect.return_value = 'url'
        mock_vt_scan.return_value = {'error': 'API Error'}
        
        data = {
            'input_value': 'https://test.com',
            'engine_choice': 'vt'
        }
        
        response = self.analyst_client.post(self.url, data)
        
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)


class ThreatReportViewSetTest(BaseTestCase):
    """Tests pour le ViewSet des rapports de menaces"""
    
    def setUp(self):
        super().setUp()
        # Créer des rapports de test
        self.analyst_report = ThreatReport.objects.create(
            analyst=self.analyst_user,
            input_type='url',
            input_value='https://test.com',
            engine_used='vt',
            status='pending',
            severity='medium'
        )
        
        self.admin_report = ThreatReport.objects.create(
            analyst=self.analyst_user,
            assigned_to=self.admin_user,
            input_type='ip',
            input_value='192.168.1.1',
            engine_used='vt',
            status='reviewed',
            severity='high'
        )
    
    def test_analyst_list_own_reports(self):
        """Test: l'analyste ne voit que ses propres rapports"""
        url = '/api/analyst/reports/'
        response = self.analyst_client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # L'analyste voit ses 2 rapports
        self.assertEqual(len(response.data), 2)
    
    def test_admin_list_assigned_reports(self):
        """Test: l'admin ne voit que les rapports qui lui sont assignés"""
        url = '/api/analyst/reports/'
        response = self.admin_client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['id'], self.admin_report.id)
    
    def test_send_to_admin_success(self):
        """Test: envoi de rapport à l'admin"""
        url = f'/api/analyst/reports/{self.analyst_report.id}/send_to_admin/'
        data = {
            'admin_id': self.admin_user.id,
            'notes': 'Veuillez examiner ce rapport'
        }
        
        response = self.analyst_client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        
        # Vérifier que le rapport a été assigné
        self.analyst_report.refresh_from_db()
        self.assertEqual(self.analyst_report.assigned_to, self.admin_user)
        
        # Vérifier qu'une notification a été créée
        notification = Notification.objects.filter(
            recipient=self.admin_user,
            report=self.analyst_report
        ).first()
        self.assertIsNotNone(notification)
    
    def test_send_to_admin_invalid_admin(self):
        """Test: envoi à un admin inexistant"""
        url = f'/api/analyst/reports/{self.analyst_report.id}/send_to_admin/'
        data = {'admin_id': 9999}
        
        response = self.analyst_client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
    
    def test_download_pdf_without_pdf(self):
        """Test: téléchargement PDF quand il n'existe pas"""
        url = f'/api/analyst/reports/{self.analyst_report.id}/download_pdf/'
        response = self.analyst_client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class TaskViewSetTest(BaseTestCase):
    """Tests pour le ViewSet des tâches"""
    
    def setUp(self):
        super().setUp()
        self.report = ThreatReport.objects.create(
            analyst=self.analyst_user,
            assigned_to=self.admin_user,
            input_type='url',
            input_value='https://test.com',
            engine_used='vt'
        )
        
        self.task = Task.objects.create(
            report=self.report,
            title='Test Task',
            description='Task description',
            assigned_to=self.admin_user,
            priority='high',
            status='open'
        )
    
    def test_admin_list_tasks(self):
        """Test: l'admin voit ses tâches"""
        url = '/api/tasks/'
        response = self.admin_client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
    
    def test_analyst_list_tasks(self):
        """Test: l'analyste voit les tâches de ses rapports"""
        url = '/api/tasks/'
        response = self.analyst_client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class NotificationViewSetTest(BaseTestCase):
    """Tests pour le ViewSet des notifications"""
    
    def setUp(self):
        super().setUp()
        self.notification = Notification.objects.create(
            recipient=self.admin_user,
            notification_type='new_report',
            title='Test Notification',
            message='Test message',
            is_read=False
        )
    
    def test_list_unread_notifications(self):
        """Test: liste des notifications non lues"""
        url = '/api/notifications/'
        response = self.admin_client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
    
    def test_mark_as_read(self):
        """Test: marquer une notification comme lue"""
        url = f'/api/notifications/{self.notification.id}/mark_as_read/'
        response = self.admin_client.post(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        
        self.notification.refresh_from_db()
        self.assertTrue(self.notification.is_read)
    
    def test_mark_as_read_forbidden(self):
        """Test: marquer la notification d'un autre utilisateur"""
        url = f'/api/notifications/{self.notification.id}/mark_as_read/'
        response = self.analyst_client.post(url)
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


# ===================================================================
# TESTS - ADMIN VIEWS
# ===================================================================

class AdminDashboardViewTest(BaseTestCase):
    """Tests pour le tableau de bord admin"""
    
    def setUp(self):
        super().setUp()
        self.url = '/api/admin/dashboard/'
        
        # Créer des rapports de test
        for i in range(5):
            ThreatReport.objects.create(
                analyst=self.analyst_user,
                assigned_to=self.admin_user,
                input_type='ip',
                input_value=f'192.168.1.{i}',
                engine_used='vt',
                severity='critical' if i < 2 else 'medium',
                status='pending'
            )
    
    def test_dashboard_access_admin(self):
        """Test: accès au dashboard par l'admin"""
        response = self.admin_client.get(self.url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('overview', response.data)
        self.assertIn('severity_distribution', response.data)
        self.assertIn('trends', response.data)
    
    def test_dashboard_access_analyst_forbidden(self):
        """Test: accès interdit au dashboard pour l'analyste"""
        response = self.analyst_client.get(self.url)
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
    
    def test_dashboard_statistics(self):
        """Test: vérification des statistiques du dashboard"""
        response = self.admin_client.get(self.url)
        
        self.assertEqual(response.data['overview']['total_reports'], 5)
        self.assertEqual(response.data['overview']['critical_reports'], 2)
        self.assertIn('severity_distribution', response.data)


class AdminAWSStatusViewTest(BaseTestCase):
    """Tests pour la vue du statut AWS"""
    
    def setUp(self):
        super().setUp()
        self.url = '/api/admin/aws/status/'
        
        self.aws_config = AWSConfiguration.objects.create(
            owner=self.admin_user,
            name='Test Config',
            aws_access_key='test_key',
            aws_secret_key='test_secret',
            aws_region='us-east-1',
            is_active=True
        )
    
    @patch('vt_analyzer.views.AWSManager')
    def test_aws_status_connected(self, mock_aws_manager):
        """Test: statut AWS quand connecté"""
        mock_manager = Mock()
        mock_manager.test_credentials.return_value = {
            'success': True,
            'message': 'Connected',
            'regions': ['us-east-1', 'eu-west-1']
        }
        mock_manager.get_vpc_info.return_value = {
            'success': True,
            'vpc': {'CidrBlock': '10.0.0.0/16'},
            'subnets': [{'id': 'subnet-1'}]
        }
        mock_aws_manager.return_value = mock_manager
        
        response = self.admin_client.get(self.url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['configured'])
        self.assertTrue(response.data['connected'])
    
    @patch('vt_analyzer.views.AWSManager')
    def test_aws_status_connection_failed(self, mock_aws_manager):
        """Test: statut AWS quand la connexion échoue"""
        mock_manager = Mock()
        mock_manager.test_credentials.return_value = {
            'success': False,
            'error': 'Invalid credentials'
        }
        mock_aws_manager.return_value = mock_manager
        
        response = self.admin_client.get(self.url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['configured'])
        self.assertFalse(response.data['connected'])
        self.assertIn('error', response.data)
    
    def test_aws_status_no_configuration(self):
        """Test: statut AWS sans configuration"""
        # Supprimer la configuration
        self.aws_config.delete()
        
        response = self.admin_client.get(self.url)
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertFalse(response.data['configured'])


class AdminThreatReportViewSetTest(BaseTestCase):
    """Tests pour le ViewSet admin des rapports"""
    
    def setUp(self):
        super().setUp()
        self.report = ThreatReport.objects.create(
            analyst=self.analyst_user,
            assigned_to=self.admin_user,
            input_type='url',
            input_value='https://malicious.com',
            engine_used='vt',
            status='pending',
            severity='high'
        )
    
    def test_update_status_success(self):
        """Test: mise à jour du statut d'un rapport"""
        url = f'/api/admin/reports/{self.report.id}/update_status/'
        data = {
            'status': 'reviewed',
            'notes': 'Rapport vérifié et validé'
        }
        
        response = self.admin_client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.report.refresh_from_db()
        self.assertEqual(self.report.status, 'reviewed')
        self.assertIn('Rapport vérifié', self.report.notes)
        
        # Vérifier qu'une notification a été créée
        notification = Notification.objects.filter(
            recipient=self.analyst_user,
            report=self.report
        ).first()
        self.assertIsNotNone(notification)
    
    def test_update_status_invalid_status(self):
        """Test: mise à jour avec un statut invalide"""
        url = f'/api/admin/reports/{self.report.id}/update_status/'
        data = {'status': 'invalid_status'}
        
        response = self.admin_client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    @patch('vt_analyzer.views.AWSManager')
    def test_create_mitigation_success(self, mock_aws_manager):
        """Test: création d'une action de mitigation"""
        url = f'/api/admin/reports/{self.report.id}/create_mitigation/'
        data = {
            'action_type': 'block_ip',
            'description': 'Bloquer IP malveillante',
            'execute_now': False
        }
        
        response = self.admin_client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('id', response.data)
        
        # Vérifier que l'action a été créée
        action = MitigationAction.objects.get(id=response.data['id'])
        self.assertEqual(action.action_type, 'block_ip')
        self.assertEqual(action.initiated_by, self.admin_user)
    
    def test_create_mitigation_missing_action_type(self):
        """Test: création de mitigation sans type d'action"""
        url = f'/api/admin/reports/{self.report.id}/create_mitigation/'
        data = {'description': 'Test'}
        
        response = self.admin_client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_filter_by_severity(self):
        """Test: filtrage des rapports par sévérité"""
        # Créer un autre rapport avec une sévérité différente
        ThreatReport.objects.create(
            analyst=self.analyst_user,
            assigned_to=self.admin_user,
            input_type='ip',
            input_value='192.168.1.1',
            engine_used='vt',
            status='pending',
            severity='critical'
        )
        
        url = '/api/admin/reports/'
        response = self.admin_client.get(url, {'severity': 'high'})
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['severity'], 'high')


class MitigationActionViewSetTest(BaseTestCase):
    """Tests pour le ViewSet des actions de mitigation"""
    
    def setUp(self):
        super().setUp()
        self.report = ThreatReport.objects.create(
            analyst=self.analyst_user,
            assigned_to=self.admin_user,
            input_type='ip',
            input_value='192.168.1.100',
            engine_used='vt'
        )
        
        self.aws_config = AWSConfiguration.objects.create(
            owner=self.admin_user,
            name='Test Config',
            aws_access_key='test_key',
            aws_secret_key='test_secret',
            aws_region='us-east-1',
            security_group_id='sg-12345',
            is_active=True
        )
        
        self.action = MitigationAction.objects.create(
            report=self.report,
            action_type='block_ip_sg',
            target_value='192.168.1.100',
            description='Bloquer IP',
            initiated_by=self.admin_user,
            status='pending'
        )
    
    def test_list_mitigation_actions(self):
        """Test: liste des actions de mitigation"""
        url = '/api/admin/mitigations/'
        response = self.admin_client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
    
    @patch('vt_analyzer.views.AWSManager')
    def test_execute_mitigation_success(self, mock_aws_manager):
        """Test: exécution réussie d'une action de mitigation"""
        mock_manager = Mock()
        mock_manager.block_ip_in_security_group.return_value = {
            'success': True,
            'message': 'IP bloquée avec succès'
        }
        mock_aws_manager.return_value = mock_manager
        
        url = f'/api/admin/mitigations/{self.action.id}/execute/'
        response = self.admin_client.post(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        
        self.action.refresh_from_db()
        self.assertEqual(self.action.status, 'completed')
        self.assertIsNotNone(self.action.completed_at)
    
    @patch('vt_analyzer.views.AWSManager')
    def test_execute_mitigation_failure(self, mock_aws_manager):
        """Test: échec de l'exécution d'une action"""
        mock_manager = Mock()
        mock_manager.block_ip_in_security_group.return_value = {
            'success': False,
            'error': 'AWS API Error'
        }
        mock_aws_manager.return_value = mock_manager
        
        url = f'/api/admin/mitigations/{self.action.id}/execute/'
        response = self.admin_client.post(url)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
        self.action.refresh_from_db()
        self.assertEqual(self.action.status, 'failed')
        self.assertIn('AWS API Error', self.action.error_message)
    
    def test_execute_already_completed_action(self):
        """Test: exécution d'une action déjà complétée"""
        self.action.status = 'completed'
        self.action.save()
        
        url = f'/api/admin/mitigations/{self.action.id}/execute/'
        response = self.admin_client.post(url)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('warning', response.data)
    
    def test_execute_without_aws_config(self):
        """Test: exécution sans configuration AWS"""
        self.aws_config.delete()
        
        url = f'/api/admin/mitigations/{self.action.id}/execute/'
        response = self.admin_client.post(url)
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class AWSConfigurationViewSetTest(BaseTestCase):
    """Tests pour le ViewSet de configuration AWS"""
    
    def setUp(self):
        super().setUp()
        self.config = AWSConfiguration.objects.create(
            owner=self.admin_user,
            name='Test Config',
            aws_access_key='test_key',
            aws_secret_key='test_secret',
            aws_region='us-east-1',
            is_active=False
        )
    
    def test_list_configurations(self):
        """Test: liste des configurations AWS"""
        url = '/api/admin/aws/configurations/'
        response = self.admin_client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
    
    def test_create_configuration(self):
        """Test: création d'une configuration AWS"""
        url = '/api/admin/aws/configurations/'
        data = {
            'name': 'New Config',
            'aws_access_key': 'new_key',
            'aws_secret_key': 'new_secret',
            'aws_region': 'eu-west-1'
        }
        
        response = self.admin_client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['owner'], self.admin_user.id)
    
    @patch('vt_analyzer.views.AWSManager')
    def test_test_credentials_success(self, mock_aws_manager):
        """Test: test des identifiants AWS réussi"""
        mock_manager = Mock()
        mock_manager.test_credentials.return_value = {
            'success': True,
            'message': 'Credentials valid',
            'regions': ['us-east-1']
        }
        mock_aws_manager.return_value = mock_manager
        
        url = f'/api/admin/aws/configurations/{self.config.id}/test_credentials/'
        response = self.admin_client.post(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
    
    def test_set_active_configuration(self):
        """Test: définir une configuration comme active"""
        url = f'/api/admin/aws/configurations/{self.config.id}/set_active/'
        response = self.admin_client.post(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        
        self.config.refresh_from_db()
        self.assertTrue(self.config.is_active)


class UserListViewTest(BaseTestCase):
    """Tests pour la vue de liste des utilisateurs"""
    
    def setUp(self):
        super().setUp()
        self.url = '/api/users/'
    
    def test_list_all_users(self):
        """Test: liste de tous les utilisateurs"""
        response = self.admin_client.get(self.url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)  # admin + analyst
    
    def test_filter_admins_only(self):
        """Test: filtrage des admins uniquement"""
        response = self.admin_client.get(self.url, {'role': 'admin'})
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['role'], 'admin')
    
    def test_filter_analysts_only(self):
        """Test: filtrage des analystes uniquement"""
        response = self.admin_client.get(self.url, {'role': 'analyst'})
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['role'], 'analyst')


class ThreatAnalyticsViewTest(BaseTestCase):
    """Tests pour la vue d'analytiques"""
    
    def setUp(self):
        super().setUp()
        self.url = '/api/admin/analytics/'
        
        # Créer des rapports sur plusieurs jours
        for i in range(10):
            ThreatReport.objects.create(
                analyst=self.analyst_user,
                assigned_to=self.admin_user,
                input_type='ip',
                input_value=f'192.168.1.{i}',
                engine_used='vt',
                severity='high' if i < 5 else 'medium',
                created_at=datetime.now() - timedelta(days=i)
            )
    
    def test_get_analytics_default_period(self):
        """Test: obtenir les analytiques avec période par défaut"""
        response = self.admin_client.get(self.url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('daily_counts', response.data)
        self.assertIn('severity_trends', response.data)
        self.assertIn('top_malicious_ips', response.data)
    
    def test_get_analytics_custom_period(self):
        """Test: obtenir les analytiques avec période personnalisée"""
        response = self.admin_client.get(self.url, {'days': 7})
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['date_range']['days'], 7)
    
    def test_analytics_forbidden_for_analyst(self):
        """Test: accès interdit pour les analystes"""
        response = self.analyst_client.get(self.url)
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


# ===================================================================
# TESTS D'INTÉGRATION
# ===================================================================

class IntegrationWorkflowTest(BaseTestCase):
    """Tests d'intégration pour le workflow complet"""
    
    @patch('vt_analyzer.views.vt_scan_url')
    @patch('vt_analyzer.views.detect_input_type')
    @patch('vt_analyzer.views.AWSManager')
    def test_complete_threat_workflow(self, mock_aws, mock_detect, mock_vt):
        """Test: workflow complet d'analyse et mitigation d'une menace"""
        # 1. Analyste analyse une URL
        mock_detect.return_value = 'url'
        mock_vt.return_value = {
            'data': {'attributes': {'last_analysis_stats': {'malicious': 10}}}
        }
        
        analyze_url = '/api/analyst/analyze/'
        analyze_data = {
            'input_value': 'https://malicious.com',
            'engine_choice': 'vt'
        }
        analyze_response = self.analyst_client.post(analyze_url, analyze_data)
        self.assertEqual(analyze_response.status_code, status.HTTP_201_CREATED)
        
        report_id = analyze_response.data['id']
        
        # 2. Analyste envoie le rapport à l'admin
        send_url = f'/api/analyst/reports/{report_id}/send_to_admin/'
        send_data = {
            'admin_id': self.admin_user.id,
            'notes': 'Urgent: site malveillant détecté'
        }
        send_response = self.analyst_client.post(send_url, send_data)
        self.assertEqual(send_response.status_code, status.HTTP_200_OK)
        
        # 3. Admin met à jour le statut
        update_url = f'/api/admin/reports/{report_id}/update_status/'
        update_data = {
            'status': 'reviewed',
            'notes': 'Confirmé comme malveillant'
        }
        update_response = self.admin_client.post(update_url, update_data)
        self.assertEqual(update_response.status_code, status.HTTP_200_OK)
        
        # 4. Admin crée une action de mitigation
        mitigation_url = f'/api/admin/reports/{report_id}/create_mitigation/'
        mitigation_data = {
            'action_type': 'block_ip',
            'description': 'Bloquer le domaine'
        }
        mitigation_response = self.admin_client.post(mitigation_url, mitigation_data)
        self.assertEqual(mitigation_response.status_code, status.HTTP_201_CREATED)


if __name__ == '__main__':
    import unittest
    unittest.main()