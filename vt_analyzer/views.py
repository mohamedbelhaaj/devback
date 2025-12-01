import logging
from django.conf import settings
from django.http import FileResponse, JsonResponse
from django.db.models import Count, Q
from rest_framework import viewsets, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import action
from datetime import datetime, timedelta
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from rest_framework.permissions import AllowAny, IsAuthenticated

from .models import (
    User, ThreatReport, Task, MitigationAction, AWSConfiguration, Notification
)
from .serializers import (
    AnalysisInputSerializer,
    ThreatReportSerializer,
    TaskSerializer,
    MitigationActionSerializer,
    AWSConfigurationSerializer,
    NotificationSerializer
)
from .permissions import IsAdminUser, IsAnalystUser, IsAdminOrOwner
from .utils import (
    detect_input_type, vt_scan_file, vt_scan_url, vt_scan_ip, vt_scan_hash, vt_scan_domain,
    otx_scan_url, otx_scan_ip, otx_scan_hash, get_ip_info
)
from .aws_integration import AWSManager

logger = logging.getLogger(__name__)

# Stub for PDF generation
def generate_pdf_report(report):
    return None

# ===================================================================
# AUTHENTICATION
# ===================================================================

class CustomLoginView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        
        user = authenticate(username=username, password=password)
        
        if user is not None:
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'role': getattr(user, 'role', None),
                }
            })
        else:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)


# ===================================================================
# ANALYST VIEWS - Threat Analysis
# ===================================================================

class AnalyzeView(APIView):
    """Analyst endpoint for analyzing threats"""
    permission_classes = [IsAnalystUser]

    def post(self, request, *args, **kwargs):
        serializer = AnalysisInputSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        validated_data = serializer.validated_data
        input_value = validated_data.get('input_value', '').strip()
        uploaded_file = validated_data.get('file')
        engine_choice = validated_data.get('engine_choice', 'vt')

        if uploaded_file:
            input_type = 'file'
            input_value = uploaded_file.name
        elif input_value:
            input_type = detect_input_type(input_value)
            if input_type == 'unknown':
                return Response({'error': 'Unknown input type.'}, status=status.HTTP_400_BAD_REQUEST)
        else:
             return Response({'error': 'Input required.'}, status=status.HTTP_400_BAD_REQUEST)

        report = ThreatReport.objects.create(
            analyst=request.user,
            input_type=input_type,
            input_value=input_value,
            file_name=uploaded_file.name if uploaded_file else None,
            engine_used=engine_choice,
            status='pending'
        )

        try:
            vt_result, otx_result, ipinfo_result = None, None, None
            
            if engine_choice == 'vt':
                if input_type == 'file': vt_result = vt_scan_file(uploaded_file)
                elif input_type == 'url': vt_result = vt_scan_url(input_value)
                elif input_type == 'ip': vt_result = vt_scan_ip(input_value)
                elif input_type == 'hash': vt_result = vt_scan_hash(input_value)
                elif input_type == 'domain': vt_result = vt_scan_domain(input_value)
                
                if vt_result and 'error' in vt_result:
                    raise Exception(f"VirusTotal Error: {vt_result.get('error')}")
                report.vt_data = vt_result

            elif engine_choice == 'otx':
                if input_type == 'ip': otx_result = otx_scan_ip(input_value)
                elif input_type == 'url': otx_result = otx_scan_url(input_value)
                elif input_type == 'hash': otx_result = otx_scan_hash(input_value)
                
                if otx_result and 'error' in otx_result:
                    raise Exception(f"OTX Error: {otx_result.get('error')}")
                report.otx_data = otx_result

            if input_type == 'ip':
                ipinfo_result = get_ip_info(input_value)
                if ipinfo_result and 'error' not in ipinfo_result:
                    report.ipinfo_data = ipinfo_result

            report.calculate_threat_score()
            report.save()

            return Response(ThreatReportSerializer(report).data, status=status.HTTP_201_CREATED)

        except Exception as e:
            report.delete()
            logger.error(f"Analysis Error: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ===================================================================
# ANALYST VIEWS - Threat Reports (For Analysts)
# ===================================================================

class ThreatReportViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for analysts to view their own reports"""
    serializer_class = ThreatReportSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.role == 'admin':
            return ThreatReport.objects.filter(assigned_to=user)
        elif user.role == 'analyst':
            return ThreatReport.objects.filter(analyst=user)
        return ThreatReport.objects.none()

    @action(detail=True, methods=['post'], permission_classes=[IsAnalystUser])
    def send_to_admin(self, request, pk=None):
        """Analyst sends report to admin for review"""
        report = self.get_object()
        admin_id = request.data.get('admin_id')
        notes = request.data.get('notes', '')

        try:
            admin = User.objects.get(id=admin_id, role='admin')
        except User.DoesNotExist:
            return Response({'error': 'Admin not found.'}, status=404)

        report.assigned_to = admin
        report.notes = f"[Analyst Note]: {notes}"
        report.status = 'pending'
        report.save()
        
        Notification.objects.create(
            recipient=admin,
            notification_type='new_report',
            title=f'New Threat Report: {report.input_type.upper()}',
            message=f"Analyst {request.user.username} sent a report ({report.severity}).",
            report=report
        )
        return Response({'success': True, 'message': f'Assigned to {admin.username}'})
    
    @action(detail=True, methods=['get'], permission_classes=[IsAdminOrOwner])
    def download_pdf(self, request, pk=None):
        """Download PDF report"""
        report = self.get_object()
        if report.pdf_report:
            return FileResponse(report.pdf_report.open(), as_attachment=True, filename=f'report_{report.id}.pdf')
        return Response({'error': 'PDF generation not available.'}, status=404)


class TaskViewSet(viewsets.ModelViewSet):
    """ViewSet for managing tasks"""
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated, IsAdminOrOwner]

    def get_queryset(self):
        user = self.request.user
        if user.role == 'admin':
            return Task.objects.filter(report__assigned_to=user)
        elif user.role == 'analyst':
            return Task.objects.filter(report__analyst=user)
        return Task.objects.none()

    def get_serializer_context(self):
        return {'request': self.request}


class NotificationViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for user notifications"""
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Notification.objects.filter(recipient=self.request.user, is_read=False)
        
    @action(detail=True, methods=['post'])
    def mark_as_read(self, request, pk=None):
        notification = self.get_object()
        if notification.recipient == request.user:
            notification.is_read = True
            notification.save()
            return Response({'success': True})
        return Response({'error': 'Forbidden'}, status=403)


# ===================================================================
# ADMIN VIEWS - Dashboard
# ===================================================================

class AdminDashboardView(APIView):
    """Comprehensive admin dashboard with threat intelligence stats"""
    permission_classes = [IsAdminUser]
    
    def get(self, request):
        """Get dashboard statistics for the logged-in admin"""
        user = request.user
        
        # Time ranges for analytics
        today = datetime.now().date()
        week_ago = today - timedelta(days=7)
        month_ago = today - timedelta(days=30)
        
        # Reports assigned to this admin
        assigned_reports = ThreatReport.objects.filter(assigned_to=user)
        
        # Basic counts
        stats = {
            'overview': {
                'total_reports': assigned_reports.count(),
                'pending_reports': assigned_reports.filter(status='pending').count(),
                'critical_reports': assigned_reports.filter(severity='critical').count(),
                'mitigated_reports': assigned_reports.filter(status='mitigated').count(),
            },
            
            # Severity distribution
            'severity_distribution': dict(
                assigned_reports.values('severity')
                .annotate(count=Count('id'))
                .values_list('severity', 'count')
            ),
            
            # Status distribution
            'status_distribution': dict(
                assigned_reports.values('status')
                .annotate(count=Count('id'))
                .values_list('status', 'count')
            ),
            
            # Time-based trends
            'trends': {
                'today': assigned_reports.filter(created_at__date=today).count(),
                'this_week': assigned_reports.filter(created_at__date__gte=week_ago).count(),
                'this_month': assigned_reports.filter(created_at__date__gte=month_ago).count(),
            },
            
            # Tasks overview
            'tasks': {
                'open': Task.objects.filter(assigned_to=user, status='open').count(),
                'in_progress': Task.objects.filter(assigned_to=user, status='in_progress').count(),
                'completed': Task.objects.filter(assigned_to=user, status='completed').count(),
                'urgent': Task.objects.filter(assigned_to=user, priority='urgent', status='open').count(),
            },
            
            # Mitigation actions
            'mitigations': {
                'pending': MitigationAction.objects.filter(
                    initiated_by=user, status='pending'
                ).count(),
                'completed': MitigationAction.objects.filter(
                    initiated_by=user, status='completed'
                ).count(),
                'failed': MitigationAction.objects.filter(
                    initiated_by=user, status='failed'
                ).count(),
            },
            
            # Top threat indicators
            'top_threats': list(
                assigned_reports.values('input_value', 'input_type', 'severity')
                .annotate(count=Count('id'))
                .order_by('-count')[:10]
            ),
            
            # Recent critical alerts
            'recent_critical': ThreatReportSerializer(
                assigned_reports.filter(severity='critical').order_by('-created_at')[:5],
                many=True
            ).data,
        }
        
        return Response(stats)


class AdminAWSStatusView(APIView):
    """Check AWS connection status and get AWS resources info"""
    permission_classes = [IsAdminUser]
    
    def get(self, request):
        """Get AWS configuration status and basic resource info"""
        user = request.user
        
        # Get active AWS config for this admin
        config = AWSConfiguration.objects.filter(owner=user, is_active=True).first()
        
        if not config:
            return Response({
                'configured': False,
                'message': 'No AWS configuration found. Please configure AWS credentials.'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Test credentials
        aws_manager = AWSManager(config)
        test_result = aws_manager.test_credentials()
        
        if not test_result['success']:
            return Response({
                'configured': True,
                'connected': False,
                'error': test_result['error'],
                'config': {
                    'name': config.name,
                    'region': config.aws_region,
                    'last_updated': config.updated_at
                }
            }, status=status.HTTP_200_OK)
        
        # Get VPC info
        vpc_info = aws_manager.get_vpc_info() if config.vpc_id else {'success': False}
        
        # Get Security Group rules
        sg_rules = aws_manager.list_security_group_rules() if config.security_group_id else {'success': False}
        
        response_data = {
            'configured': True,
            'connected': True,
            'config': {
                'name': config.name,
                'region': config.aws_region,
                'vpc_id': config.vpc_id,
                'security_group_id': config.security_group_id,
                'waf_configured': bool(config.waf_ip_set_id),
                'nacl_configured': bool(config.nacl_id),
                'firewall_configured': bool(config.network_firewall_arn),
                'last_updated': config.updated_at,
                'auto_block_enabled': config.auto_block_enabled,
                'auto_block_threshold': config.auto_block_threshold,
            },
            'regions_available': test_result.get('regions', []),
        }
        
        if vpc_info.get('success'):
            response_data['vpc_info'] = {
                'cidr_block': vpc_info['vpc']['CidrBlock'],
                'subnets_count': len(vpc_info['subnets']),
            }
        
        if sg_rules.get('success'):
            response_data['security_group'] = {
                'ingress_rules_count': len(sg_rules['rules']['ingress']),
                'egress_rules_count': len(sg_rules['rules']['egress']),
            }
        
        return Response(response_data)


# ===================================================================
# ADMIN VIEWS - Threat Reports Management
# ===================================================================

class AdminThreatReportViewSet(viewsets.ReadOnlyModelViewSet):
    """Admin view of threat reports assigned to them"""
    serializer_class = ThreatReportSerializer
    permission_classes = [IsAdminUser]
    
    def get_queryset(self):
        """Get reports assigned to this admin"""
        queryset = ThreatReport.objects.filter(assigned_to=self.request.user)
        
        # Apply filters from query params
        severity = self.request.query_params.get('severity')
        status_filter = self.request.query_params.get('status')
        search = self.request.query_params.get('search')
        
        if severity:
            queryset = queryset.filter(severity=severity)
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        if search:
            queryset = queryset.filter(
                Q(input_value__icontains=search) | 
                Q(notes__icontains=search)
            )
        
        return queryset.order_by('-created_at')

    @action(detail=True, methods=['post'])
    def update_status(self, request, pk=None):
        """Update report status with admin notes"""
        report = self.get_object()
        new_status = request.data.get('status')
        admin_notes = request.data.get('notes', '')
        
        valid_statuses = ['reviewed', 'mitigated', 'false_positive']
        if new_status not in valid_statuses:
            return Response({
                'error': f'Invalid status. Must be one of: {", ".join(valid_statuses)}'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Update report
        report.status = new_status
        report.reviewed_at = datetime.now()
        
        if admin_notes:
            report.notes += f"\n\n[Admin - {request.user.username} - {datetime.now().strftime('%Y-%m-%d %H:%M')}]:\n{admin_notes}"
        
        report.save()
        
        # Notify analyst
        Notification.objects.create(
            recipient=report.analyst,
            notification_type='report_updated',
            title='Report Status Updated',
            message=f'Admin updated your report to: {report.get_status_display()}',
            report=report
        )
        
        return Response(ThreatReportSerializer(report).data)

    @action(detail=True, methods=['post'])
    def create_mitigation(self, request, pk=None):
        """Create mitigation action directly from a report"""
        report = self.get_object()
        
        action_type = request.data.get('action_type')
        target_value = request.data.get('target_value', report.input_value)
        description = request.data.get('description', f'Mitigation for report {report.id}')
        execute_now = request.data.get('execute_now', False)
        
        if not action_type:
            return Response({
                'error': 'action_type is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Create mitigation action
        config = AWSConfiguration.objects.filter(owner=request.user, is_active=True).first()
        aws_region = config.aws_region if config else 'us-east-1'
        
        action = MitigationAction.objects.create(
            report=report,
            action_type=action_type,
            target_value=target_value,
            description=description,
            initiated_by=request.user,
            aws_region=aws_region
        )
        
        # Execute immediately if requested
        if execute_now:
            # Execute the action (call execute method)
            exec_result = self._execute_mitigation(action, request.user)
            
            return Response({
                'action': MitigationActionSerializer(action).data,
                'execution_result': exec_result
            })
        
        return Response(MitigationActionSerializer(action).data, status=status.HTTP_201_CREATED)
    
    def _execute_mitigation(self, action_obj, user):
        """Internal method to execute mitigation"""
        config = AWSConfiguration.objects.filter(owner=user, is_active=True).first()
        
        if not config:
            return {'success': False, 'error': 'No active AWS configuration'}
        
        try:
            aws_manager = AWSManager(config)
        except Exception as e:
            return {'success': False, 'error': str(e)}
        
        result = {'success': False, 'error': 'Unknown action type'}
        
        try:
            if action_obj.action_type in ['block_ip', 'block_ip_sg']:
                result = aws_manager.block_ip_in_security_group(
                    action_obj.target_value, action_obj.description
                )
            elif action_obj.action_type == 'block_ip_waf':
                if not config.waf_ip_set_id:
                    raise ValueError("WAF IP Set not configured")
                result = aws_manager.block_ip_in_waf(
                    action_obj.target_value, config.waf_ip_set_name, config.waf_ip_set_id
                )
            elif action_obj.action_type == 'block_ip_nacl':
                if not config.nacl_id:
                    raise ValueError("NACL not configured")
                result = aws_manager.edit_nacl_rules(
                    config.nacl_id, action_obj.rule_number, action_obj.target_value, action='deny'
                )
            elif action_obj.action_type == 'isolate_instance':
                if not config.isolation_sg_id:
                    raise ValueError("Isolation SG not configured")
                result = aws_manager.isolate_instance(
                    action_obj.target_value, config.isolation_sg_id
                )
        except Exception as e:
            result = {'success': False, 'error': str(e)}
        
        # Update action status
        if result['success']:
            action_obj.status = 'completed'
            action_obj.completed_at = datetime.now()
            action_obj.error_message = result.get('message', 'Success')
        else:
            action_obj.status = 'failed'
            action_obj.error_message = result.get('error', 'Unknown error')
        
        action_obj.save()
        return result


# ===================================================================
# ADMIN VIEWS - Mitigation Actions
# ===================================================================

class MitigationActionViewSet(viewsets.ModelViewSet):
    serializer_class = MitigationActionSerializer
    permission_classes = [IsAdminUser]

    def get_queryset(self):
        """Return mitigation actions for the logged-in admin"""
        return MitigationAction.objects.filter(initiated_by=self.request.user).order_by('-created_at')

    def perform_create(self, serializer):
        """Create mitigation action"""
        serializer.save(initiated_by=self.request.user)

    @action(detail=True, methods=['post'])
    def execute(self, request, pk=None):
        """Execute a mitigation action using AWS"""
        action_obj = self.get_object()
        
        if action_obj.status == 'completed':
            return Response({
                'warning': 'Action already executed successfully.'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        config = AWSConfiguration.objects.filter(
            owner=request.user, 
            is_active=True
        ).first()
        
        if not config:
            return Response({
                'error': 'No active AWS configuration found.'
            }, status=status.HTTP_404_NOT_FOUND)
        
        try:
            aws_manager = AWSManager(config)
        except Exception as e:
            return Response({
                'error': f'Failed to initialize AWS: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        action_obj.status = 'in_progress'
        action_obj.save()
        
        result = {'success': False, 'error': 'Unknown action type'}
        
        try:
            if action_obj.action_type in ['block_ip', 'block_ip_sg']:
                result = aws_manager.block_ip_in_security_group(
                    action_obj.target_value, action_obj.description
                )
            elif action_obj.action_type == 'block_ip_waf':
                if not config.waf_ip_set_id:
                    raise ValueError("WAF IP Set not configured")
                result = aws_manager.block_ip_in_waf(
                    action_obj.target_value, config.waf_ip_set_name, config.waf_ip_set_id
                )
            elif action_obj.action_type == 'block_ip_nacl':
                if not config.nacl_id:
                    raise ValueError("NACL not configured")
                result = aws_manager.edit_nacl_rules(
                    config.nacl_id, action_obj.rule_number, action_obj.target_value, action='deny'
                )
            elif action_obj.action_type == 'isolate_instance':
                if not config.isolation_sg_id:
                    raise ValueError("Isolation SG not configured")
                result = aws_manager.isolate_instance(
                    action_obj.target_value, config.isolation_sg_id
                )
            elif action_obj.action_type == 'geo_block':
                if not config.waf_web_acl_id:
                    raise ValueError("WAF Web ACL not configured")
                countries = [c.strip() for c in action_obj.target_value.split(',')]
                result = aws_manager.set_geo_blocking(
                    config.waf_web_acl_name, config.waf_web_acl_id, countries
                )
            elif action_obj.action_type == 'rate_limit':
                if not config.waf_web_acl_id:
                    raise ValueError("WAF Web ACL not configured")
                limit = int(action_obj.target_value) if action_obj.target_value.isdigit() else 1000
                result = aws_manager.set_rate_limit_rule(
                    config.waf_web_acl_name, config.waf_web_acl_id, limit
                )
        except ValueError as ve:
            result = {'success': False, 'error': str(ve)}
        except Exception as e:
            logger.error(f"AWS Execution Error: {e}")
            result = {'success': False, 'error': str(e)}
        
        if result['success']:
            action_obj.status = 'completed'
            action_obj.completed_at = datetime.now()
            action_obj.error_message = result.get('message', 'Success')
            
            if action_obj.report:
                Notification.objects.create(
                    recipient=action_obj.report.analyst,
                    notification_type='action_completed',
                    title='Mitigation Action Completed',
                    message=f"Action '{action_obj.get_action_type_display()}' completed successfully.",
                    report=action_obj.report
                )
        else:
            action_obj.status = 'failed'
            action_obj.error_message = result.get('error', 'Unknown error')
        
        action_obj.save()
        
        status_code = status.HTTP_200_OK if result['success'] else status.HTTP_400_BAD_REQUEST
        return Response({
            **result,
            'action': MitigationActionSerializer(action_obj).data
        }, status=status_code)


# ===================================================================
# ADMIN VIEWS - AWS Configuration
# ===================================================================
class UserListView(APIView):
    """
    API endpoint to list users based on role
    GET /api/users/ - Returns all users
    GET /api/users/?role=admin - Returns only admin users
    GET /api/users/?role=analyst - Returns only analyst users
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        role = request.GET.get('role')  # Get the role parameter from query string
        
        try:
            if role == 'admin':
                # Filter users with admin role
                users = User.objects.filter(role='admin')
            elif role == 'analyst':
                # Filter users with analyst role
                users = User.objects.filter(role='analyst')
            else:
                # Return all users if no role specified
                users = User.objects.all()
            
            user_data = [
                {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'role': getattr(user, 'role', None),
                    'is_staff': user.is_staff,
                    'is_superuser': user.is_superuser,
                }
                for user in users
            ]
            
            return Response(user_data, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error(f"Error fetching users: {e}")
            return Response(
                {'error': f'Error fetching users: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
class AWSConfigurationViewSet(viewsets.ModelViewSet):
    """Manage AWS configurations for the logged-in admin"""
    serializer_class = AWSConfigurationSerializer
    permission_classes = [IsAdminUser]
    
    def get_queryset(self):
        """Return only configurations owned by the logged-in admin"""
        return AWSConfiguration.objects.filter(owner=self.request.user)

    def perform_create(self, serializer):
        """Create AWS configuration for the logged-in admin"""
        serializer.save(owner=self.request.user)

    @action(detail=True, methods=['post'])
    def test_credentials(self, request, pk=None):
        """Test if AWS credentials are valid"""
        config = self.get_object()
        
        try:
            aws_manager = AWSManager(config)
            result = aws_manager.test_credentials()
            
            if result['success']:
                return Response({
                    'success': True,
                    'message': result['message'],
                    'regions': result.get('regions', [])
                })
            else:
                return Response({
                    'success': False,
                    'error': result['error']
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except Exception as e:
            logger.error(f"Credential test failed: {e}")
            return Response({
                'success': False,
                'error': f'Failed to test credentials: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=True, methods=['get'])
    def get_resources(self, request, pk=None):
        """Get available AWS resources"""
        config = self.get_object()
        
        try:
            aws_manager = AWSManager(config)
            test_result = aws_manager.test_credentials()
            
            if not test_result['success']:
                return Response({
                    'error': test_result['error']
                }, status=status.HTTP_401_UNAUTHORIZED)
            
            resources = {}
            
            if config.vpc_id:
                vpc_info = aws_manager.get_vpc_info()
                if vpc_info['success']:
                    resources['vpc'] = vpc_info
            
            if config.security_group_id:
                sg_rules = aws_manager.list_security_group_rules()
                if sg_rules['success']:
                    resources['security_group'] = sg_rules
            
            return Response({
                'success': True,
                'resources': resources
            })
            
        except Exception as e:
            logger.error(f"Failed to get resources: {e}")
            return Response({
                'error': f'Failed to retrieve resources: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=True, methods=['post'])
    def set_active(self, request, pk=None):
        """Set this configuration as the active one"""
        config = self.get_object()
        
        AWSConfiguration.objects.filter(owner=request.user).update(is_active=False)
        config.is_active = True
        config.save()
        
        return Response({
            'success': True,
            'message': f'Configuration "{config.name}" is now active'
        })


# ===================================================================
# ADMIN VIEWS - Analytics
# ===================================================================

class ThreatAnalyticsView(APIView):
    """Advanced threat analytics for admin dashboard"""
    permission_classes = [IsAdminUser]
    
    def get(self, request):
        """Get detailed analytics and trends"""
        user = request.user
        days = int(request.query_params.get('days', 30))
        
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=days)
        
        reports = ThreatReport.objects.filter(
            assigned_to=user,
            created_at__date__gte=start_date
        )
        
        # Daily threat counts
        daily_counts = {}
        for i in range(days):
            date = start_date + timedelta(days=i)
            count = reports.filter(created_at__date=date).count()
            daily_counts[date.isoformat()] = count
        
        # Severity trends over time
        severity_trends = {}
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            severity_trends[severity] = reports.filter(severity=severity).count()
        
        # Top malicious IPs
        top_malicious_ips = list(
            reports.filter(input_type='ip', malicious_count__gt=0)
            .values('input_value', 'malicious_count', 'severity')
            .order_by('-malicious_count')[:10]
        )
        
        # Analyst performance
        analyst_stats = list(
            reports.values('analyst__username')
            .annotate(
                total=Count('id'),
                critical=Count('id', filter=Q(severity='critical')),
                mitigated=Count('id', filter=Q(status='mitigated'))
            )
        )
        
        return Response({
            'date_range': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat(),
                'days': days
            },
            'daily_counts': daily_counts,
            'severity_trends': severity_trends,
            'top_malicious_ips': top_malicious_ips,
            'analyst_performance': analyst_stats,
            'total_reports': reports.count()
        })