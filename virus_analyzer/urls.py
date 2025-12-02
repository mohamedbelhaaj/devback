from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView

# Import from single views.py file
from vt_analyzer import views

# Create router for ViewSets
router = DefaultRouter()

# ==================== ANALYST ENDPOINTS ====================
# These are for analysts to submit and view their reports
router.register(r'reports', views.ThreatReportViewSet, basename='report')
router.register(r'tasks', views.TaskViewSet, basename='task')
router.register(r'notifications', views.NotificationViewSet, basename='notification')

# ==================== ADMIN ENDPOINTS ====================
# These are for administrators to manage security operations
router.register(r'admin/reports', views.AdminThreatReportViewSet, basename='admin-report')
router.register(r'admin/mitigations', views.MitigationActionViewSet, basename='admin-mitigation')
router.register(r'admin/aws-config', views.AWSConfigurationViewSet, basename='admin-aws-config')

urlpatterns = [
    # ==================== DJANGO ADMIN ====================
    path('admin/', admin.site.urls),
    
    # ==================== AUTHENTICATION ====================
    path('api/auth/login/', views.CustomLoginView.as_view(), name='custom-login'),
    path('api/auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/auth/', include('dj_rest_auth.urls')),
        path('api/users/', views.UserListView.as_view(), name='user-list'),

    # ==================== ANALYST ENDPOINTS ====================
    path('api/analyze/', views.AnalyzeView.as_view(), name='analyze'),
    
    # ==================== ADMIN DASHBOARD ENDPOINTS ====================
    path('api/admin/dashboard/', views.AdminDashboardView.as_view(), name='admin-dashboard'),
    path('api/admin/aws-status/', views.AdminAWSStatusView.as_view(), name='admin-aws-status'),
    path('api/admin/analytics/', views.ThreatAnalyticsView.as_view(), name='admin-analytics'),
    
    # ==================== ALL API ROUTES ====================
    path('api/', include(router.urls)),
    path('api/auth/', include('dj_rest_auth.urls')),
]