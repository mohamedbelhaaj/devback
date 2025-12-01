from rest_framework import serializers
from dj_rest_auth.serializers import UserDetailsSerializer as BaseUserDetailsSerializer
from .models import (
    User, ThreatReport, Task, MitigationAction, AWSConfiguration, Notification
)

class UserSimpleSerializer(serializers.ModelSerializer):
    """Simple serializer for nesting user details."""
    class Meta:
        model = User
        fields = ['id', 'username', 'role']

class UserDetailsSerializer(BaseUserDetailsSerializer):
    """Custom UserDetails serializer to include role/department."""
    class Meta(BaseUserDetailsSerializer.Meta):
        fields = BaseUserDetailsSerializer.Meta.fields + ('role', 'department', 'phone')

# ===================================================================
# ANALYSIS ENDPOINT SERIALIZERS
# ===================================================================
class AnalysisInputSerializer(serializers.Serializer):
    input_value = serializers.CharField(required=False, allow_blank=True)
    file = serializers.FileField(required=False, allow_null=True)
    engine_choice = serializers.ChoiceField(choices=['vt', 'otx'], default='vt')

    def validate(self, data):
        if not data.get('input_value') and not data.get('file'):
            raise serializers.ValidationError("Please provide either an input value or upload a file")
        return data

# ===================================================================
# MODEL SERIALIZERS
# ===================================================================

class ThreatReportSerializer(serializers.ModelSerializer):
    analyst = UserSimpleSerializer(read_only=True)
    assigned_to = UserSimpleSerializer(read_only=True)
    
    severity = serializers.CharField(source='get_severity_display', read_only=True)
    status = serializers.CharField(source='get_status_display', read_only=True)
    input_type = serializers.CharField(source='get_input_type_display', read_only=True)
    
    class Meta:
        model = ThreatReport
        fields = [
            'id', 'analyst', 'assigned_to', 'input_type', 'input_value', 
            'file_name', 'engine_used', 'vt_data', 'otx_data', 'ipinfo_data',
            'severity', 'threat_score', 'status', 'notes', 'created_at', 'reviewed_at'
        ]

class TaskSerializer(serializers.ModelSerializer):
    created_by = UserSimpleSerializer(read_only=True)
    assigned_to = UserSimpleSerializer(read_only=True)
    
    assigned_to_id = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(), source='assigned_to', write_only=True
    )
    report_id = serializers.PrimaryKeyRelatedField(
        queryset=ThreatReport.objects.all(), source='report', write_only=True
    )
    
    class Meta:
        model = Task
        fields = [
            'id', 'report', 'title', 'description', 'priority', 'status',
            'created_by', 'assigned_to', 'due_date', 'created_at',
            'assigned_to_id', 'report_id'
        ]
        read_only_fields = ('report', 'created_by', 'assigned_to')

    def create(self, validated_data):
        validated_data['created_by'] = self.context['request'].user
        return super().create(validated_data)

class MitigationActionSerializer(serializers.ModelSerializer):
    initiated_by = UserSimpleSerializer(read_only=True)
    initiated_by_username = serializers.ReadOnlyField(source='initiated_by.username')
    status = serializers.CharField(read_only=True)
    
    report_id = serializers.PrimaryKeyRelatedField(
        queryset=ThreatReport.objects.all(), source='report', write_only=True, required=False
    )

    class Meta:
        model = MitigationAction
        fields = [
            'id', 'report', 'action_type', 'target_value', 'aws_region', 
            'rule_number', 'description', 'status', 'initiated_by', 'initiated_by_username',
            'created_at', 'error_message', 'report_id'
        ]
        read_only_fields = ('report', 'initiated_by', 'status', 'error_message', 'created_at')

    def create(self, validated_data):
        validated_data['initiated_by'] = self.context['request'].user
        return super().create(validated_data)

class AWSConfigurationSerializer(serializers.ModelSerializer):
    aws_secret_key = serializers.CharField(write_only=True, required=False, allow_blank=True)
    
    class Meta:
        model = AWSConfiguration
        fields = '__all__' # Includes new fields: waf_ip_set_id, nacl_id, etc.
    
    def update(self, instance, validated_data):
        if not validated_data.get('aws_secret_key'):
            validated_data.pop('aws_secret_key', None)
        return super().update(instance, validated_data)

class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = [
            'id', 'notification_type', 'title', 'message', 'is_read', 'created_at'
        ]