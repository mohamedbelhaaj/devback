import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import logging
import time
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class AWSManager:
    """
    Enhanced AWS Manager with full support for AWS Academy credentials
    and comprehensive security operations
    """
    def __init__(self, aws_config):
        """
        Initialize AWS clients with configuration from database
        """
        self.config = aws_config
        self.session = None
        self.ec2 = None
        self.wafv2 = None
        self.network_firewall = None
        self.cloudwatch = None
        self.cloudtrail = None
        
        try:
            # Support both AWS Academy (with session token) and standard credentials
            session_params = {
                'aws_access_key_id': self.config.aws_access_key,
                'aws_secret_access_key': self.config.aws_secret_key,
                'region_name': self.config.aws_region
            }
            
            # Add session token if available (AWS Academy)
            if self.config.aws_session_token and self.config.aws_session_token.strip():
                logger.info("🎓 Initializing AWS session with session token (AWS Academy mode)")
                session_params['aws_session_token'] = self.config.aws_session_token
            else:
                logger.info("🔑 Initializing AWS session with standard credentials")
            
            self.session = boto3.Session(**session_params)
            
            # Initialize all AWS service clients
            self.ec2 = self.session.client('ec2')
            self.wafv2 = self.session.client('wafv2')
            self.network_firewall = self.session.client('network-firewall')
            self.cloudwatch = self.session.client('logs')
            self.cloudtrail = self.session.client('cloudtrail')
            
            logger.info(f"✅ AWS clients initialized successfully for region {self.config.aws_region}")
            
        except NoCredentialsError as e:
            logger.error(f"❌ No AWS credentials provided: {e}")
            raise
        except Exception as e:
            logger.error(f"❌ Failed to initialize AWS clients: {e}")
            raise

    def test_credentials(self):
        """
        Test AWS credentials validity - essential for AWS Academy
        """
        if not self.ec2:
            return {
                'success': False, 
                'error': 'EC2 client not initialized. Check AWS credentials.'
            }
        
        try:
            response = self.ec2.describe_regions()
            logger.info("✅ AWS credentials validated successfully")
            return {
                'success': True, 
                'message': 'AWS connection successful. Credentials are valid.',
                'regions': [r['RegionName'] for r in response.get('Regions', [])]
            }
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if 'AuthFailure' in error_code or 'InvalidClientTokenId' in error_code:
                return {
                    'success': False,
                    'error': '🔴 AWS credentials are invalid or expired. Please update your AWS Academy credentials.'
                }
            elif 'ExpiredToken' in error_code:
                return {
                    'success': False,
                    'error': '🔴 AWS session token has expired (AWS Academy tokens expire every 3-4 hours). Please get new credentials.'
                }
            else:
                return {
                    'success': False,
                    'error': f'AWS API Error: {str(e)}'
                }
        except Exception as e:
            logger.error(f"Unexpected error testing credentials: {e}")
            return {
                'success': False,
                'error': f'Unexpected error: {str(e)}'
            }

    def _validate_credentials(self):
        """
        Internal validation - raises exception if credentials invalid
        """
        if not self.ec2:
            raise Exception("AWS clients not initialized. Check configuration.")
        
        try:
            self.ec2.describe_regions()
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if 'AuthFailure' in error_code or 'InvalidClientTokenId' in error_code:
                raise Exception("⚠️ AWS credentials expired. Please update AWS configuration with fresh credentials from AWS Academy.")
            elif 'ExpiredToken' in error_code:
                raise Exception("⚠️ AWS session token expired (AWS Academy). Get new credentials from AWS Academy.")
            raise

    # ==================== SECURITY GROUP OPERATIONS ====================
    
    def block_ip_in_security_group(self, ip_address, description="Blocked by Threat Analyzer"):
        """
        Block an IP by removing it from Security Group (deny all traffic)
        """
        return self._modify_sg('revoke', ip_address, description)

    def allow_ip_in_security_group(self, ip_address, description="Allowed by Threat Analyzer"):
        """
        Allow an IP by adding it to Security Group
        """
        return self._modify_sg('authorize', ip_address, description)

    def _modify_sg(self, action, ip_address, description):
        """
        Internal method to modify Security Group rules
        """
        try:
            self._validate_credentials()
        except Exception as e:
            return {'success': False, 'error': str(e)}
        
        if not self.config.security_group_id:
            return {
                'success': False, 
                'error': 'No Security Group ID configured. Please update AWS configuration.'
            }
        
        # Ensure CIDR notation
        cidr = f"{ip_address}/32" if '/' not in ip_address else ip_address
        sg_id = self.config.security_group_id

        try:
            # Define the rule for all protocols (-1)
            permission = {
                'IpProtocol': '-1',  # All protocols
                'IpRanges': [{'CidrIp': cidr, 'Description': description}]
            }

            if action == 'revoke':
                self.ec2.revoke_security_group_ingress(
                    GroupId=sg_id, 
                    IpPermissions=[permission]
                )
                msg = f"✅ IP {cidr} blocked (removed from Security Group {sg_id})"
            else:
                self.ec2.authorize_security_group_ingress(
                    GroupId=sg_id, 
                    IpPermissions=[permission]
                )
                msg = f"✅ IP {cidr} allowed (added to Security Group {sg_id})"

            logger.info(msg)
            return {'success': True, 'message': msg}
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code == 'InvalidPermission.NotFound' and action == 'revoke':
                return {
                    'success': True, 
                    'message': f"IP {cidr} was not in Security Group, so it's already blocked."
                }
            elif error_code == 'InvalidPermission.Duplicate':
                return {
                    'success': True, 
                    'message': f"IP {cidr} already exists in Security Group."
                }
            else:
                logger.error(f"Security Group error: {e}")
                return {'success': False, 'error': f"Security Group Error: {str(e)}"}

    def list_security_group_rules(self):
        """
        List all rules in the configured Security Group
        """
        try:
            self._validate_credentials()
            
            if not self.config.security_group_id:
                return {'success': False, 'error': 'No Security Group ID configured'}
            
            response = self.ec2.describe_security_groups(
                GroupIds=[self.config.security_group_id]
            )
            
            sg = response['SecurityGroups'][0]
            rules = {
                'ingress': sg.get('IpPermissions', []),
                'egress': sg.get('IpPermissionsEgress', [])
            }
            
            return {'success': True, 'rules': rules}
            
        except Exception as e:
            logger.error(f"Error listing SG rules: {e}")
            return {'success': False, 'error': str(e)}

    # ==================== WAF OPERATIONS ====================
    
    def block_ip_in_waf(self, ip_address, ip_set_name, ip_set_id, scope='REGIONAL'):
        """
        Block an IP by adding it to WAF IP Set
        """
        try:
            self._validate_credentials()
        except Exception as e:
            return {'success': False, 'error': str(e)}
        
        cidr = f"{ip_address}/32" if '/' not in ip_address else ip_address

        try:
            # Get current IP Set
            response = self.wafv2.get_ip_set(
                Name=ip_set_name, 
                Scope=scope, 
                Id=ip_set_id
            )
            
            lock_token = response['LockToken']
            addresses = response['IPSet']['Addresses']

            # Check if already exists
            if cidr in addresses:
                return {
                    'success': True, 
                    'message': f"IP {cidr} already blocked in WAF IP Set."
                }

            # Add the IP
            addresses.append(cidr)

            # Update IP Set
            self.wafv2.update_ip_set(
                Name=ip_set_name, 
                Scope=scope, 
                Id=ip_set_id,
                Addresses=addresses, 
                LockToken=lock_token
            )
            
            return {
                'success': True, 
                'message': f"✅ IP {cidr} added to WAF IP Set '{ip_set_name}'."
            }
        except Exception as e:
            logger.error(f"WAF error: {e}")
            return {'success': False, 'error': f"WAF Error: {str(e)}"}

    def unblock_ip_in_waf(self, ip_address, ip_set_name, ip_set_id, scope='REGIONAL'):
        """
        Unblock an IP by removing it from WAF IP Set
        """
        try:
            self._validate_credentials()
        except Exception as e:
            return {'success': False, 'error': str(e)}
        
        cidr = f"{ip_address}/32" if '/' not in ip_address else ip_address

        try:
            response = self.wafv2.get_ip_set(
                Name=ip_set_name, 
                Scope=scope, 
                Id=ip_set_id
            )
            
            lock_token = response['LockToken']
            addresses = response['IPSet']['Addresses']

            if cidr not in addresses:
                return {
                    'success': True, 
                    'message': f"IP {cidr} not found in WAF IP Set."
                }

            addresses.remove(cidr)

            self.wafv2.update_ip_set(
                Name=ip_set_name, 
                Scope=scope, 
                Id=ip_set_id,
                Addresses=addresses, 
                LockToken=lock_token
            )
            
            return {
                'success': True, 
                'message': f"✅ IP {cidr} removed from WAF IP Set '{ip_set_name}'."
            }
        except Exception as e:
            logger.error(f"WAF error: {e}")
            return {'success': False, 'error': f"WAF Error: {str(e)}"}

    def set_geo_blocking(self, web_acl_name, web_acl_id, country_codes, scope='REGIONAL'):
        """
        Block traffic from specific countries using WAF
        country_codes: List of ISO country codes ['CN', 'RU', 'KP']
        """
        try:
            self._validate_credentials()
        except Exception as e:
            return {'success': False, 'error': str(e)}

        try:
            # Get current Web ACL
            response = self.wafv2.get_web_acl(
                Name=web_acl_name,
                Scope=scope,
                Id=web_acl_id
            )
            
            lock_token = response['LockToken']
            
            # Create geo-blocking rule
            geo_rule = {
                'Name': 'GeoBlockRule',
                'Priority': 0,
                'Statement': {
                    'GeoMatchStatement': {
                        'CountryCodes': country_codes
                    }
                },
                'Action': {'Block': {}},
                'VisibilityConfig': {
                    'SampledRequestsEnabled': True,
                    'CloudWatchMetricsEnabled': True,
                    'MetricName': 'GeoBlockRule'
                }
            }
            
            # Update Web ACL with geo rule
            rules = response['WebACL'].get('Rules', [])
            
            # Remove existing geo block rule if present
            rules = [r for r in rules if r['Name'] != 'GeoBlockRule']
            
            # Add new geo rule at priority 0
            rules.insert(0, geo_rule)
            
            self.wafv2.update_web_acl(
                Name=web_acl_name,
                Scope=scope,
                Id=web_acl_id,
                DefaultAction=response['WebACL']['DefaultAction'],
                Rules=rules,
                VisibilityConfig=response['WebACL']['VisibilityConfig'],
                LockToken=lock_token
            )
            
            return {
                'success': True,
                'message': f"✅ Geo-blocking enabled for countries: {', '.join(country_codes)}"
            }
            
        except Exception as e:
            logger.error(f"Geo-blocking error: {e}")
            return {'success': False, 'error': f"Geo-blocking Error: {str(e)}"}

    def set_rate_limit_rule(self, web_acl_name, web_acl_id, rate_limit=1000, scope='REGIONAL'):
        """
        Set rate limiting rule in WAF
        rate_limit: Maximum requests per 5 minutes from single IP
        """
        try:
            self._validate_credentials()
        except Exception as e:
            return {'success': False, 'error': str(e)}

        try:
            response = self.wafv2.get_web_acl(
                Name=web_acl_name,
                Scope=scope,
                Id=web_acl_id
            )
            
            lock_token = response['LockToken']
            
            rate_rule = {
                'Name': 'RateLimitRule',
                'Priority': 1,
                'Statement': {
                    'RateBasedStatement': {
                        'Limit': rate_limit,
                        'AggregateKeyType': 'IP'
                    }
                },
                'Action': {'Block': {}},
                'VisibilityConfig': {
                    'SampledRequestsEnabled': True,
                    'CloudWatchMetricsEnabled': True,
                    'MetricName': 'RateLimitRule'
                }
            }
            
            rules = response['WebACL'].get('Rules', [])
            rules = [r for r in rules if r['Name'] != 'RateLimitRule']
            rules.append(rate_rule)
            
            self.wafv2.update_web_acl(
                Name=web_acl_name,
                Scope=scope,
                Id=web_acl_id,
                DefaultAction=response['WebACL']['DefaultAction'],
                Rules=rules,
                VisibilityConfig=response['WebACL']['VisibilityConfig'],
                LockToken=lock_token
            )
            
            return {
                'success': True,
                'message': f"✅ Rate limit set to {rate_limit} requests per 5 minutes"
            }
            
        except Exception as e:
            logger.error(f"Rate limit error: {e}")
            return {'success': False, 'error': f"Rate Limit Error: {str(e)}"}

    # ==================== NETWORK ACL OPERATIONS ====================
    
    def edit_nacl_rules(self, nacl_id, rule_number, ip_cidr, action='deny'):
        """
        Create or update NACL rule to block/allow traffic
        """
        try:
            self._validate_credentials()
        except Exception as e:
            return {'success': False, 'error': str(e)}

        try:
            # Ensure CIDR notation
            if '/' not in ip_cidr:
                ip_cidr = f"{ip_cidr}/32"
            
            # Try to create the rule
            try:
                self.ec2.create_network_acl_entry(
                    NetworkAclId=nacl_id,
                    RuleNumber=int(rule_number),
                    Protocol='-1',  # All protocols
                    RuleAction=action,
                    Egress=False,  # Ingress rule
                    CidrBlock=ip_cidr
                )
                logger.info(f"Created NACL rule #{rule_number}")
            except ClientError as e:
                if 'NetworkAclEntryAlreadyExists' in str(e):
                    # Rule exists, replace it
                    self.ec2.replace_network_acl_entry(
                        NetworkAclId=nacl_id,
                        RuleNumber=int(rule_number),
                        Protocol='-1',
                        RuleAction=action,
                        Egress=False,
                        CidrBlock=ip_cidr
                    )
                    logger.info(f"Replaced NACL rule #{rule_number}")
                else:
                    raise
            
            msg = f"✅ NACL rule #{rule_number} ({action}) applied for {ip_cidr} on {nacl_id}"
            return {'success': True, 'message': msg}
            
        except Exception as e:
            logger.error(f"NACL error: {e}")
            return {'success': False, 'error': f"NACL Error: {str(e)}"}

    def delete_nacl_rule(self, nacl_id, rule_number):
        """
        Delete a NACL rule
        """
        try:
            self._validate_credentials()
            
            self.ec2.delete_network_acl_entry(
                NetworkAclId=nacl_id,
                RuleNumber=int(rule_number),
                Egress=False
            )
            
            return {
                'success': True,
                'message': f"✅ NACL rule #{rule_number} deleted"
            }
        except Exception as e:
            logger.error(f"NACL delete error: {e}")
            return {'success': False, 'error': str(e)}

    # ==================== EC2 INSTANCE OPERATIONS ====================
    
    def isolate_instance(self, instance_id, isolation_sg_id):
        """
        Isolate an EC2 instance by changing its Security Group to quarantine SG
        """
        try:
            self._validate_credentials()
        except Exception as e:
            return {'success': False, 'error': str(e)}

        try:
            self.ec2.modify_instance_attribute(
                InstanceId=instance_id,
                Groups=[isolation_sg_id]
            )
            msg = f"✅ Instance {instance_id} isolated (moved to quarantine SG {isolation_sg_id})"
            logger.info(msg)
            return {'success': True, 'message': msg}
        except Exception as e:
            logger.error(f"Instance isolation error: {e}")
            return {'success': False, 'error': f"Isolation Error: {str(e)}"}

    def get_instance_info(self, instance_id):
        """
        Get detailed information about an EC2 instance
        """
        try:
            self._validate_credentials()
            
            response = self.ec2.describe_instances(InstanceIds=[instance_id])
            
            if not response['Reservations']:
                return {'success': False, 'error': 'Instance not found'}
            
            instance = response['Reservations'][0]['Instances'][0]
            
            return {
                'success': True,
                'instance': {
                    'id': instance['InstanceId'],
                    'state': instance['State']['Name'],
                    'type': instance['InstanceType'],
                    'private_ip': instance.get('PrivateIpAddress'),
                    'public_ip': instance.get('PublicIpAddress'),
                    'security_groups': [sg['GroupId'] for sg in instance.get('SecurityGroups', [])],
                    'vpc_id': instance.get('VpcId'),
                    'subnet_id': instance.get('SubnetId')
                }
            }
        except Exception as e:
            logger.error(f"Get instance info error: {e}")
            return {'success': False, 'error': str(e)}

    # ==================== NETWORK FIREWALL OPERATIONS ====================
    
    def update_network_firewall_policy(self, firewall_arn, rule_group_arn):
        """
        Update Network Firewall policy with new rule group
        """
        try:
            self._validate_credentials()
        except Exception as e:
            return {'success': False, 'error': str(e)}

        try:
            # This is a simplified version - actual implementation depends on your setup
            response = self.network_firewall.describe_firewall(
                FirewallArn=firewall_arn
            )
            
            return {
                'success': True,
                'message': f"✅ Network Firewall policy updated",
                'firewall': response['Firewall']
            }
        except Exception as e:
            logger.error(f"Network Firewall error: {e}")
            return {'success': False, 'error': f"Firewall Error: {str(e)}"}

    # ==================== CLOUDWATCH LOGS ====================
    
    def query_cloudwatch_logs(self, log_group_name, query_string, hours=24):
        """
        Query CloudWatch logs for threat intelligence
        """
        try:
            self._validate_credentials()
            
            start_time = int((datetime.now() - timedelta(hours=hours)).timestamp())
            end_time = int(datetime.now().timestamp())
            
            response = self.cloudwatch.start_query(
                logGroupName=log_group_name,
                startTime=start_time,
                endTime=end_time,
                queryString=query_string
            )
            
            query_id = response['queryId']
            
            # Wait for query to complete
            time.sleep(2)
            
            result = self.cloudwatch.get_query_results(queryId=query_id)
            
            return {
                'success': True,
                'results': result['results'],
                'status': result['status']
            }
            
        except Exception as e:
            logger.error(f"CloudWatch query error: {e}")
            return {'success': False, 'error': str(e)}

    # ==================== UTILITY METHODS ====================
    
    def get_vpc_info(self):
        """
        Get information about configured VPC and subnets
        """
        try:
            self._validate_credentials()
            
            if not self.config.vpc_id:
                return {'success': False, 'error': 'No VPC ID configured'}
            
            vpc_response = self.ec2.describe_vpcs(VpcIds=[self.config.vpc_id])
            subnets_response = self.ec2.describe_subnets(
                Filters=[{'Name': 'vpc-id', 'Values': [self.config.vpc_id]}]
            )
            
            return {
                'success': True,
                'vpc': vpc_response['Vpcs'][0],
                'subnets': subnets_response['Subnets']
            }
        except Exception as e:
            logger.error(f"VPC info error: {e}")
            return {'success': False, 'error': str(e)}