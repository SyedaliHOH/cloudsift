#!/usr/bin/env python3
"""
AWS ScoutSuite HTML Report Generator
Generates a beautiful, interactive HTML report with AWS CLI commands and CSV downloads

Usage:
    python3 generate_report.py <scoutsuite_results_file.js>
    python3 generate_report.py -f <scoutsuite_results_file.js>
"""

import json
import re
import csv
import io
import base64
import sys
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from datetime import datetime

COMMANDS_FILE = "commands.json"
DEFAULT_REGION = "us-east-1"

def load_scoutsuite(path: str) -> Dict:
    """Load and parse ScoutSuite results from JS file"""
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()
        raw = re.sub(r"^scoutsuite_results\s*=\s*", "", raw.strip())
    return json.loads(raw)

def load_commands(path: str) -> list:
    """Load command definitions from JSON file"""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("commands", [])

def extract_ids_from_path(path_str: str) -> Dict[str, str]:
    """Extract AWS resource IDs from the path string itself"""
    parts = path_str.split('.')
    ids = {}
    
    # Extract region
    for i, part in enumerate(parts):
        if part == "regions" and i + 1 < len(parts):
            ids['region'] = parts[i + 1]
    
    # Extract IDs from path by pattern matching
    for part in parts:
        if part.startswith('vpc-'):
            ids['vpc'] = part
        elif part.startswith('sg-'):
            ids['security_group'] = part
        elif part.startswith('vol-'):
            ids['volume'] = part
        elif part.startswith('snap-'):
            ids['snapshot'] = part
        elif part.startswith('subnet-'):
            ids['subnet'] = part
        elif part.startswith('acl-'):
            ids['network_acl'] = part
        elif part.startswith('i-'):
            ids['instance'] = part
    
    return ids

def is_iam_resource_id(part: str) -> bool:
    """Check if a path part is an IAM resource ID"""
    iam_prefixes = ['AIDA', 'AROA', 'AGPA', 'ANPA', 'AKIA']
    return any(part.startswith(prefix) for prefix in iam_prefixes)

def parse_resource_path(path_str: str, scout_data: Dict) -> Tuple[Optional[str], Dict, Dict]:
    """Parse ScoutSuite path string and extract resource data"""
    parts = path_str.split('.')
    
    # Extract IDs from path
    path_ids = extract_ids_from_path(path_str)
    
    # Extract region
    region = path_ids.get('region')
    
    # Navigate to the actual resource
    current = scout_data.get('services', {})
    
    # Determine where to stop
    stop_at = len(parts)
    
    # For IAM resources
    if parts[0] == 'iam' and len(parts) >= 3:
        if is_iam_resource_id(parts[2]) or parts[2].startswith('scoutid-'):
            stop_at = 3
    # For AWS Config regions - stop at region level
    elif parts[0] == 'config' and 'regions' in parts:
        # config.regions.ap-northeast-1.NotConfigured -> stop at ap-northeast-1
        region_idx = parts.index('regions')
        if region_idx + 1 < len(parts):
            stop_at = region_idx + 2
    # For EBS regional settings - navigate through the numeric index
    elif 'regional_settings' in parts:
        # ec2.regions.ca-west-1.regional_settings.0.NoDefaultEBSEncryption
        # Navigate to regional_settings.0
        regional_idx = parts.index('regional_settings')
        if regional_idx + 1 < len(parts) and parts[regional_idx + 1].isdigit():
            stop_at = regional_idx + 2
    else:
        # For other services, stop before property/attribute indicators
        for i in range(len(parts) - 1, -1, -1):
            # These are properties/attributes, not the resource itself
            if parts[i] in [
                'no_flowlog', 'no_mfa', 'encrypted', 'Encrypted', 
                'attributes', 'Properties', 'Policy', 'PolicyDocument', 'Statement',
                'rules', 'ingress', 'egress', 'inline_policies', 'AccessKeys', 
                'assume_role_policy', 'flow_logs', 'NotConfigured', 'NoDefaultEBSEncryption'
            ] or parts[i].isdigit():
                stop_at = i
            # Stop after resource IDs
            elif parts[i].startswith(('scoutid-', 'vol-', 'snap-', 'sg-', 'subnet-', 'acl-', 'vpc-', 'i-')):
                stop_at = i + 1
                break
    
    # Navigate through the path
    for part in parts[:stop_at]:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return region, {}, path_ids
    
    return region, current if isinstance(current, dict) else {}, path_ids

def extract_first_resource_from_finding(finding: Dict, scout_data: Dict) -> Tuple[Optional[str], Dict, Dict]:
    """Extract the FIRST resource from a finding"""
    items = finding.get("items", [])
    
    if not items or not isinstance(items, list):
        return None, {}, {}
    
    first_path = items[0]
    
    if not isinstance(first_path, str):
        return None, {}, {}
    
    region, resource, path_ids = parse_resource_path(first_path, scout_data)
    
    if region and "region" not in resource:
        resource["region"] = region
    
    return region, resource, path_ids

def extract_all_resources_from_finding(finding: Dict, scout_data: Dict) -> List[Dict]:
    """Extract ALL resources from a finding (for CSV generation)"""
    items = finding.get("items", [])
    resources = []
    
    if not items or not isinstance(items, list):
        return resources
    
    for item_path in items:
        if not isinstance(item_path, str):
            continue
        
        region, resource, path_ids = parse_resource_path(item_path, scout_data)
        
        if resource:
            if region and "region" not in resource:
                resource["region"] = region
            resources.append(resource)
    
    return resources

def fill_placeholders(cmd: str, resource: Dict, path_ids: Dict, region: Optional[str] = None) -> str:
    """Fill command placeholders with actual resource values"""
    
    if not resource and not path_ids:
        return cmd
    
    # Use provided region or extract from resource or path_ids
    region = region or resource.get('region') or path_ids.get('region') or DEFAULT_REGION
    
    # Extract core identifiers from resource
    resource_id = resource.get('id', '')
    resource_name = resource.get('name', resource.get('Name', ''))
    
    # Extract ARN
    resource_arn = (resource.get('arn') or resource.get('Arn') or 
                   resource.get('CertificateArn') or resource.get('LoadBalancerArn') or
                   resource.get('RoleArn') or resource.get('TrailARN') or
                   resource.get('PolicyArn') or resource.get('DBInstanceArn'))
    
    # For ACM certificates, prioritize CertificateArn over arn
    if resource.get('CertificateArn'):
        certificate_arn = resource.get('CertificateArn')
    else:
        certificate_arn = resource_arn
    
    # Build comprehensive mapping with descriptive names
    mapping = {
        # Generic
        "<Region>": region,
        "<ResourceId>": resource_id,
        "<ResourceName>": resource_name,
        "<ResourceArn>": resource_arn,
        
        # EC2 - Volumes
        "<VolumeId>": (path_ids.get('volume') or 
                       (resource_id if resource_id.startswith('vol-') else '') or 
                       resource.get('VolumeId', '')),
        
        # EC2 - Snapshots
        "<SnapshotId>": (path_ids.get('snapshot') or 
                         (resource_id if resource_id.startswith('snap-') else '') or 
                         resource.get('SnapshotId', '')),
        
        # EC2 - Instances
        "<InstanceId>": (path_ids.get('instance') or 
                         (resource_id if resource_id.startswith('i-') else '') or 
                         resource.get('InstanceId', '')),
        
        # EC2 - Security Groups
        "<SecurityGroupId>": (path_ids.get('security_group') or 
                              (resource_id if resource_id.startswith('sg-') else '') or 
                              resource.get('GroupId', '')),
        
        # EC2 - Network ACLs
        "<NetworkAclId>": (path_ids.get('network_acl') or 
                           (resource_id if resource_id.startswith('acl-') else '') or 
                           resource.get('NetworkAclId', '')),
        
        # EC2 - Subnets
        "<SubnetId>": (path_ids.get('subnet') or 
                       (resource_id if resource_id.startswith('subnet-') else '') or 
                       resource.get('SubnetId', '')),
        
        # VPC
        "<VpcId>": path_ids.get('vpc') or resource.get('VpcId', ''),
        
        # IAM - Roles
        "<RoleName>": resource_name or resource.get('RoleName', ''),
        
        # IAM - Users
        "<UserName>": resource_name or resource.get('UserName', ''),
        
        # IAM - Groups
        "<GroupName>": resource_name or resource.get('GroupName', ''),
        
        # IAM - Policies
        "<PolicyArn>": resource_arn or resource.get('PolicyArn', ''),
        
        # IAM - Access Keys
        "<AccessKeyId>": resource.get('AccessKeyId', '') or resource_id,
        
        # S3
        "<BucketName>": resource_name or resource.get('BucketName', ''),
        
        # RDS
        "<DBInstanceIdentifier>": resource_name or resource.get('DBInstanceIdentifier', ''),
        
        # ELB/ALB
        "<LoadBalancerArn>": resource_arn or resource.get('LoadBalancerArn', ''),
        
        # CloudTrail
        "<TrailArn>": resource_arn or resource.get('TrailARN', ''),
        "<TrailName>": resource_name or resource.get('TrailName', ''),
        
        # CloudWatch
        "<AlarmName>": resource_name or resource.get('AlarmName', ''),
        
        # Route53
        "<DomainName>": resource.get('DomainName', '') or resource_name,
        
        # ACM
        "<CertificateArn>": resource_arn or resource.get('CertificateArn', ''),
        
        # ACM
        "<CertificateArn>": certificate_arn or resource.get('CertificateArn', ''),
        
        # KMS
        "<KeyId>": resource_id if not resource_id.startswith(('vol-', 'snap-', 'sg-', 'subnet-', 'acl-', 'i-')) else resource.get('KeyId', ''),
        
        # CloudFormation
        "<StackName>": resource_name or resource.get('StackName', ''),
        
        # CloudFront
        "<DistributionId>": resource_id or resource.get('DistributionId', ''),
        
        # SES
        "<Identity>": resource_name or resource.get('Identity', ''),
    }
    
    # Apply replacements
    result = cmd
    for placeholder, value in mapping.items():
        if value and placeholder in result:
            result = result.replace(placeholder, str(value))
    
    return result

def generate_csv_data(finding: Dict, scout_data: Dict, csv_columns: str) -> str:
    """Generate CSV data for a finding"""
    resources = extract_all_resources_from_finding(finding, scout_data)
    
    if not resources or not csv_columns:
        return ""
    
    # Parse CSV column definition
    columns = [col.strip() for col in csv_columns.split(',') if col.strip()]
    
    if not columns:
        return ""
    
    # Add "No" column at the beginning
    columns_with_no = ['No'] + columns
    
    # Create CSV in memory
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=columns_with_no, extrasaction='ignore')
    writer.writeheader()
    
    # Map resource fields to CSV columns
    for idx, resource in enumerate(resources, 1):
        row = {'No': idx}  # Add row number
        
        for col in columns:
            value = ""
            
            # Special mappings first (most specific)
            if col in ['ARN', 'Arn']:
                value = resource.get('arn') or resource.get('Arn') or ""
            elif col in ['Name']:
                value = resource.get('name') or resource.get('Name') or ""
            elif col in ['ID', 'Id']:
                value = resource.get('id') or resource.get('Id') or ""
            elif col == 'Region':
                value = resource.get('region') or ""
            elif col == 'VPC':
                # VPC ID can be in multiple places
                value = (
                    resource.get('VpcId') or 
                    resource.get('vpc_id') or 
                    resource.get('VPC') or 
                    ""
                )
            elif col == 'Roles':
                # For IAM policies - extract role names from attached_to
                attached = resource.get('attached_to', {})
                roles = attached.get('roles', [])
                if isinstance(roles, list):
                    role_names = [r.get('name', '') if isinstance(r, dict) else str(r) for r in roles]
                    value = ', '.join(role_names)  # Use comma separation
                else:
                    value = str(roles)
            elif col == 'Users':
                # For IAM policies - extract user names from attached_to
                attached = resource.get('attached_to', {})
                users = attached.get('users', [])
                if isinstance(users, list):
                    user_names = [u.get('name', '') if isinstance(u, dict) else str(u) for u in users]
                    value = ', '.join(user_names)  # Use comma separation
                else:
                    value = str(users)
            elif col == 'Encrypted':
                value = str(resource.get('Encrypted', resource.get('encrypted', "")))
            elif col == 'MultiAZ':
                value = str(resource.get('MultiAZ', ""))
            elif col == 'PubliclyAccessible':
                value = str(resource.get('PubliclyAccessible', ""))
            elif col == 'BackupRetentionPeriod':
                value = str(resource.get('BackupRetentionPeriod', ""))
            elif col == 'AZ':
                value = resource.get('AvailabilityZone') or resource.get('AZ') or ""
            elif col == 'DNS':
                value = resource.get('DNSName') or resource.get('DNS') or ""
            elif col == 'MultiRegion':
                value = str(resource.get('IsMultiRegionTrail', resource.get('MultiRegion', "")))
            elif col == 'Ingress':
                # For security groups
                value = str(resource.get('IpPermissions', resource.get('Ingress', "")))
            elif col == 'Egress':
                # For security groups
                value = str(resource.get('IpPermissionsEgress', resource.get('Egress', "")))
            elif col == 'Identity':
                value = resource.get('Identity') or resource.get('name') or ""
            elif col == 'region':
                # For region-level checks like AWS Config
                value = resource.get('region') or ""
            elif col == 'ebs_default_encryption_key_id':
                value = resource.get('ebs_default_encryption_key_id') or ""
            elif col == 'ebs_encryption_default':
                value = str(resource.get('ebs_encryption_default', ""))
            elif col == 'Region':
                # For regional settings and region-level resources
                value = resource.get('region') or resource.get('Region') or ""
            elif col == 'CreateDate':
                # For IAM resources
                value = resource.get('CreateDate') or resource.get('create_date') or ""
            elif col == 'PasswordEnabled':
                # For IAM credential reports
                value = str(resource.get('password_enabled', resource.get('PasswordEnabled', "")))
            elif col == 'AccessKey1LastUsed':
                # For IAM credential reports - access key 1 last used date
                value = resource.get('access_key_1_last_used_date', "")
            elif col == 'AccessKey2LastUsed':
                # For IAM credential reports - access key 2 last used date
                value = resource.get('access_key_2_last_used_date', "")
            elif col == 'DataEventsEnabled':
                # For CloudTrail
                value = str(resource.get('data_events_enabled', resource.get('DataEventsEnabled', "")))
            elif col == 'VpcId':
                # For ELB and other VPC resources
                value = resource.get('VpcId') or resource.get('vpc_id') or ""
            elif col == 'DNSName':
                # For ELB resources
                value = resource.get('DNSName') or resource.get('dns_name') or ""
            elif col == 'PolicyName':
                # For IAM policies
                value = resource.get('PolicyName') or resource.get('name') or ""
            elif col == 'RiskPattern':
                # For managed policy combined check
                value = resource.get('risk_pattern', "")
            elif col == 'AffectedActions':
                # For managed policy combined check
                value = resource.get('affected_actions', "")
            elif col == 'AttachedRoles':
                # For managed policy combined check - join roles with newline
                roles = resource.get('attached_roles', [])
                if isinstance(roles, list):
                    value = "\n".join(roles)
                else:
                    value = str(roles)
            else:
                # Try generic field name variations
                value = (
                    resource.get(col) or 
                    resource.get(col.lower()) or 
                    resource.get(col.upper()) or
                    resource.get(col.replace(' ', '')) or
                    resource.get(col.replace('_', '')) or
                    ""
                )
            
            row[col] = str(value) if value else ""
        
        writer.writerow(row)
    
    return output.getvalue()

def generate_managed_policy_csv(policy_items: Dict[str, List[str]], scout_data: Dict) -> str:
    """Generate combined CSV for managed policy findings"""
    # Organize by policy ARN to avoid duplicates
    policy_data = {}
    
    # Process PassRole findings
    for item_path in policy_items.get('PassRole', []):
        parts = item_path.split('.')
        policy_id = parts[2] if len(parts) > 2 else None
        if not policy_id:
            continue
        
        # Navigate to policy
        policy = scout_data.get('services', {}).get('iam', {}).get('policies', {}).get(policy_id, {})
        policy_name = policy.get('name', '')
        
        if policy_name not in policy_data:
            policy_data[policy_name] = {
                'name': policy_name,
                'risks': set(),
                'actions': set(),
                'roles': set()
            }
        
        policy_data[policy_name]['risks'].add('iam:PassRole allowed for all resources')
        policy_data[policy_name]['actions'].add('iam:PassRole')
        
        # Extract attached roles
        attached = policy.get('attached_to', {}).get('roles', [])
        for role in attached:
            if isinstance(role, dict):
                policy_data[policy_name]['roles'].add(role.get('name', ''))
            else:
                policy_data[policy_name]['roles'].add(str(role))
    
    # Process NotActions findings
    for item_path in policy_items.get('NotActions', []):
        parts = item_path.split('.')
        policy_id = parts[2] if len(parts) > 2 else None
        if not policy_id:
            continue
        
        policy = scout_data.get('services', {}).get('iam', {}).get('policies', {}).get(policy_id, {})
        policy_name = policy.get('name', '')
        
        if policy_name not in policy_data:
            policy_data[policy_name] = {
                'name': policy_name,
                'risks': set(),
                'actions': set(),
                'roles': set()
            }
        
        policy_data[policy_name]['risks'].add('Use of NotAction')
        policy_data[policy_name]['actions'].add('NotAction')
        
        attached = policy.get('attached_to', {}).get('roles', [])
        for role in attached:
            if isinstance(role, dict):
                policy_data[policy_name]['roles'].add(role.get('name', ''))
            else:
                policy_data[policy_name]['roles'].add(str(role))
    
    # Process AssumeRole findings
    for item_path in policy_items.get('AssumeRole', []):
        parts = item_path.split('.')
        policy_id = parts[2] if len(parts) > 2 else None
        if not policy_id:
            continue
        
        policy = scout_data.get('services', {}).get('iam', {}).get('policies', {}).get(policy_id, {})
        policy_name = policy.get('name', '')
        
        if policy_name not in policy_data:
            policy_data[policy_name] = {
                'name': policy_name,
                'risks': set(),
                'actions': set(),
                'roles': set()
            }
        
        policy_data[policy_name]['risks'].add('sts:AssumeRole allowed broadly')
        policy_data[policy_name]['actions'].add('sts:AssumeRole')
        
        attached = policy.get('attached_to', {}).get('roles', [])
        for role in attached:
            if isinstance(role, dict):
                policy_data[policy_name]['roles'].add(role.get('name', ''))
            else:
                policy_data[policy_name]['roles'].add(str(role))
    
    # Generate CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['No', 'PolicyName', 'RiskPattern', 'AffectedActions', 'AttachedRoles'])
    
    for idx, (policy_name, data) in enumerate(sorted(policy_data.items()), 1):
        risk_pattern = '; '.join(sorted(data['risks']))
        affected_actions = '; '.join(sorted(data['actions']))
        attached_roles = '\n'.join(sorted(data['roles']))
        
        writer.writerow([idx, policy_name, risk_pattern, affected_actions, attached_roles])
    
    return output.getvalue()

def get_severity_order(severity: str) -> int:
    """Return sorting order for severity"""
    severity_map = {
        "danger": 0,
        "high": 0,
        "warning": 1,
        "medium": 1,
        "info": 2,
        "low": 2
    }
    return severity_map.get(severity.lower(), 99)

def normalize_finding_title(title: str) -> str:
    """Normalize finding titles"""
    return title

def collect_findings_with_commands(scout_data: Dict, commands: List[Dict]) -> List[Dict]:
    """Collect all findings with their commands and CSV data"""
    findings_list = []
    services = scout_data.get("services", {})
    
    # Create a mapping of title to order index from commands list
    title_to_order = {cmd["title"]: idx for idx, cmd in enumerate(commands)}
    
    # Track combined findings
    key_rotation_items = []
    managed_policy_items = {
        'PassRole': [],
        'NotActions': [],
        'AssumeRole': []
    }
    
    for service_name, service_data in services.items():
        findings = service_data.get("findings", {})
        
        for finding_key, finding in findings.items():
            flagged_count = finding.get("flagged_items", 0)
            
            if flagged_count == 0:
                continue
            
            title = finding.get("description", "Unknown Finding")
            level = finding.get("level", "unknown")
            
            # Handle Key Rotation combination
            if "Lack of Key Rotation for 90 Days" in title:
                key_rotation_items.extend(finding.get("items", []))
                continue  # Skip individual processing
            
            # Handle Managed Policy combination
            if 'Managed Policy Allows "iam:PassRole"' in title:
                managed_policy_items['PassRole'].extend(finding.get("items", []))
                continue
            elif 'Managed Policy Allows "NotActions"' in title:
                managed_policy_items['NotActions'].extend(finding.get("items", []))
                continue
            elif 'Managed Policy Allows "sts:AssumeRole"' in title:
                managed_policy_items['AssumeRole'].extend(finding.get("items", []))
                continue
            
            normalized_title = normalize_finding_title(title)
            
            # Find matching command definition
            cmd_def = next((c for c in commands if c["title"] == normalized_title), None)
            
            if not cmd_def:
                continue
            
            # Extract first resource for command filling
            region, resource, path_ids = extract_first_resource_from_finding(finding, scout_data)
            
            # Fill placeholders in commands with actual resource data
            filled_commands = []
            for cmd_template in cmd_def.get("commands", []):
                filled_cmd = fill_placeholders(cmd_template, resource, path_ids, region)
                filled_commands.append(filled_cmd)
            
            # Get CSV data if columns are defined
            csv_data = ""
            csv_columns = cmd_def.get("csv", "")
            if csv_columns and csv_columns.strip():
                csv_data = generate_csv_data(finding, scout_data, csv_columns)
            
            # Get order index from commands.json
            order_index = title_to_order.get(normalized_title, 9999)
            
            findings_list.append({
                'service': service_name,
                'title': title,
                'level': level,
                'count': flagged_count,
                'commands': filled_commands,
                'csv_data': csv_data,
                'csv_columns': csv_columns,
                'pafa': cmd_def.get("pafa", ""),
                'order_index': order_index
            })
    
    # Add combined Key Rotation finding
    if key_rotation_items:
        combined_finding = {
            'items': key_rotation_items,
            'flagged_items': len(key_rotation_items),
            'description': 'Lack of Key Rotation for 90 Days',
            'level': 'danger'
        }
        cmd_def = next((c for c in commands if c["title"] == "Lack of Key Rotation for 90 Days"), None)
        if cmd_def:
            region, resource, path_ids = extract_first_resource_from_finding(combined_finding, scout_data)
            filled_commands = []
            for cmd_template in cmd_def.get("commands", []):
                filled_cmd = fill_placeholders(cmd_template, resource, path_ids, region)
                filled_commands.append(filled_cmd)
            
            csv_data = ""
            csv_columns = cmd_def.get("csv", "")
            if csv_columns and csv_columns.strip():
                csv_data = generate_csv_data(combined_finding, scout_data, csv_columns)
            
            order_index = title_to_order.get("Lack of Key Rotation for 90 Days", 9999)
            
            findings_list.append({
                'service': 'iam',
                'title': 'Lack of Key Rotation for 90 Days',
                'level': 'danger',
                'count': len(key_rotation_items),
                'commands': filled_commands,
                'csv_data': csv_data,
                'csv_columns': csv_columns,
                'pafa': cmd_def.get("pafa", ""),
                'order_index': order_index
            })
    
    # Add combined Managed Policy finding
    all_managed_items = []
    for items in managed_policy_items.values():
        all_managed_items.extend(items)
    
    if all_managed_items:
        combined_finding = {
            'items': all_managed_items,
            'flagged_items': len(all_managed_items),
            'description': 'Managed Policies Allow Overly Broad IAM Access',
            'level': 'danger'
        }
        cmd_def = next((c for c in commands if c["title"] == "Managed Policies Allow Overly Broad IAM Access"), None)
        if cmd_def:
            # Special CSV generation for managed policies
            csv_data = generate_managed_policy_csv(managed_policy_items, scout_data)
            
            region, resource, path_ids = extract_first_resource_from_finding(combined_finding, scout_data)
            filled_commands = []
            for cmd_template in cmd_def.get("commands", []):
                filled_cmd = fill_placeholders(cmd_template, resource, path_ids, region)
                filled_commands.append(filled_cmd)
            
            order_index = title_to_order.get("Managed Policies Allow Overly Broad IAM Access", 9999)
            
            findings_list.append({
                'service': 'iam',
                'title': 'Managed Policies Allow Overly Broad IAM Access',
                'level': 'danger',
                'count': len(set(all_managed_items)),  # Unique count since same policy can appear in multiple checks
                'commands': filled_commands,
                'csv_data': csv_data,
                'csv_columns': cmd_def.get("csv", ""),
                'pafa': cmd_def.get("pafa", ""),
                'order_index': order_index
            })
    
    return findings_list

def generate_html_report(findings: List[Dict], output_file: str, input_filename: str):
    """Generate a beautiful HTML report"""
    
    # Sort by order_index (which preserves commands.json order)
    # The order in commands.json already has HIGH first, then MEDIUM
    findings.sort(key=lambda f: f.get('order_index', 9999))
    
    # Count statistics
    high_count = sum(1 for f in findings if f['level'].lower() in ['high', 'danger'])
    medium_count = sum(1 for f in findings if f['level'].lower() in ['medium', 'warning'])
    total_count = len(findings)
    
    # Generate timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS ScoutSuite - Security Findings Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 700;
        }}
        
        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .stats {{
            display: flex;
            justify-content: space-around;
            padding: 30px;
            background: #f8f9fa;
            border-bottom: 1px solid #e9ecef;
        }}
        
        .stat-card {{
            text-align: center;
            padding: 20px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            min-width: 150px;
        }}
        
        .stat-number {{
            font-size: 2.5em;
            font-weight: 700;
            margin-bottom: 5px;
        }}
        
        .stat-label {{
            color: #6c757d;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .stat-high {{ color: #dc3545; }}
        .stat-medium {{ color: #fd7e14; }}
        .stat-total {{ color: #6c757d; }}
        .stat-validated {{ color: #dc3545; }}
        
        .filter-controls {{
            max-width: 1200px;
            margin: 20px auto 30px;
            padding: 20px;
            background: white;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 20px;
            flex-wrap: wrap;
        }}
        
        .filter-toggle {{
            display: flex;
            align-items: center;
            gap: 10px;
            cursor: pointer;
            font-size: 1.1em;
            font-weight: 600;
        }}
        
        .filter-toggle input[type="checkbox"] {{
            width: 20px;
            height: 20px;
            cursor: pointer;
        }}
        
        .toggle-label {{
            user-select: none;
        }}
        
        .clear-all-btn {{
            background: #dc3545;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 6px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
        }}
        
        .clear-all-btn:hover {{
            background: #c82333;
            transform: scale(1.05);
        }}
        
        .validate-btn {{
            position: absolute;
            top: 12px;
            right: 15px;
            background: #6c757d;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            font-size: 0.85em;
            transition: all 0.3s ease;
            z-index: 100;
        }}
        
        .validate-btn:hover {{
            background: #5a6268;
        }}
        
        .validate-btn.validated {{
            background: #dc3545;
        }}
        
        .validate-btn.validated::before {{
            content: "✗ ";
        }}
        
        .finding-card.validated {{
            border-left: 5px solid #dc3545;
            background: linear-gradient(to right, #fff5f5 0%, white 50px);
        }}
        
        .finding-card.hidden {{
            display: none !important;
        }}
        
        .copy-notification {{
            position: fixed;
            top: 20px;
            right: 20px;
            background: #28a745;
            color: white;
            padding: 15px 25px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            opacity: 0;
            transform: translateY(-20px);
            transition: all 0.3s ease;
            z-index: 10000;
            font-weight: 600;
        }}
        
        .copy-notification.show {{
            opacity: 1;
            transform: translateY(0);
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .severity-section {{
            margin-bottom: 40px;
        }}
        
        .severity-header {{
            display: flex;
            align-items: center;
            padding: 15px 20px;
            margin-bottom: 20px;
            border-radius: 8px;
            font-size: 1.5em;
            font-weight: 700;
            color: white;
        }}
        
        .severity-high {{
            background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);
        }}
        
        .severity-medium {{
            background: linear-gradient(135deg, #fd7e14 0%, #e8590c 100%);
        }}
        
        .finding-card {{
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            margin-bottom: 15px;
            overflow: hidden;
            transition: all 0.3s ease;
        }}
        
        .finding-card:hover {{
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        }}
        
        .finding-header {{
            position: relative;
            padding: 15px 20px;
            background: #f8f9fa;
            border-bottom: 1px solid #dee2e6;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            user-select: none;
        }}
        
        .finding-header:hover {{
            background: #e9ecef;
        }}
        
        .finding-header:active {{
            background: #dee2e6;
        }}
        
        .finding-left {{
            display: flex;
            align-items: center;
            flex: 1;
        }}
        
        .finding-title {{
            font-weight: 600;
            font-size: 1.05em;
            color: #212529;
        }}
        
        .finding-right {{
            display: flex;
            align-items: center;
            gap: 10px;
            padding-right: 110px;
        }}
        
        .finding-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
        }}
        
        .badge-high {{
            background: #dc3545;
            color: white;
        }}
        
        .badge-medium {{
            background: #fd7e14;
            color: white;
        }}
        
        .finding-count {{
            background: #6c757d;
            color: white;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
        }}
        
        .service-tag {{
            display: inline-block;
            background: #e9ecef;
            color: #495057;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: 600;
            margin-right: 12px;
            text-transform: uppercase;
        }}
        
        .finding-body {{
            padding: 20px;
            background: white;
        }}
        
        .command-block {{
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 6px;
            margin-bottom: 12px;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', monospace;
            font-size: 0.9em;
            position: relative;
            overflow-x: auto;
        }}
        
        .command-block pre {{
            margin: 0;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
        
        .copy-btn {{
            position: absolute;
            top: 10px;
            right: 10px;
            background: #667eea;
            color: white;
            border: none;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.85em;
            transition: all 0.3s ease;
            z-index: 10;
        }}
        
        .copy-btn:hover {{
            background: #5568d3;
            transform: scale(1.05);
        }}
        
        .copy-btn.copied {{
            background: #28a745;
        }}
        
        .download-section {{
            margin-top: 15px;
            padding: 15px;
            background: #e7f3ff;
            border-radius: 6px;
            border-left: 4px solid #0066cc;
        }}
        
        .download-btn {{
            display: inline-block;
            background: #0066cc;
            color: white;
            padding: 10px 20px;
            border-radius: 6px;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s ease;
            border: none;
            cursor: pointer;
            font-size: 0.95em;
        }}
        
        .download-btn:hover {{
            background: #0052a3;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0, 102, 204, 0.3);
        }}
        
        .pafa-info {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 12px 15px;
            margin-top: 15px;
            border-radius: 4px;
            font-size: 0.9em;
        }}
        
        .pafa-label {{
            font-weight: 700;
            color: #856404;
            margin-right: 8px;
        }}
        
        .copy-notification {{
            position: fixed;
            top: 20px;
            right: 20px;
            background: #28a745;
            color: white;
            padding: 15px 20px;
            border-radius: 6px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            display: none;
            z-index: 1000;
            animation: slideIn 0.3s ease;
        }}
        
        .copy-notification.show {{
            display: block;
        }}
        
        @keyframes slideIn {{
            from {{
                transform: translateX(400px);
                opacity: 0;
            }}
            to {{
                transform: translateX(0);
                opacity: 1;
            }}
        }}
        
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #6c757d;
            font-size: 0.9em;
            border-top: 1px solid #dee2e6;
        }}
        
        @media print {{
            body {{
                background: white;
                padding: 0;
            }}
            .container {{
                box-shadow: none;
            }}
            .copy-btn {{
                display: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="copy-notification" id="copyNotification">
        ✓ Copied to clipboard!
    </div>
    
    <div class="container">
        <div class="header">
            <h1>🔒 AWS Security Findings Report</h1>
            <p>ScoutSuite CLI Commands & Resources</p>
            <p style="font-size: 0.9em; opacity: 0.8;">Generated on {timestamp}</p>
            <p style="font-size: 0.85em; opacity: 0.7; margin-top: 5px;">Source: {input_filename}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number stat-high" id="high-count">{high_count}</div>
                <div class="stat-label">High Severity</div>
            </div>
            <div class="stat-card">
                <div class="stat-number stat-medium" id="medium-count">{medium_count}</div>
                <div class="stat-label">Medium Severity</div>
            </div>
            <div class="stat-card">
                <div class="stat-number stat-total" id="total-count">{total_count}</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-number stat-validated" id="validated-count">0</div>
                <div class="stat-label">Invalid</div>
            </div>
        </div>
        
        <div class="filter-controls">
            <label class="filter-toggle">
                <input type="checkbox" id="showOnlyValid" onchange="toggleValidFilter()">
                <span class="toggle-label">📋 Show Only Valid Findings (Hide Invalid)</span>
            </label>
            <button class="clear-all-btn" onclick="clearAllValidations()">🗑️ Clear All Invalid Marks</button>
        </div>
        
        <div id="copyNotification" class="copy-notification"></div>
        
        <div class="content">
"""
    
    # Generate findings by severity
    current_severity = None
    csv_counter = 1  # Track CSV file numbers
    
    for finding in findings:
        severity_display = "High" if finding['level'].lower() in ['high', 'danger'] else "Medium"
        
        # Add severity section header
        if current_severity != severity_display:
            if current_severity is not None:
                html_content += "        </div>\n"
            
            current_severity = severity_display
            severity_class = "severity-high" if severity_display == "High" else "severity-medium"
            
            html_content += f"""
            <div class="severity-section">
                <div class="severity-header {severity_class}">
                    🚨 {severity_display.upper()} SEVERITY FINDINGS
                </div>
"""
        
        # Generate finding card
        service = finding['service']
        title = finding['title']
        count = finding['count']
        commands = finding['commands']
        csv_data = finding['csv_data']
        pafa = finding['pafa']
        
        badge_class = "badge-high" if severity_display == "High" else "badge-medium"
        
        # Create safe ID for title copying and validation
        title_id = f"title_{service}_{title.replace(' ', '_')}".replace('"', '').replace("'", "").replace('/', '_').replace('(', '').replace(')', '')
        finding_id = f"finding_{service}_{title.replace(' ', '_')}".replace('"', '').replace("'", "").replace('/', '_').replace('(', '').replace(')', '')
        
        html_content += f"""
                <div class="finding-card" id="{finding_id}" data-finding-id="{finding_id}" data-finding-number="{csv_counter}">
                    <div class="finding-header" onclick="copyTitle('{title_id}', '{finding_id}')">
                        <button class="validate-btn" onclick="event.stopPropagation(); toggleValidation('{finding_id}')">Mark Invalid</button>
                        <div class="finding-left">
                            <span class="service-tag">{service}</span>
                            <span class="finding-title" id="{title_id}">{title}</span>
                        </div>
                        <div class="finding-right">
                            <span class="finding-badge {badge_class}">{severity_display}</span>
                            <span class="finding-count">{count} affected</span>
                        </div>
                    </div>
                    <div class="finding-body">
"""
        
        # Add commands
        for idx, cmd in enumerate(commands, 1):
            cmd_id = f"{service}_{title.replace(' ', '_')}_{idx}".replace('"', '').replace("'", "").replace('/', '_').replace('(', '').replace(')', '')
            # Escape HTML in command
            cmd_escaped = cmd.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            html_content += f"""
                        <div class="command-block">
                            <button class="copy-btn" onclick="copyCommand(this, '{cmd_id}')">Copy</button>
                            <pre id="{cmd_id}">{cmd_escaped}</pre>
                        </div>
"""
        
        # Add PAFA info if available
        if pafa:
            html_content += f"""
                        <div class="pafa-info">
                            <span class="pafa-label">Pass/Fail Criteria:</span>
                            {pafa}
                        </div>
"""
        
        # Add CSV download if available
        if csv_data:
            csv_base64 = base64.b64encode(csv_data.encode('utf-8')).decode('utf-8')
            # Add number prefix to filename
            csv_filename = f"{csv_counter}_{service}_{title.replace(' ', '_')}.csv".replace('"', '').replace("'", "").replace('/', '_').replace('(', '').replace(')', '')
            csv_counter += 1  # Increment counter
            
            html_content += f"""
                        <div class="download-section">
                            <strong>📊 Resource Data Available:</strong>
                            <br><br>
                            <button class="download-btn" onclick="downloadCSV('{csv_base64}', '{csv_filename}')">
                                ⬇️ Download CSV Report
                            </button>
                        </div>
"""
        
        html_content += """
                    </div>
                </div>
"""
    
    # Close last severity section
    if current_severity is not None:
        html_content += "            </div>\n"
    
    # Add footer and JavaScript
    html_content += f"""
        </div>
        
        <div class="footer">
            Generated by AWS ScoutSuite Report Generator | {total_count} findings analyzed | Click finding titles to copy them
        </div>
    </div>
    
    <script>
        function showNotification(message) {{
            const notification = document.getElementById('copyNotification');
            notification.textContent = message || '✓ Copied to clipboard!';
            notification.classList.add('show');
            
            setTimeout(() => {{
                notification.classList.remove('show');
            }}, 2000);
        }}
        
        function copyTitle(titleId, findingId) {{
            const element = document.getElementById(titleId);
            const findingCard = document.getElementById(findingId);
            const showOnlyValid = document.getElementById('showOnlyValid').checked;
            
            let text = element.textContent;
            
            // Add number prefix based on current view
            if (showOnlyValid) {{
                // Get only valid (non-invalid) findings
                const validCards = Array.from(document.querySelectorAll('.finding-card:not(.validated)'));
                const index = validCards.indexOf(findingCard);
                if (index >= 0) {{
                    text = `${{index + 1}}_${{text}}`;
                }}
            }} else {{
                // Use original number from data attribute
                const originalNumber = findingCard.getAttribute('data-finding-number');
                if (originalNumber) {{
                    text = `${{originalNumber}}_${{text}}`;
                }}
            }}
            
            navigator.clipboard.writeText(text).then(() => {{
                showNotification('✓ Title copied: ' + text.substring(0, 40) + '...');
            }}).catch(err => {{
                console.error('Failed to copy title:', err);
            }});
        }}
        
        function copyCommand(btn, elementId) {{
            const element = document.getElementById(elementId);
            const text = element.textContent;
            
            navigator.clipboard.writeText(text).then(() => {{
                const originalText = btn.textContent;
                btn.textContent = 'Copied!';
                btn.classList.add('copied');
                
                setTimeout(() => {{
                    btn.textContent = originalText;
                    btn.classList.remove('copied');
                }}, 2000);
            }}).catch(err => {{
                console.error('Failed to copy command:', err);
            }});
        }}
        
        function downloadCSV(base64Data, filename) {{
            // Get valid findings if filter is active
            const showOnlyValid = document.getElementById('showOnlyValid').checked;
            
            if (showOnlyValid) {{
                // Renumber CSV for valid findings only
                const csvContent = atob(base64Data);
                const lines = csvContent.split('\\n');
                
                if (lines.length > 1) {{
                    // Renumber the "No" column
                    const validFindings = getValidatedFindings();
                    const currentFindingCards = Array.from(document.querySelectorAll('.finding-card:not(.hidden)'));
                    const currentIndex = currentFindingCards.findIndex(card => {{
                        const downloadBtn = card.querySelector('.download-btn');
                        return downloadBtn && downloadBtn.getAttribute('onclick').includes(filename);
                    }});
                    
                    if (currentIndex >= 0) {{
                        const newNumber = currentIndex + 1;
                        // Update filename with new number
                        filename = filename.replace(/^\\d+_/, newNumber + '_');
                    }}
                }}
            }}
            
            const csvContent = atob(base64Data);
            const blob = new Blob([csvContent], {{ type: 'text/csv' }});
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        }}
        
        // Validation functions (now for Invalid marking)
        function toggleValidation(findingId) {{
            const card = document.getElementById(findingId);
            const btn = card.querySelector('.validate-btn');
            
            const isInvalid = card.classList.toggle('validated');
            
            if (isInvalid) {{
                btn.textContent = 'Invalid';
            }} else {{
                btn.textContent = 'Mark Invalid';
            }}
            
            // Save to localStorage
            saveValidationState();
            updateValidatedCount();
        }}
        
        function toggleValidFilter() {{
            const showOnlyValid = document.getElementById('showOnlyValid').checked;
            const allCards = document.querySelectorAll('.finding-card');
            
            if (showOnlyValid) {{
                // Hide invalid findings, show valid ones
                allCards.forEach(card => {{
                    if (card.classList.contains('validated')) {{
                        card.classList.add('hidden');
                    }}
                }});
                renumberValidCSVs();
            }} else {{
                allCards.forEach(card => {{
                    card.classList.remove('hidden');
                }});
            }}
        }}
        
        function clearAllValidations() {{
            if (!confirm('Clear all invalid marks? This cannot be undone.')) {{
                return;
            }}
            
            const allCards = document.querySelectorAll('.finding-card.validated');
            allCards.forEach(card => {{
                card.classList.remove('validated');
                const btn = card.querySelector('.validate-btn');
                btn.textContent = 'Mark Invalid';
            }});
            
            document.getElementById('showOnlyValid').checked = false;
            toggleValidFilter();
            
            localStorage.removeItem('validatedFindings');
            updateValidatedCount();
            showNotification('✓ All invalid marks cleared!');
        }}
        
        function saveValidationState() {{
            const validatedIds = [];
            document.querySelectorAll('.finding-card.validated').forEach(card => {{
                validatedIds.push(card.getAttribute('data-finding-id'));
            }});
            localStorage.setItem('validatedFindings', JSON.stringify(validatedIds));
        }}
        
        function loadValidationState() {{
            const savedIds = localStorage.getItem('validatedFindings');
            if (savedIds) {{
                const validatedIds = JSON.parse(savedIds);
                validatedIds.forEach(id => {{
                    const card = document.getElementById(id);
                    if (card) {{
                        card.classList.add('validated');
                        const btn = card.querySelector('.validate-btn');
                        if (btn) {{
                            btn.textContent = 'Invalid';
                        }}
                    }}
                }});
                updateValidatedCount();
            }}
        }}
        
        function updateValidatedCount() {{
            const count = document.querySelectorAll('.finding-card.validated').length;
            document.getElementById('validated-count').textContent = count;
        }}
        
        function getValidatedFindings() {{
            // Get invalid findings
            return Array.from(document.querySelectorAll('.finding-card.validated'));
        }}
        
        function getValidFindings() {{
            // Get valid (non-invalid) findings
            return Array.from(document.querySelectorAll('.finding-card:not(.validated)'));
        }}
        
        function renumberValidCSVs() {{
            // This updates CSV filenames when filtered to show only valid
            const validCards = getValidFindings();
            validCards.forEach((card, index) => {{
                const downloadBtns = card.querySelectorAll('[onclick*="downloadCSV"]');
                downloadBtns.forEach(btn => {{
                    const onclick = btn.getAttribute('onclick');
                    // Update the number prefix in filename
                    const newOnclick = onclick.replace(/downloadCSV\\('([^']+)',\\s*'\\d+_/, 
                        `downloadCSV('$1', '${{index + 1}}_`);
                    btn.setAttribute('onclick', newOnclick);
                }});
            }});
        }}
        
        // Load validation state on page load
        document.addEventListener('DOMContentLoaded', function() {{
            loadValidationState();
        }});
    </script>
</body>
</html>
"""
    
    # Write to file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)

def sanitize_filename(title: str) -> str:
    """Convert a finding title into a safe screenshot filename base"""
    name = re.sub(r'[^A-Za-z0-9]+', '_', title).strip('_')
    return name or "finding"

def bash_escape(cmd: str) -> str:
    """Escape a command so it is safe inside a bash double-quoted string"""
    cmd = cmd.replace('\\', '\\\\')
    cmd = cmd.replace('`', '\\`')
    cmd = cmd.replace('$', '\\$')
    cmd = cmd.replace('"', '\\"')
    return cmd

def iter_findings_with_slugs(findings: List[Dict]) -> List[Tuple[str, str, List[str]]]:
    """Yield (title, slug, commands) for each finding that has commands.

    Slugs are stable and collision-free so the same finding maps to the same
    base name across the screenshot script and the verification script.
    """
    used_names: Dict[str, int] = {}
    out: List[Tuple[str, str, List[str]]] = []

    for finding in findings:
        commands = [c.strip() for c in finding.get('commands', []) if c and c.strip()]
        if not commands:
            continue

        title = finding.get('title', 'finding')
        base = sanitize_filename(title)

        # Avoid base-name collisions across findings with the same title
        if base in used_names:
            used_names[base] += 1
            base = f"{base}_dup{used_names[base]}"
        else:
            used_names[base] = 0

        out.append((title, base, commands))

    return out

def generate_termshot_script(findings: List[Dict], script_file: str) -> int:
    """Write a bash script that captures a termshot screenshot for every command.

    Each finding title becomes the screenshot name. A single-command finding
    produces <Title>.png; a multi-command finding produces <Title>_1.png,
    <Title>_2.png, and so on. Returns the total number of termshot commands.
    """
    groups: List[Tuple[str, List[Tuple[str, str]]]] = []

    for title, base, commands in iter_findings_with_slugs(findings):
        multi = len(commands) > 1
        pairs = []
        for idx, cmd in enumerate(commands, 1):
            png = f"{base}_{idx}.png" if multi else f"{base}.png"
            pairs.append((png, cmd))
        groups.append((title, pairs))

    total = sum(len(pairs) for _, pairs in groups)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        "#!/usr/bin/env bash",
        "#",
        "# AWS ScoutSuite - termshot screenshot capture",
        f"# Auto-generated by generate_report.py on {timestamp}",
        f"# Total screenshots: {total}",
        "#",
        "set -uo pipefail",
        "",
        f"TOTAL={total}",
        "COUNT=0",
        "OK=0",
        "FAIL=0",
        "",
        "C_INFO='\\033[0;36m'",
        "C_OK='\\033[0;32m'",
        "C_ERR='\\033[0;31m'",
        "C_BOLD='\\033[1m'",
        "C_NC='\\033[0m'",
        "",
        "if ! command -v termshot >/dev/null 2>&1; then",
        '    printf "${C_ERR}error:${C_NC} termshot is not installed or not in PATH\\n"',
        "    exit 1",
        "fi",
        "",
        'OUTDIR="screenshots"',
        'mkdir -p "$OUTDIR"',
        'cd "$OUTDIR"',
        "",
        "progress() {",
        "    COUNT=$((COUNT + 1))",
        '    printf "${C_INFO}[%3d/%3d]${C_NC} %s\\n" "$COUNT" "$TOTAL" "$1"',
        "}",
        "",
        "status() {",
        '    if [ "$1" -eq 0 ]; then',
        "        OK=$((OK + 1))",
        "    else",
        "        FAIL=$((FAIL + 1))",
        '        printf "  ${C_ERR}capture failed${C_NC}\\n"',
        "    fi",
        "}",
        "",
        'printf "${C_BOLD}Capturing %d screenshots with termshot${C_NC}\\n\\n" "$TOTAL"',
        "",
    ]

    for title, pairs in groups:
        lines.append(f"# --- {title} ---")
        for png, cmd in pairs:
            lines.append(f'progress "{png}"')
            lines.append(
                f'termshot --show-cmd --filename {png} -- "{bash_escape(cmd)}"'
            )
            lines.append("status $?")
        lines.append("")

    lines.append(
        'printf "\\n${C_BOLD}Done${C_NC} - '
        '${C_OK}%d captured${C_NC}, ${C_ERR}%d failed${C_NC} (saved to ./%s)\\n" '
        '"$OK" "$FAIL" "$OUTDIR"'
    )
    lines.append("")

    with open(script_file, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines))

    Path(script_file).chmod(0o755)
    return total

def generate_verification_script(findings: List[Dict], script_file: str) -> int:
    """Write a bash script that runs each finding's commands and asks Claude Code
    whether the ScoutSuite finding is a true positive or a false positive.

    For every finding the script runs all of its AWS CLI commands, captures the
    combined output, pipes it to `claude -p` in headless mode, and parses a
    VERDICT line from the response. Returns the number of findings to verify.
    """
    groups = iter_findings_with_slugs(findings)
    total = len(groups)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        "#!/usr/bin/env bash",
        "#",
        "# AWS ScoutSuite - false-positive verification via Claude Code",
        f"# Auto-generated by generate_report.py on {timestamp}",
        f"# Findings to verify: {total}",
        "#",
        "# For each finding this script runs the AWS CLI commands, captures the",
        "# live output, and asks Claude Code (headless `claude -p`) whether the",
        "# finding is a real issue. One Claude Code call is made per finding.",
        "#",
        "set -uo pipefail",
        "",
        "# ---- config ----",
        'MODEL=""                 # e.g. MODEL="--model sonnet"  (empty = default)',
        "MAX_EVIDENCE_BYTES=100000  # cap evidence piped to claude (stdin limit is 10MB)",
        'OUTDIR="verification"',
        "",
        "# ---- colors ----",
        "C_INFO='\\033[0;36m'",
        "C_OK='\\033[0;32m'",
        "C_WARN='\\033[0;33m'",
        "C_ERR='\\033[0;31m'",
        "C_BOLD='\\033[1m'",
        "C_NC='\\033[0m'",
        "",
        "# ---- preflight ----",
        "if ! command -v aws >/dev/null 2>&1; then",
        '    printf "${C_ERR}error:${C_NC} aws CLI not found in PATH\\n"; exit 1',
        "fi",
        "if ! command -v claude >/dev/null 2>&1; then",
        '    printf "${C_ERR}error:${C_NC} claude (Claude Code) not found in PATH\\n"; exit 1',
        "fi",
        "",
        'mkdir -p "$OUTDIR/raw" "$OUTDIR/verdicts"',
        'RESULTS="$OUTDIR/results.tsv"',
        'printf "verdict\\tfinding\\tevidence\\treasoning\\n" > "$RESULTS"',
        "",
        f"TOTAL={total}",
        "COUNT=0",
        "TP=0; FP=0; INC=0",
        "",
        "run_cmd() {",
        "    # $1 = command string, $2 = evidence file",
        "    {",
        '        printf "### COMMAND: %s\\n" "$1"',
        '        eval "$1" 2>&1',
        '        printf "### EXIT CODE: %s\\n\\n" "$?"',
        '    } >> "$2"',
        "}",
        "",
        "verify() {",
        "    # $1 = title, $2 = slug",
        '    local title="$1" slug="$2"',
        '    local evidence="$OUTDIR/raw/${slug}.txt"',
        '    local vfile="$OUTDIR/verdicts/${slug}.txt"',
        "",
        "    local instruction",
        '    instruction="You are a senior cloud security analyst reviewing an AWS ScoutSuite finding to decide whether it is a true positive or a false positive.',
        "",
        'ScoutSuite reported this finding: \\"${title}\\".',
        "",
        "The text on stdin is the live output of AWS CLI commands that gather the current state of the affected resources. Judge ONLY from that evidence.",
        "",
        "Reply with the FIRST line being EXACTLY one of:",
        "VERDICT: TRUE_POSITIVE",
        "VERDICT: FALSE_POSITIVE",
        "VERDICT: INCONCLUSIVE",
        "",
        "Then add 1-3 sentences citing the specific evidence. Treat command errors or empty output as INCONCLUSIVE.",
        "",
        "Write the reasoning in caveman style: terse, drop articles, filler, pleasantries, and hedging. Fragments OK. Short synonyms. Keep technical terms, API names, resource IDs, and error strings exact. Keep the VERDICT line above exactly as specified.\"",
        "",
        "    local resp",
        '    resp=$(head -c "$MAX_EVIDENCE_BYTES" "$evidence" | claude -p $MODEL "$instruction" 2>/dev/null)',
        '    printf "%s\\n" "$resp" > "$vfile"',
        "",
        "    local verdict",
        "    verdict=$(printf '%s\\n' \"$resp\" | grep -oE '(TRUE_POSITIVE|FALSE_POSITIVE|INCONCLUSIVE)' | head -n1)",
        '    [ -z "$verdict" ] && verdict="INCONCLUSIVE"',
        "",
        "    local color",
        '    case "$verdict" in',
        "        TRUE_POSITIVE)  TP=$((TP + 1));  color=$C_OK ;;",
        "        FALSE_POSITIVE) FP=$((FP + 1));  color=$C_WARN ;;",
        "        *)              INC=$((INC + 1)); color=$C_ERR ;;",
        "    esac",
        '    printf "      ${color}-> %s${C_NC}\\n" "$verdict"',
        "",
        "    local reason",
        "    reason=$(printf '%s' \"$resp\" | grep -vE 'VERDICT:' | tr '\\n' ' ' | sed 's/  */ /g' | cut -c1-300)",
        '    printf "%s\\t%s\\t%s\\t%s\\n" "$verdict" "$title" "$evidence" "$reason" >> "$RESULTS"',
        "}",
        "",
        'printf "${C_BOLD}Verifying %d findings with Claude Code${C_NC}\\n\\n" "$TOTAL"',
        "",
    ]

    for title, slug, commands in groups:
        ev = f"$OUTDIR/raw/{slug}.txt"
        lines.append(f"# === {title} ===")
        lines.append("COUNT=$((COUNT + 1))")
        lines.append(
            f'printf "${{C_INFO}}[%3d/%3d]${{C_NC}} %s\\n" "$COUNT" "$TOTAL" "{bash_escape(title)}"'
        )
        lines.append(f': > "{ev}"')
        for cmd in commands:
            lines.append(f'run_cmd "{bash_escape(cmd)}" "{ev}"')
        lines.append(f'verify "{bash_escape(title)}" "{slug}"')
        lines.append("")

    lines += [
        'printf "\\n${C_BOLD}Summary${C_NC}: ${C_OK}%d confirmed${C_NC}, '
        '${C_WARN}%d false positive${C_NC}, ${C_ERR}%d inconclusive${C_NC} '
        '(of %d)\\n" "$TP" "$FP" "$INC" "$TOTAL"',
        "",
        'if [ "$FP" -gt 0 ]; then',
        '    printf "\\n${C_BOLD}Likely false positives:${C_NC}\\n"',
        "    awk -F'\\t' 'NR>1 && $1==\"FALSE_POSITIVE\" {print \"  - \" $2}' \"$RESULTS\"",
        "fi",
        'if [ "$INC" -gt 0 ]; then',
        '    printf "\\n${C_BOLD}Needs manual review (inconclusive):${C_NC}\\n"',
        "    awk -F'\\t' 'NR>1 && $1==\"INCONCLUSIVE\" {print \"  - \" $2}' \"$RESULTS\"",
        "fi",
        'printf "\\nFull results : %s\\n" "$RESULTS"',
        'printf "Reasoning    : %s/verdicts/\\n" "$OUTDIR"',
        'printf "Raw evidence : %s/raw/\\n" "$OUTDIR"',
        "",
    ]

    with open(script_file, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines))

    Path(script_file).chmod(0o755)
    return total

def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description='Generate HTML report from AWS ScoutSuite results',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 generate_report.py scoutsuite_results_aws-462973179763.js
  python3 generate_report.py -f scoutsuite_results_aws-462973179763.js
  python3 generate_report.py -f results.js -o custom_report.html
        """
    )
    
    parser.add_argument(
        'scout_file',
        nargs='?',
        help='ScoutSuite results JS file'
    )
    
    parser.add_argument(
        '-f', '--file',
        dest='scout_file_flag',
        help='ScoutSuite results JS file'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='scoutsuite_report.html',
        help='Output HTML file (default: scoutsuite_report.html)'
    )
    
    parser.add_argument(
        '-s', '--script',
        default='capture_screenshots.sh',
        help='Output termshot bash script (default: capture_screenshots.sh)'
    )
    
    parser.add_argument(
        '-V', '--verify-script',
        default='verify_findings.sh',
        help='Output Claude Code verification script (default: verify_findings.sh)'
    )
    
    args = parser.parse_args()
    
    # Use -f flag if provided, otherwise use positional argument
    scout_file = args.scout_file_flag or args.scout_file
    
    if not scout_file:
        parser.print_help()
        sys.exit(1)
    
    return scout_file, args.output, args.script, args.verify_script

def main():
    """Main function"""
    scout_file, output_file, script_file, verify_file = parse_arguments()

    print("AWS ScoutSuite Report Generator")
    print("-" * 40)

    # Check if files exist
    if not Path(scout_file).exists():
        print(f"[!] error: {scout_file} not found")
        sys.exit(1)

    if not Path(COMMANDS_FILE).exists():
        print(f"[!] error: {COMMANDS_FILE} not found in current directory")
        sys.exit(1)

    try:
        scout = load_scoutsuite(scout_file)
    except Exception as e:
        print(f"[!] error loading ScoutSuite file: {e}")
        sys.exit(1)

    try:
        commands = load_commands(COMMANDS_FILE)
    except Exception as e:
        print(f"[!] error loading commands file: {e}")
        sys.exit(1)

    findings = collect_findings_with_commands(scout, commands)
    generate_html_report(findings, output_file, scout_file)
    total_cmds = generate_termshot_script(findings, script_file)
    total_verify = generate_verification_script(findings, verify_file)

    print(f"[+] input          : {scout_file}")
    print(f"[+] findings       : {len(findings)}")
    print(f"[+] html report    : {output_file}")
    print(f"[+] termshot script: {script_file} ({total_cmds} commands)")
    print(f"[+] verify script  : {verify_file} ({total_verify} findings)")
    print("-" * 40)
    print(f"Done. Screenshots : ./{script_file}")
    print(f"      Verify (FP) : ./{verify_file}")

if __name__ == "__main__":
    main()