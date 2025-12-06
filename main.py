import boto3
import configparser
import sys
import os
import json


"""
    Setup required to use the script
"""
def validateAWSCredentials():
    try:
        print('- Validating the AWS credentials')

        aws_access_key_id = None
        aws_secret_access_key = None
        aws_session_token = None
        is_not_valid = True

        credentials_path = os.path.expanduser('~/.aws/credentials')
        config = configparser.ConfigParser()

        if os.path.exists(credentials_path):
            config.read(credentials_path)
            if 'default' in config:
                aws_access_key_id = config['default'].get('aws_access_key_id')
                aws_secret_access_key = config['default'].get('aws_secret_access_key')
                aws_session_token = config['default'].get('aws_session_token')

        if not aws_access_key_id or not aws_secret_access_key:
            aws_access_key_id, aws_secret_access_key, aws_session_token = getAWSCredentials()

        while is_not_valid:
            try:
                sts = boto3.client(
                    'sts',
                    aws_access_key_id=aws_access_key_id,
                    aws_secret_access_key=aws_secret_access_key,
                    aws_session_token=aws_session_token
                )

                sts.get_caller_identity()
                is_not_valid = False

            except Exception:
                print('- credential verification failed\n')
                aws_access_key_id, aws_secret_access_key, aws_session_token = getAWSCredentials()

        os.environ['AWS_ACCESS_KEY_ID'] = aws_access_key_id
        os.environ['AWS_SECRET_ACCESS_KEY'] = aws_secret_access_key
        if aws_session_token:
            os.environ['AWS_SESSION_TOKEN'] = aws_session_token

        print('- AWS credentials verified')

    except Exception as e:
        print(f'Failed to validate user\'s credentials: {e}')
        sys.exit(1)


def getAWSCredentials() -> tuple[str, str, str | None]:
    try:
        print('- Enter the following required variables to login')
        aws_access_key_id = input('→ AWS Access Key Id: ')
        aws_secret_access_key = input('→ AWS Secret Access Key: ')
        aws_session_token = input('→ AWS Session Token (press enter if none): ')

        return aws_access_key_id, aws_secret_access_key, aws_session_token
    
    except Exception as e:
        print(f'Failed to get user\'s input credentials: {e}')
        sys.exit(1)


def setBoto3Clients():
    try:
        print('- Starting setting up the boto3 clients')

        global EC2_CLIENT, S3_CLIENT, CW_CLIENT, SSM_CLIENT, IAM_CLIENT, CLOUDTRAIL_CLIENT

        EC2_CLIENT = boto3.client(
            'ec2',
            aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
            aws_session_token=os.getenv('AWS_SESSION_TOKEN'),
            region_name=os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
        )

        S3_CLIENT = boto3.client(
            's3',
            aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
            aws_session_token=os.getenv('AWS_SESSION_TOKEN'),
            region_name=os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
        )

        CW_CLIENT = boto3.client(
            'cloudwatch',
            aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
            aws_session_token=os.getenv('AWS_SESSION_TOKEN'),
            region_name=os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
        )

        SSM_CLIENT = boto3.client(
            'ssm',
            aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
            aws_session_token=os.getenv('AWS_SESSION_TOKEN'),
            region_name=os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
        )

        IAM_CLIENT = boto3.client(
            'iam',
            aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
            aws_session_token=os.getenv('AWS_SESSION_TOKEN'),
            region_name=os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
        )

        CLOUDTRAIL_CLIENT = boto3.client(
            'cloudtrail',
            aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
            aws_session_token=os.getenv('AWS_SESSION_TOKEN'),
            region_name=os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
        )

        print('- finished setting up the boto3 clients')

    except Exception as e:
        print(f'Failed to set Boto3\'s clients: {e}')
        sys.exit(1)


"""
    AWS architecture
"""
def createVPC(cidr_block='10.0.0.0/16', vpc_name='polystudent-vpc'):
    try:
        print(f'- Creating VPC: {vpc_name} with CIDR: {cidr_block}')
        
        vpc_response = EC2_CLIENT.create_vpc(
            CidrBlock=cidr_block,
            TagSpecifications=[
                {
                    'ResourceType': 'vpc',
                    'Tags': [
                        {
                            'Key': 'Name',
                            'Value': vpc_name
                        }
                    ]
                }
            ]
        )
        
        vpc_id = vpc_response['Vpc']['VpcId']
        
        EC2_CLIENT.modify_vpc_attribute(
            VpcId=vpc_id,
            EnableDnsHostnames={'Value': True}
        )
        
        EC2_CLIENT.modify_vpc_attribute(
            VpcId=vpc_id,
            EnableDnsSupport={'Value': True}
        )
        
        print(f'- VPC created successfully with ID: {vpc_id}')
        
        return vpc_id
        
    except Exception as e:
        print(f'- Failed to create VPC {vpc_id}: {e}')
        sys.exit(1)


def createSubnet(vpc_id, cidr_block, availability_zone, subnet_name, is_public=False):
    try:
        print(f'- Creating Subnet: {subnet_name} in {availability_zone}')
        
        subnet_response = EC2_CLIENT.create_subnet(
            VpcId=vpc_id,
            CidrBlock=cidr_block,
            AvailabilityZone=availability_zone,
            TagSpecifications=[
                {
                    'ResourceType': 'subnet',
                    'Tags': [
                        {
                            'Key': 'Name',
                            'Value': subnet_name
                        }
                    ]
                }
            ]
        )
        
        subnet_id = subnet_response['Subnet']['SubnetId']
        
        if is_public:
            EC2_CLIENT.modify_subnet_attribute(
                SubnetId=subnet_id,
                MapPublicIpOnLaunch={'Value': True}
            )
            print(f'- Public Subnet created with ID: {subnet_id}')
        else:
            print(f'- Private Subnet created with ID: {subnet_id}')
        
        return subnet_id
        
    except Exception as e:
        print(f'- Failed to create subnet: {e}')
        sys.exit(1)


def createInternetGateway(vpc_id, igw_name='polystudent-igw'):
    try:
        print(f'- Creating Internet Gateway: {igw_name}')
        
        igw_response = EC2_CLIENT.create_internet_gateway(
            TagSpecifications=[
                {
                    'ResourceType': 'internet-gateway',
                    'Tags': [
                        {
                            'Key': 'Name',
                            'Value': igw_name
                        }
                    ]
                }
            ]
        )
        
        igw_id = igw_response['InternetGateway']['InternetGatewayId']
        
        EC2_CLIENT.attach_internet_gateway(
            InternetGatewayId=igw_id,
            VpcId=vpc_id
        )
        
        print(f'- Internet Gateway created and attached: {igw_id}')
        
        return igw_id
        
    except Exception as e:
        print(f'- Failed to create internet gateway: {e}')
        sys.exit(1)


def createNATGateway(subnet_id, nat_name):
    try:
        print(f'- Creating NAT Gateway: {nat_name}')
        
        eip_response = EC2_CLIENT.allocate_address(Domain='vpc')
        eip_allocation_id = eip_response['AllocationId']
        
        print(f'- Elastic IP allocated: {eip_response["PublicIp"]}')
        
        nat_response = EC2_CLIENT.create_nat_gateway(
            SubnetId=subnet_id,
            AllocationId=eip_allocation_id,
            TagSpecifications=[
                {
                    'ResourceType': 'natgateway',
                    'Tags': [
                        {
                            'Key': 'Name',
                            'Value': nat_name
                        }
                    ]
                }
            ]
        )
        
        nat_gateway_id = nat_response['NatGateway']['NatGatewayId']
        
        print(f'- Waiting for NAT Gateway {nat_name} to become available...')
        waiter = EC2_CLIENT.get_waiter('nat_gateway_available')
        waiter.wait(NatGatewayIds=[nat_gateway_id])
        
        print(f'- NAT Gateway created successfully: {nat_gateway_id}')
        
        return nat_gateway_id
        
    except Exception as e:
        print(f'- Failed to create NAT: {e}')
        sys.exit(1)


def createRoutingTable(vpc_id, igw_id=None, nat_gateway_id=None, route_table_name='RouteTable', is_public=False):
    try:
        print(f'- Creating Route Table: {route_table_name}')
        
        route_table_response = EC2_CLIENT.create_route_table(
            VpcId=vpc_id,
            TagSpecifications=[
                {
                    'ResourceType': 'route-table',
                    'Tags': [
                        {
                            'Key': 'Name',
                            'Value': route_table_name
                        }
                    ]
                }
            ]
        )
        
        route_table_id = route_table_response['RouteTable']['RouteTableId']
        
        if is_public and igw_id:
            EC2_CLIENT.create_route(
                RouteTableId=route_table_id,
                DestinationCidrBlock='0.0.0.0/0',
                GatewayId=igw_id
            )

            print(f'- Public Route Table created with route to IGW: {route_table_id}')

        elif not is_public and nat_gateway_id:
            EC2_CLIENT.create_route(
                RouteTableId=route_table_id,
                DestinationCidrBlock='0.0.0.0/0',
                NatGatewayId=nat_gateway_id
            )

            print(f'- Private Route Table created with route to NAT: {route_table_id}')
        else:
            print(f'- Route Table created without internet route: {route_table_id}')
        
        return route_table_id
        
    except Exception as e:
        print(f'- Failed to create routing table: {e}')
        sys.exit(1)


def associateRouteTable(route_table_id, subnet_id):
    try:
        print(f'- Associating Route Table {route_table_id} with Subnet {subnet_id}')
        
        association_response = EC2_CLIENT.associate_route_table(
            RouteTableId=route_table_id,
            SubnetId=subnet_id
        )
        
        association_id = association_response['AssociationId']
        print(f'- Route Table associated successfully: {association_id}')
        
        return association_id
        
    except Exception as e:
        print(f'- Failed to associate route table: {e}')
        sys.exit(1)
        

def createSecurityGroup(vpc_id, sg_name='polystudent-sg', sg_description='Security group for polystudent infrastructure'):
    try:
        print(f'- Creating Security Group: {sg_name}')
        
        sg_response = EC2_CLIENT.create_security_group(
            GroupName=sg_name,
            Description=sg_description,
            VpcId=vpc_id,
            TagSpecifications=[
                {
                    'ResourceType': 'security-group',
                    'Tags': [
                        {
                            'Key': 'Name',
                            'Value': sg_name
                        }
                    ]
                }
            ]
        )
        
        security_group_id = sg_response['GroupId']
        
        ingress_rules = [
            {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'CidrIp': '0.0.0.0/0', 'Description': 'SSH'},
            {'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'CidrIp': '0.0.0.0/0', 'Description': 'HTTP'},
            {'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443, 'CidrIp': '0.0.0.0/0', 'Description': 'HTTPS'},
            {'IpProtocol': 'tcp', 'FromPort': 53, 'ToPort': 53, 'CidrIp': '0.0.0.0/0', 'Description': 'DNS TCP'},
            {'IpProtocol': 'udp', 'FromPort': 53, 'ToPort': 53, 'CidrIp': '0.0.0.0/0', 'Description': 'DNS UDP'},
            {'IpProtocol': 'tcp', 'FromPort': 1433, 'ToPort': 1433, 'CidrIp': '0.0.0.0/0', 'Description': 'MSSQL'},
            {'IpProtocol': 'tcp', 'FromPort': 5432, 'ToPort': 5432, 'CidrIp': '0.0.0.0/0', 'Description': 'PostgreSQL'},
            {'IpProtocol': 'tcp', 'FromPort': 3306, 'ToPort': 3306, 'CidrIp': '0.0.0.0/0', 'Description': 'MySQL'},
            {'IpProtocol': 'tcp', 'FromPort': 3389, 'ToPort': 3389, 'CidrIp': '0.0.0.0/0', 'Description': 'RDP'},
            {'IpProtocol': 'tcp', 'FromPort': 1514, 'ToPort': 1514, 'CidrIp': '0.0.0.0/0', 'Description': 'OSSEC'},
            {'IpProtocol': 'tcp', 'FromPort': 9200, 'ToPort': 9300, 'CidrIp': '0.0.0.0/0', 'Description': 'ElasticSearch'},
        ]
        
        print('- Adding ingress rules to Security Group')
        for rule in ingress_rules:
            EC2_CLIENT.authorize_security_group_ingress(
                GroupId=security_group_id,
                IpPermissions=[
                    {
                        'IpProtocol': rule['IpProtocol'],
                        'FromPort': rule['FromPort'],
                        'ToPort': rule['ToPort'],
                        'IpRanges': [{'CidrIp': rule['CidrIp'], 'Description': rule['Description']}]
                    }
                ]
            )
        
        print(f'- Security Group created successfully: {security_group_id}')
        
        return security_group_id
        
    except Exception as e:
        print(f'- Failed to create security group: {e}')
        sys.exit(1)
        

def createS3Bucket(bucket_name):
    try:
        print(f'- Creating S3 Bucket: {bucket_name}')
        
        try:
            S3_CLIENT.create_bucket(Bucket=bucket_name, ObjectOwnership='BucketOwnerPreferred')
            print(f'- Bucket created: {bucket_name}')
        except Exception as e:
            if 'BucketAlreadyOwnedByYou' in str(e):
                print(f'- Bucket {bucket_name} already exists and is owned by you')
            else:
                raise e
        
        S3_CLIENT.put_bucket_acl(
            Bucket=bucket_name,
            ACL='private'
        )
        print('- ACL set to private')
        
        S3_CLIENT.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        print('- Public access blocked')
        
        S3_CLIENT.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={'Status': 'Enabled'}
        )
        print('- Versioning enabled')
        

        encryption_config = {
            'Rules': [
                {
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'AES256'
                    },
                    'BucketKeyEnabled': False
                }
            ]
        }
        print('- Encryption configured with AES256')
        
        S3_CLIENT.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration=encryption_config
        )
        
        print(f'- S3 Bucket created successfully: {bucket_name}')
        
        return bucket_name
        
    except Exception as e:
        print(f'- Failed to create S3 bucket: {e}')
        sys.exit(1)


def createVPCFlowLog(vpc_id, bucket_name, flow_log_name='polystudent-flowlog'):
    try:
        print(f'- Creating VPC Flow Log: {flow_log_name}')
        
        flow_log_response = EC2_CLIENT.create_flow_logs(
            ResourceIds=[vpc_id],
            ResourceType='VPC',
            TrafficType='REJECT',
            LogDestinationType='s3',
            LogDestination=f'arn:aws:s3:::{bucket_name}',
            TagSpecifications=[
                {
                    'ResourceType': 'vpc-flow-log',
                    'Tags': [
                        {
                            'Key': 'Name',
                            'Value': flow_log_name
                        }
                    ]
                }
            ]
        )
        
        flow_log_id = flow_log_response['FlowLogIds'][0]
        
        print(f'- VPC Flow Log created successfully: {flow_log_id}')
        print('  - Traffic Type: REJECT')
        print(f'  - Destination: s3://{bucket_name}')
        
        return flow_log_id
        
    except Exception as e:
        print(f'- Failed to create VPC Flow Log: {e}')
        sys.exit(1)


def createEC2Instance(subnet_id, security_group_id, instance_name, iam_role_name='LabRole'):
    try:
        print(f'- Creating EC2 Instance: {instance_name}')
        
        # Get latest Amazon Linux 2 AMI
        response = SSM_CLIENT.get_parameter(
            Name='/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2'
        )
        ami_id = response['Parameter']['Value']
        print(f'- Using AMI: {ami_id}')

        # Try to find a key pair
        key_name = None
        try:
            key_pairs = EC2_CLIENT.describe_key_pairs()
            if key_pairs['KeyPairs']:
                # Prefer 'vockey' if it exists
                for kp in key_pairs['KeyPairs']:
                    if kp['KeyName'] == 'vockey':
                        key_name = 'vockey'
                        break
                if not key_name:
                    key_name = key_pairs['KeyPairs'][0]['KeyName']
                print(f'- Using Key Pair: {key_name}')
        except Exception:
            print('- No Key Pair found or failed to list, proceeding without one')

        run_instances_args = {
            'ImageId': ami_id,
            'InstanceType': 't2.micro',
            'MinCount': 1,
            'MaxCount': 1,
            'SubnetId': subnet_id,
            'SecurityGroupIds': [security_group_id],
            'IamInstanceProfile': {'Name': iam_role_name},
            'TagSpecifications': [
                {
                    'ResourceType': 'instance',
                    'Tags': [{'Key': 'Name', 'Value': instance_name}]
                }
            ]
        }

        if key_name:
            run_instances_args['KeyName'] = key_name

        instance_response = EC2_CLIENT.run_instances(**run_instances_args)
        
        instance_id = instance_response['Instances'][0]['InstanceId']
        print(f'- Instance created: {instance_id}')
        
        print(f'- Waiting for instance {instance_id} to be running...')
        waiter = EC2_CLIENT.get_waiter('instance_running')
        waiter.wait(InstanceIds=[instance_id])
        
        print(f'- Instance {instance_name} is running')
        
        return instance_id

    except Exception as e:
        print(f'- Failed to create instance: {e}')
        sys.exit(1)


def createCloudWatchAlarm(instance_id, instance_name):
    try:
        print(f'- Creating CloudWatch Alarm for {instance_name}')
        
        CW_CLIENT.put_metric_alarm(
            AlarmName=f'High-Incoming-Traffic-{instance_name}',
            AlarmDescription='Alarm when incoming packets exceed 1000 pkts/sec',
            ActionsEnabled=False,
            MetricName='NetworkPacketsIn',
            Namespace='AWS/EC2',
            Statistic='Average',
            Dimensions=[
                {
                    'Name': 'InstanceId',
                    'Value': instance_id
                },
            ],
            Period=60,
            EvaluationPeriods=1,
            Threshold=1000.0,
            ComparisonOperator='GreaterThanThreshold'
        )
        
        print(f'- Alarm created successfully for {instance_id}')
        
    except Exception as e:
        print(f'- Failed to create CloudWatch alarm: {e}')
        sys.exit(1)


def getLabRoleArn():
    try:
        role = IAM_CLIENT.get_role(RoleName='LabRole')
        return role['Role']['Arn']
    except Exception as e:
        print(f'- Failed to get LabRole: {e}')
        sys.exit(1)


def configureS3Replication(source_bucket, dest_bucket, role_arn):
    try:
        print(f'- Configuring replication from {source_bucket} to {dest_bucket}')
        
        S3_CLIENT.put_bucket_replication(
            Bucket=source_bucket,
            ReplicationConfiguration={
                'Role': role_arn,
                'Rules': [
                    {
                        'ID': 'ReplicationRule',
                        'Priority': 1,
                        'Status': 'Enabled',
                        'Filter': {},
                        'Destination': {
                            'Bucket': f'arn:aws:s3:::{dest_bucket}'
                        },
                        'DeleteMarkerReplication': {'Status': 'Disabled'}
                    }
                ]
            }
        )
        print('- Replication configured successfully')
        
    except Exception as e:
        print(f'- Failed to configure replication: {e}')
        sys.exit(1)


def createCloudTrail(trail_name, bucket_to_watch, log_bucket):
    try:
        print(f'- Creating CloudTrail: {trail_name}')
        
        # Policy for Log Bucket
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AWSCloudTrailAclCheck",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:GetBucketAcl",
                    "Resource": f"arn:aws:s3:::{log_bucket}"
                },
                {
                    "Sid": "AWSCloudTrailWrite",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": f"arn:aws:s3:::{log_bucket}/AWSLogs/*",
                    "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}
                }
            ]
        }
        
        S3_CLIENT.put_bucket_policy(
            Bucket=log_bucket,
            Policy=json.dumps(policy_doc)
        )
        
        try:
            CLOUDTRAIL_CLIENT.create_trail(
                Name=trail_name,
                S3BucketName=log_bucket,
                IsMultiRegionTrail=False,
                EnableLogFileValidation=True
            )
        except Exception as e:
            if 'TrailAlreadyExistsException' in str(e):
                print(f'- Trail {trail_name} already exists')
            else:
                raise e
        
        CLOUDTRAIL_CLIENT.put_event_selectors(
            TrailName=trail_name,
            EventSelectors=[
                {
                    'ReadWriteType': 'All',
                    'IncludeManagementEvents': True,
                    'DataResources': [
                        {
                            'Type': 'AWS::S3::Object',
                            'Values': [f'arn:aws:s3:::{bucket_to_watch}/']
                        }
                    ]
                }
            ]
        )
        
        CLOUDTRAIL_CLIENT.start_logging(Name=trail_name)
        print(f'- CloudTrail {trail_name} created and logging started')
        
    except Exception as e:
        print(f'- Failed to create CloudTrail: {e}')
        sys.exit(1)


def main():
    print('*'*18 + ' Initial Setup ' + '*'*17)
    validateAWSCredentials()
    setBoto3Clients()
    print('*'*50 + '\n')

    print('*'*14 + ' Infrastructure Start ' + '*'*14)
    
    vpc_id = createVPC('10.0.0.0/16', 'polystudent-vpc1')
    igw_id = createInternetGateway(vpc_id, 'polystudent-igw')
    
    public_subnet_az1 = createSubnet(vpc_id, '10.0.1.0/24', 'us-east-1a', 'PublicSubnetAZ1', is_public=True)
    public_subnet_az2 = createSubnet(vpc_id, '10.0.2.0/24', 'us-east-1b', 'PublicSubnetAZ2', is_public=True)
    private_subnet_az1 = createSubnet(vpc_id, '10.0.3.0/24', 'us-east-1a', 'PrivateSubnetAZ1', is_public=False)
    private_subnet_az2 = createSubnet(vpc_id, '10.0.4.0/24', 'us-east-1b', 'PrivateSubnetAZ2', is_public=False)

    nat_gateway_az1 = createNATGateway(public_subnet_az1, 'NATGatewayAZ1')
    nat_gateway_az2 = createNATGateway(public_subnet_az2, 'NATGatewayAZ2')
    
    public_route_table = createRoutingTable(vpc_id, igw_id=igw_id, route_table_name='PublicRouteTable', is_public=True)
    private_route_table_az1 = createRoutingTable(vpc_id, nat_gateway_id=nat_gateway_az1, route_table_name='PrivateRouteTableAZ1', is_public=False)
    private_route_table_az2 = createRoutingTable(vpc_id, nat_gateway_id=nat_gateway_az2, route_table_name='PrivateRouteTableAZ2', is_public=False)
    
    associateRouteTable(public_route_table, public_subnet_az1)
    associateRouteTable(public_route_table, public_subnet_az2)
    associateRouteTable(private_route_table_az1, private_subnet_az1)
    associateRouteTable(private_route_table_az2, private_subnet_az2)

    security_group_id = createSecurityGroup(vpc_id, 'polystudent-sg')

    bucket_name = createS3Bucket('tp4polystudents2051559')
    backup_bucket_name = createS3Bucket('tp4polystudents2051559-back')
    
    role_arn = getLabRoleArn()
    print(f'- Using existing LabRole for replication: {role_arn}')
    configureS3Replication(bucket_name, backup_bucket_name, role_arn)
    
    log_bucket_name = createS3Bucket('tp4polystudents2051559-logs')
    createCloudTrail('polystudent-trail', bucket_name, log_bucket_name)

    flow_log_id = createVPCFlowLog(vpc_id, bucket_name, 'polystudent-flowlog')

    instance_name = 'WebInstanceAZ1'
    instance_id = createEC2Instance(public_subnet_az1, security_group_id, instance_name)
    createCloudWatchAlarm(instance_id, instance_name)

    print('*'*50 + '\n')
    print('*'*14 + ' Result for Exercise 1  ' + '*'*12)
    print(f'VPC ID: {vpc_id}')
    print(f'Internet Gateway ID: {igw_id}')
    print(f'Public Subnet AZ1 ID: {public_subnet_az1}')
    print(f'Public Subnet AZ2 ID: {public_subnet_az2}')
    print(f'Private Subnet AZ1 ID: {private_subnet_az1}')
    print(f'Private Subnet AZ2 ID: {private_subnet_az2}')
    print(f'NAT Gateway AZ1 ID: {nat_gateway_az1}')
    print(f'NAT Gateway AZ2 ID: {nat_gateway_az2}')
    print(f'Public Route Table ID: {public_route_table}')
    print(f'Private Route Table AZ1 ID: {private_route_table_az1}')
    print(f'Private Route Table AZ2 ID: {private_route_table_az2}')
    print(f'Security Group ID: {security_group_id}')
    print('*'*50 + '\n')

    print('*'*14 + ' Result for Exercise 2  ' + '*'*12)
    print(f'S3 Bucket Name: {bucket_name}')
    print('*'*50 + '\n')

    print('*'*14 + ' Result for Exercise 3  ' + '*'*12)

    print('-'*22 + ' 3.1  ' + '-'*22)
    print(f'VPC Flow Log ID: {flow_log_id}')
    
    print('-'*22 + ' 3.2  ' + '-'*22)
    print(f'Instance ID: {instance_id}')
    print(f'CloudWatch Alarm created for {instance_id}')
    print('-'*50)

    print('-'*22 + ' 3.3  ' + '-'*22)
    print(f'Backup Bucket Name: {backup_bucket_name}')
    print(f'Log Bucket Name: {log_bucket_name}')
    print(f'Replication Role: {role_arn}')
    print(f'CloudTrail enabled for {bucket_name}')
    print('-'*50)

if __name__ == "__main__":
    main()