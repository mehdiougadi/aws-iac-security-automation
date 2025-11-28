import boto3
import configparser
import sys
import os
import time


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

        global EC2_CLIENT, S3_CLIENT

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

        print('- finished setting up the boto3 clients')

    except Exception as e:
        print(f'Failed to set Boto3\'s clients: {e}')
        sys.exit(1)


"""
    Cleanup functions
"""
def deleteVPC(vpc_id):
    try:
        print(f'- Deleting VPC: {vpc_id}')
        
        EC2_CLIENT.delete_vpc(VpcId=vpc_id)
        
        print(f'- VPC {vpc_id} deleted successfully')
        
    except Exception as e:
        print(f'- Failed to delete VPC {vpc_id}: {e}')


def deleteSubnets(vpc_id):
    try:
        print(f'- Deleting Subnets in VPC: {vpc_id}')
        
        subnets = EC2_CLIENT.describe_subnets(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
        )
        
        for subnet in subnets['Subnets']:
            subnet_id = subnet['SubnetId']
            subnet_name = 'N/A'
            if 'Tags' in subnet:
                for tag in subnet['Tags']:
                    if tag['Key'] == 'Name':
                        subnet_name = tag['Value']
                        break
            
            print(f'- Deleting Subnet: {subnet_id} ({subnet_name})')
            try:
                EC2_CLIENT.delete_subnet(SubnetId=subnet_id)
            except Exception as e:
                print(f'- Failed to delete {subnet_id}: {e}')
        
        print('- Subnets deleted successfully')
        
    except Exception as e:
        print(f'- Failed to delete Subnets: {e}')


def deleteInternetGateways(vpc_id):
    try:
        print(f'- Deleting Internet Gateways in VPC: {vpc_id}')
        
        igws = EC2_CLIENT.describe_internet_gateways(
            Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}]
        )
        
        for igw in igws['InternetGateways']:
            igw_id = igw['InternetGatewayId']
            print(f'- Detaching and deleting Internet Gateway: {igw_id}')
            try:
                EC2_CLIENT.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
                EC2_CLIENT.delete_internet_gateway(InternetGatewayId=igw_id)
            except Exception as e:
                print(f'- Failed to delete {igw_id}: {e}')
        
        print('- Internet Gateways deleted successfully')
        
    except Exception as e:
        print(f'- Failed to delete Internet Gateways: {e}')


def deleteNATGateways(vpc_id):
    try:
        print(f'- Deleting NAT Gateways in VPC: {vpc_id}')
        
        nat_gateways = EC2_CLIENT.describe_nat_gateways(
            Filters=[
                {'Name': 'vpc-id', 'Values': [vpc_id]},
                {'Name': 'state', 'Values': ['available', 'pending']}
            ]
        )
        
        for nat in nat_gateways['NatGateways']:
            nat_id = nat['NatGatewayId']
            print(f'- Deleting NAT Gateway: {nat_id}')
            EC2_CLIENT.delete_nat_gateway(NatGatewayId=nat_id)
        
        if nat_gateways['NatGateways']:
            print('- Waiting for NAT Gateways to be deleted...')
            time.sleep(30)
            
            waiter = EC2_CLIENT.get_waiter('nat_gateway_deleted')
            for nat in nat_gateways['NatGateways']:
                try:
                    waiter.wait(NatGatewayIds=[nat['NatGatewayId']])
                except:
                    pass
        
        print('- NAT Gateways deleted successfully')
        
    except Exception as e:
        print(f'- Failed to delete NAT Gateways: {e}')


def releaseElasticIPs():
    try:
        print('- Releasing unattached Elastic IPs')
        
        addresses = EC2_CLIENT.describe_addresses()
        
        for address in addresses['Addresses']:
            if 'AssociationId' not in address:
                allocation_id = address['AllocationId']
                print(f'- Releasing Elastic IP: {address["PublicIp"]}')
                try:
                    EC2_CLIENT.release_address(AllocationId=allocation_id)
                except Exception as e:
                    print(f'- Failed to release {allocation_id}: {e}')
        
        print('- Elastic IPs released successfully')
        
    except Exception as e:
        print(f'- Failed to release Elastic IPs: {e}')


def deleteRouteTables(vpc_id):
    try:
        print(f'- Deleting Route Tables in VPC: {vpc_id}')
        
        route_tables = EC2_CLIENT.describe_route_tables(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
        )
        
        for rt in route_tables['RouteTables']:
            is_main = False
            for assoc in rt['Associations']:
                if assoc.get('Main', False):
                    is_main = True
                    break
            
            if not is_main:
                rt_id = rt['RouteTableId']
                print(f'- Deleting Route Table: {rt_id}')
                try:
                    EC2_CLIENT.delete_route_table(RouteTableId=rt_id)
                except Exception as e:
                    print(f'- Failed to delete {rt_id}: {e}')
        
        print('- Route Tables deleted successfully')
        
    except Exception as e:
        print(f'- Failed to delete Route Tables: {e}')


def deleteSecurityGroups(vpc_id):
    try:
        print(f'- Deleting Security Groups in VPC: {vpc_id}')
        
        security_groups = EC2_CLIENT.describe_security_groups(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
        )
        
        for sg in security_groups['SecurityGroups']:
            if sg['GroupName'] != 'default':
                sg_id = sg['GroupId']
                print(f'- Deleting Security Group: {sg_id} ({sg["GroupName"]})')
                try:
                    EC2_CLIENT.delete_security_group(GroupId=sg_id)
                except Exception as e:
                    print(f'- Failed to delete {sg_id}: {e}')
        
        print('- Security Groups deleted successfully')
        
    except Exception as e:
        print(f'- Failed to delete Security Groups: {e}')


def cleanupAllVPCs():
    try:
        print('- Fetching all VPCs in the region')
        
        vpcs = EC2_CLIENT.describe_vpcs()
        
        non_default_vpcs = [vpc for vpc in vpcs['Vpcs'] if not vpc['IsDefault']]
        
        if not non_default_vpcs:
            print('- No non-default VPCs found to delete')
            return
        
        print(f'- Found {len(non_default_vpcs)} non-default VPC(s) to clean up')
        
        for vpc in non_default_vpcs:
            vpc_id = vpc['VpcId']
            vpc_name = 'N/A'
            if 'Tags' in vpc:
                for tag in vpc['Tags']:
                    if tag['Key'] == 'Name':
                        vpc_name = tag['Value']
                        break
            
            print(f'\n{"="*50}')
            print(f'Cleaning up VPC: {vpc_id} ({vpc_name})')
            print(f'{"="*50}')
            
            deleteNATGateways(vpc_id)
            releaseElasticIPs()
            deleteSecurityGroups(vpc_id)
            deleteSubnets(vpc_id)
            deleteRouteTables(vpc_id)
            deleteInternetGateways(vpc_id)
            deleteVPC(vpc_id)
        
        print(f'\n{"="*50}')
        print('All VPCs cleaned up successfully')
        print(f'{"="*50}')
        
    except Exception as e:
        print(f'- Failed to cleanup VPCs: {e}')
        sys.exit(1)


def main():
    print('*'*18 + ' Initial Setup ' + '*'*17)
    validateAWSCredentials()
    setBoto3Clients()
    print('*'*50 + '\n')

    cleanupAllVPCs()

if __name__ == "__main__":
    main()