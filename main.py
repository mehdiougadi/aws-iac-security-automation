import boto3
import configparser
import sys
import os


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
        pass
    except Exception as e:
        print(f'- Failed to create security group: {e}')
        sys.exit(1)
        

def createS3Bucket(bucket_name):
    try:
        pass
    except Exception as e:
        print(f'- Failed to create S3 bucket: {e}')
        sys.exit(1)


def main():
    print('*'*18 + ' Initial Setup ' + '*'*17)
    validateAWSCredentials()
    setBoto3Clients()
    print('*'*50 + '\n')

    print('*'*14 + ' Infrastructure Start ' + '*'*14)
    
    vpc_id = createVPC('10.0.0.0/16', 'polystudent-vpc1')


if __name__ == "__main__":
    main()