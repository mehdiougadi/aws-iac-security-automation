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
        pass
    except Exception as e:
        print(f'- Failed to create subnet: {e}')
        sys.exit(1)


def createInternetGateway(vpc_id, igw_name='polystudent-igw'):
    try:
        pass
    except Exception as e:
        print(f'- Failed to create internet gateway: {e}')
        sys.exit(1)


def createNATGateway(subnet_id, nat_name):
    try:
        pass
    except Exception as e:
        print(f'- Failed to create NAT: {e}')
        sys.exit(1)


def createRoutingTable(vpc_id, igw_id=None, nat_gateway_id=None, route_table_name='RouteTable', is_public=False):
    try:
        pass
    except Exception as e:
        print(f'- Failed to create routing table: {e}')
        sys.exit(1)


def associateRouteTable(route_table_id, subnet_id):
    try:
        pass
    except Exception as e:
        print(f'- Failed to associate route table: {e}')
        sys.exit(1)


def createSecurityGroup(vpc_id, sg_name='polystudent-sg', sg_description='Security group for polystudent infrastructure'):
    try:
        pass
    except Exception as e:
        print(f'- Failed to create security group: {e}')
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