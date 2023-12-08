import os
import json
import yaml
import subprocess
from jinja2 import Environment, FileSystemLoader
import boto3
import logging
import base64
import secrets
import string
import time
import requests
from requests.auth import HTTPBasicAuth
from botocore.exceptions import ClientError

###################################  LOGS ###########################################
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
def log_error(e):
    logging.error(e.response['Error']['Message'])

###################################  GLOBAL VARIABLES ###########################################

# Every region has a different subnet naming convention, hence we are hard coding the values below
# Add more regions and their corresponding subnets as needed
REGION_SUBNET_MAPPING = {
    'ca-central-1': ['subnet-06f45035183d72a63'],
    'eu-west-1': ['subnet-abcde', 'subnet-fghij'],
}
# Every region has a different security group naming convention, hence we are hard coding the values below
REGION_SECURITY_GROUP_MAPPING = {
    'ca-central-1': ["sg-084bfe2d8728356fe"]
}

###################################  SECRETS FUNCTIONS  ###########################################
def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits
    password = ''.join(secrets.choice(characters) for i in range(length))
    return password

# Get Secrets from AWS Secret Manager
def get_secret_values(secret_name):
    """
    Retrieve all values from a secret stored in AWS Secrets Manager.
    """
    secrets_client = boto3.client('secretsmanager', region_name=os.environ.get('AWS_REGION'))
    try:
        secret_value_response = secrets_client.get_secret_value(SecretId=secret_name)
        # The secret string is expected to be a JSON string
        secret_values = json.loads(secret_value_response['SecretString'])
        return secret_values
    except Exception as e:
        print(f"Error retrieving secret: {e}")
        return None
    
# Check for existing secret | create a new secret and secret values
def create_or_update_secret(client_name, env, region):
    secrets_client = boto3.client('secretsmanager', region_name=region)
    secret_name = f"{client_name}_secrets"
    new_key = f"{client_name}_{env}_db_user"

    try:
        # Attempt to retrieve the secret
        try:
            get_secret_value_response = secrets_client.get_secret_value(SecretId=secret_name)
            secret_exists = True
            secret = json.loads(get_secret_value_response['SecretString'])
            logging.info(f"AWS Secret '{secret_name}' already exists.")
        except secrets_client.exceptions.ResourceNotFoundException:
            secret_exists = False
            secret = {}
            logging.info(f"Creating new secret '{secret_name}'.")

        # Check if the key already exists
        if new_key in secret:
            logging.info(f"Key '{new_key}' already exists in secret '{secret_name}'. No update performed.")
        else:
            # Key does not exist, create it
            role_password = generate_random_password(12)
            secret[new_key] = role_password
            updated_secret_string = json.dumps(secret)

            # Update or create the secret
            if secret_exists:
                secrets_client.update_secret(SecretId=secret_name, SecretString=updated_secret_string)
                logging.info(f"Updated secret '{secret_name}' with new key '{new_key}'.")
            else:
                secrets_client.create_secret(Name=secret_name, SecretString=updated_secret_string)
                logging.info(f"Created secret '{secret_name}' with key '{new_key}'.")

        return secret_name

    except Exception as e:
        print(f"Error handling the secret: {e}")

###################################  SSM FUNCTION  ########################################### 
            
# Send SSM Commands to MGMT Instance
def send_command_to_ec2(instance_id, commands, region, retries=3, delay=10):
    try:
        ssm_client = boto3.client('ssm', region_name=region)
        for attempt in range(retries):
            try:
                response = ssm_client.send_command(
                    InstanceIds=[instance_id],
                    DocumentName='AWS-RunShellScript',
                    Parameters={'commands': commands}
                )
                logging.info(f"SSM command sucessfully sent. Attempt {attempt+1}. Command ID: {response['Command']['CommandId']}")
                break
            except ClientError as e:
                logging.error(f"Error sending command to Management instance {instance_id}: {e}")
                if attempt < retries - 1:
                    logging.info(f"Retrying in {delay} seconds...")
                    time.sleep(delay)
    except ClientError as e:
        log_error(e)

################################### YAML TEMPLATING FUNCTION #################################
# Function to get data from YAML file
def get_yaml_data(client_name, env, region):
    yaml_path = os.path.join(os.getcwd(), 'customers', region, f'{client_name}.yaml')
    print(f"Attempting to read YAML file at: {yaml_path}")  # Log the path being accessed
    try:
        with open(yaml_path, 'r') as file:
            data = yaml.safe_load(file)
            return data.get(client_name, {}).get(env, {})
    except Exception as e:
        print(f"Error reading YAML file for {client_name} in {env}: {e}")
        return {}

###################################  EFS FUNCTIONS  ###########################################

# Check if EFS exists
def efs_exists(client_name, efs_client):
    try:
        response = efs_client.describe_file_systems()
        for fs in response['FileSystems']:
            if fs['Name'] == f"{client_name}-k8s":
                return fs['FileSystemId']
        return None
    except ClientError as e:
        log_error(e)
        return None

# Create EFS
def create_efs(client_name, region, efs_client):
    try:
        response = efs_client.create_file_system(PerformanceMode='generalPurpose', ThroughputMode='bursting', 
                                                 Encrypted=True, Tags=[{'Key': 'Name', 'Value': f"{client_name}-k8s"}])
        file_system_id = response['FileSystemId']
        wait_for_efs_available(file_system_id, efs_client)
        # Create a mount target for each subnet listed
        if region in REGION_SUBNET_MAPPING:
            security_groups = REGION_SECURITY_GROUP_MAPPING.get(region, [])
            for subnet_id in REGION_SUBNET_MAPPING[region]:
                create_mount_target(file_system_id, subnet_id, security_groups, efs_client)

        return file_system_id
    except ClientError as e:
        log_error(e)

# Wait for EFS availabity 
def wait_for_efs_available(file_system_id, efs_client, timeout=300, interval=10):
    elapsed_time = 0
    while elapsed_time < timeout:
        try:
            response = efs_client.describe_file_systems(FileSystemId=file_system_id)
            if response['FileSystems'][0]['LifeCycleState'] == 'available':
                logging.info(f"EFS {file_system_id} is now available.")
                return
        except ClientError as e:
            log_error(e)
            return
        time.sleep(interval)
        elapsed_time += interval
    logging.warning(f"Timeout waiting for EFS {file_system_id} to become available.") 

# Create mount target           
def create_mount_target(file_system_id, subnet_id, security_groups, efs_client):
    try:
        response = efs_client.create_mount_target(FileSystemId=file_system_id, SubnetId=subnet_id, SecurityGroups=security_groups)
        logging.info(f"Mount target created in subnet: {subnet_id} with security groups: {security_groups} for file system {file_system_id}.")
        logging.info("Waiting for mount target to be available...")  # Log message indicating the start of the waiting process
        return wait_for_mount_target_availability(file_system_id, efs_client)
    except ClientError as e:
        log_error(e)
        return False

# Wait for mount target availabity 
def wait_for_mount_target_availability(file_system_id, efs_client, timeout=300, interval=10):
    """
    Wait for all mount targets of a given file system to become available.
    """
    elapsed_time = 0
    while elapsed_time < timeout:
        try:
            response = efs_client.describe_mount_targets(FileSystemId=file_system_id)
            if all(mount['LifeCycleState'] == 'available' for mount in response['MountTargets']):
                logging.info(f"All mount targets for EFS {file_system_id} are now available.")
                return True
        except ClientError as e:
            log_error(e)
            return False
        time.sleep(interval)
        elapsed_time += interval
    logging.warning(f"Timeout waiting for all mount targets of EFS {file_system_id} to become available.")
    return False

# Check for existing Access points
def access_point_exists(file_system_id, access_point_name, efs_client):
    try:
        response = efs_client.describe_access_points(FileSystemId=file_system_id)
        for ap in response.get('AccessPoints', []):
            for tag in ap.get('Tags', []):
                if tag.get('Key') == 'Name' and tag.get('Value') == access_point_name:
                    return True
        return False
    except ClientError as e:
        log_error(e)
        return False
    
# Create Access points
def create_access_point(file_system_id, client_name, env, efs_client):
    access_point_name = f"{client_name}-{env}"
    if access_point_exists(file_system_id, access_point_name, efs_client):
        logging.info(f"Access point '{access_point_name}' already exists for {client_name} in {env} environment.")
        return None  # Return None if Access Point already exists
    else:
        try:
            access_point_options = {
                'FileSystemId': file_system_id, 
                'PosixUser': {'Uid': 65000, 'Gid': 65000},
                'RootDirectory': {
                    'Path': f"/{env}", 
                    'CreationInfo': {
                        'OwnerUid': 65000, 
                        'OwnerGid': 65000, 
                        'Permissions': '0755'
                    }
                },
                'Tags': [
                    {'Key': 'Name', 'Value': access_point_name}, 
                    {'Key': 'Client', 'Value': client_name}
                ]
            }
            response = efs_client.create_access_point(**access_point_options)
            access_point_id = response['AccessPointId']
            logging.info(f"Access point '{access_point_name}' created for {client_name} in {env} environment.")
            return access_point_id  # Return the newly created Access Point ID
        except ClientError as e:
            log_error(e)
            return None
        
# SSM Commands for mounting EFS, creating dirs and configuring permissions
def setup_client_directories(client_name, environments, efs_id, instance_id, region):
    mount_commands = [
        # Mount EFS to the specific client directory
        f"if mount | grep -q '{efs_id}:/ /mnt/{client_name}'; then echo 'EFS {efs_id} already mounted at /mnt/{client_name}'; else sudo mkdir -p /mnt/{client_name} && sudo mount -t efs -o tls {efs_id}:/ /mnt/{client_name}; fi",
    ]
    for env in environments:
        mount_commands.extend([
            # Check if the environment directory exists and is not empty
            f"if [ -d /mnt/{client_name}/{env}/assets ] && [ \"$(ls -A /mnt/{client_name}/{env}/assets)\" ]; then echo 'Error: Directory /mnt/{client_name}/{env}/assets already exists and is not empty'; exit 1; fi",
            f"sudo mkdir -p /mnt/{client_name}/{env}/assets",
            # Apply ownership and permissions
            f"sudo chown -R 65000:65000 /mnt/{client_name}/{env}",
            f"sudo chmod -R 0755 /mnt/{client_name}/{env}"
        ])
    logging.info(f"Mounting EFS, creating directories and setting up permissions for: {client_name} {env} via SSM...")
    send_command_to_ec2(instance_id, mount_commands, region)
    
###################################  DATABASE FUNCTIONS  ########################################### 

# Create RDS db, role and set permissions
def setup_rds_for_environment(client_name, env, instance_id, region, rds_endpoint, master_secret):
    
    # Retrieve master admin RDS secret from Secret Manager
    master_secret_values = get_secret_values(master_secret)
    # Get RDS master username and password to handle initial connection
    db_master_user = master_secret_values['username']
    db_master_password = master_secret_values['password']
    
    # Check for existing client secret | create a new secret and secret values 
    secret_name = create_or_update_secret(client_name,env,region)
    # Retrieve secret values created for new database
    client_secret_values = get_secret_values(secret_name)
   
    # Setup variables for db name and role according to conventions
    db_name = f'{client_name}_{env}_db'
    role_name = f'{client_name}_{env}_db_user'
     # Get password created to be used in the new role
    role_password = client_secret_values[role_name]
    
    # psql commands to configure DB for dotcms
    rds_commands = [
        f"export PGPASSWORD='{db_master_password}'",
        f"psql -h {rds_endpoint} -U {db_master_user} -c \"CREATE DATABASE {db_name};\"",
        f"psql -h {rds_endpoint} -U {db_master_user} -c \"CREATE ROLE {role_name} WITH LOGIN ENCRYPTED PASSWORD '{role_password}';\"",
        f"psql -h {rds_endpoint} -U {db_master_user} -c \"GRANT ALL PRIVILEGES ON DATABASE {db_name} TO {role_name};\"",
        f"psql -h {rds_endpoint} -U {db_master_user} -c \"ALTER DATABASE {db_name} OWNER TO {role_name};\"",
        f"unset PGPASSWORD"
    ]
    # send commands to MGMT instance via SSM
    logging.info(f"Setting up DB for: {client_name} {env} via SSM...")
    send_command_to_ec2(instance_id, rds_commands, region)
    logging.info(f"Database {db_name}, role {role_name} and permissions have been setup for {client_name} {env} via SSM...")


# Function to create a new user in OpenSearch
def create_opensearch_user(opensearch_endpoint, client_name, env):
    new_username = f"{client_name}-{env}-cluster" # CONFIRM
    url = f"https://{opensearch_endpoint}/_plugins/_security/api/internalusers/{new_username}"
    payload = {
        "password": "Barbarbarbar1!",
        "backend_roles": ["some_backend_role"],  # Modify as needed
        "attributes": {"attribute1": "value1"}   # Modify as needed
    }
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    try:
        response = requests.put(url, auth=HTTPBasicAuth("dsantos", "Barbarbarbar1!"), headers=headers, data=json.dumps(payload), verify=False)
        if response.status_code == 201:
            print(f"User '{new_username}' created successfully in OpenSearch.")
        else:
            print(f"Failed to create user. Status code: {response.status_code}, Response: {response.text}")
    except Exception as e:
        print(f"Error creating user: {e}")

def create_customer_directory_structure(base_path, customer_name, environments):
    customer_path = os.path.join(base_path, customer_name)
    namespace_path = os.path.join(customer_path, 'namespace')

    logging.info(f"Creating directories for customer: {customer_name}")
    for env in environments:
        env_path = os.path.join(customer_path, env)
        os.makedirs(env_path, exist_ok=True)
        logging.info(f"Created environment directory: {env_path}")

    for subdir in ['network-policies', 'secrets', 'volumes']:
        subdir_path = os.path.join(namespace_path, subdir)
        os.makedirs(subdir_path, exist_ok=True)
        logging.info(f"Created subdirectory: {subdir_path}")

    return customer_path, namespace_path
      
# Main function to handle multiple clients and environments
def main():
    base_infra_path = os.path.join(os.getcwd(), 'infrastructure-as-code', 'kubernetes', 'customers')
    # Code build environment variables
    region = os.environ.get('AWS_REGION')
    mgmt_instance = os.environ.get('EC2_MANAGEMENT') 
    rds_endpoint =  os.environ.get('RDS_ENDPOINT')
    master_secret = os.environ.get('SECRET_NAME')
    to_onboard_git_env_base64 = os.environ.get('TO_ONBOARD') 
    os_endpoint = os.environ.get('OS_ENDPOINT')
    
    # # Enable these variables for local testing (outside codebuild)
    # region = "ca-central-1" 
    # mgmt_instance = "i-0acdc2aee9fc7581e" 
    # rds_endpoint =  "rds-dsantos.cfv6lwb0lbi7.ca-central-1.rds.amazonaws.com" 
    # master_secret = 'arn:aws:secretsmanager:ca-central-1:292384479065:secret:master_password-i6USFD'
    # to_onboard_git_env_base64 = "eyJhcnFpdmEiOiBbInByb2QiLCJkZXYiXSwgImJyYW1ibGVzIjogWyJwcm9kIiwidWF0Il0sICJjcmFjayI6IFsicHJvZCJdfQo="
    # os_endpoint = 'vpc-dsantos-dotcms-os-lamcrtluzpw32m7n4gdzrtpxqy.ca-central-1.es.amazonaws.com'
    
    # Decode git environment variable
    to_onboard_git_env_decoded = base64.b64decode(to_onboard_git_env_base64).decode('utf-8')
    # Load the JSON string into a Python dictionary
    to_onboard = json.loads(to_onboard_git_env_decoded)
    
    efs_client = boto3.client('efs', region_name=region)
    for client_name, environments in to_onboard.items():
        file_system_id = efs_exists(client_name, efs_client)
        if file_system_id:
            logging.info(f"EFS already exists for {client_name}, checking for existing Access points...")
        else:
            logging.info(f"EFS {client_name}-k8s does not exist. Creating EFS...")
            file_system_id = create_efs(client_name, region, efs_client)
            if file_system_id:
                logging.info(f"EFS creation has been completed for {client_name}")
            else:
                logging.error(f"Failed to create EFS for {client_name}")
                continue

        for env in environments:
            # Retrieve or create the access point and get its ID
            access_point_id = access_point_exists(file_system_id, env, efs_client)
            if not access_point_id:
                access_point_id = create_access_point(file_system_id, client_name, env, efs_client)

            if not access_point_id:
                logging.error(f"Failed to create or find access point for {client_name} in {env}")
                continue

            setup_client_directories(client_name, environments, file_system_id, mgmt_instance, region)
            setup_rds_for_environment(client_name, env, mgmt_instance, region, rds_endpoint, master_secret)
            create_opensearch_user(os_endpoint, client_name, env)
            customer_path, namespace_path = create_customer_directory_structure(base_infra_path, client_name, environments)
            yaml_data = get_yaml_data(client_name, env, region)
            data = {
                    'smpt_server': f"email-smtp.{region}.amazonaws.com",
                    'cluster_id': f"{client_name}-{env}",
                    'client_name': client_name,
                    'full_name': f"dotcms-{client_name}-{env}",
                    'service_name': f"{client_name}-{env}-pp",
                    'pv_name': f"{client_name}-{env}-efs-pv",
                    'pv_size_storage_capacity': f"{yaml_data.get('volumes_specs', {}).get('pv_storage_capacity', '30')}",
                    'pv_accesspoint': f"access_point_id={access_point_id}",
                    'efs_id': f"{file_system_id}",
                    'pvc_name': f"{client_name}-{env}-efs-pvc",
                    'alb_service_name': f"{client_name}-{env}-svc",
                    'alb_name': f"{client_name}-{env}-alb",
                    'alb_tags': [
                        f"'dotcms.client.name.short={client_name}'",
                        "'VantaOwner=gregg.cobb@dotcms.com'",
                        f"'VantaDescription=ALB for {client_name} {env}'"
                    ],
                    'certificates_arns': yaml_data.get('alb_specs', {}).get('certificates', []), 
                    'alb_security_groups': REGION_SECURITY_GROUP_MAPPING.get(region, []),
                    'alb_attributes': [
                        "idle_timeout.timeout_seconds=60",
                        "access_logs.s3.enabled=true",
                        f"access_logs.s3.bucket=dotcms-{region}-alb-access-logs",
                        f"access_logs.s3.prefix={client_name}/{env}"
                    ],
                    'alb_waf': f"'{yaml_data.get('alb_specs', {}).get('waf', 'default_waf')}'",
                    'alb_host': f"{yaml_data.get('alb_specs', {}).get('hosts', 'default_host')}",  
                    'replicas': yaml_data.get('alb_specs', {}).get('replicas', 1), 
                    'env': env,
                    'dotcms_version': f"'{yaml_data.get('dotcms_version', 'default_version')}'",
                    'region': region,
                    'image': f"'{yaml_data.get('stateful_set_specs', {}).get('image', 'default_image')}'",
                    'requests': { 
                        'cpu': f"'{yaml_data.get('stateful_set_specs', {}).get('cpu', 'default_cpu')}'",
                        'memory': f"{yaml_data.get('stateful_set_specs', {}).get('memory', 'default_memory')}",
                        'ephemeral-storage': f"'{yaml_data.get('stateful_set_specs', {}).get('ephemeral-storage', 'default_ephemeral_storage')}'",
                        'cpu_limit': f"'{yaml_data.get('stateful_set_specs', {}).get('cpu_limit', 'default_cpu_limit')}'",
                        'memory_limit': f"{yaml_data.get('stateful_set_specs', {}).get('memory_limit', 'default_memory_limit')}"
                    },
                    'open_search_endpoint': f"https://{os_endpoint}", 
                    'rds_endpoint': f"'{rds_endpoint}'",
                    'provider_db_url': f"jdbc:postgresql://{rds_endpoint}/{client_name}_{env}_db",
                    'provider_db_username': f"{client_name}_{env}_db_user"
                }
            
            jinja_env = Environment(loader=FileSystemLoader('jinja_templates'), trim_blocks=True, lstrip_blocks=True)
            template_paths = {
                    'env': ['env/alb.yaml.j2', 'env/service.yaml.j2', 'env/ss.yaml.j2'],
                    'network-policies': ['network-policies/deny-all.yaml.j2', 'network-policies/dotcms.yaml.j2', 'network-policies/inter-ns.yaml.j2','network-policies/linkerd.yaml.j2'],
                    'volumes': ['volumes/pv.yaml.j2', 'volumes/pvc.yaml.j2'],
                    #'secrets': ['secrets/secrets-all.yaml.j2']
            }
            for category, templates in template_paths.items():
                output_dir = os.path.join(namespace_path, category) if category in ['network-policies', 'volumes', 'secrets'] else os.path.join(customer_path, env)

                if category == 'network-policies' and any(fname.endswith('.yaml') for fname in os.listdir(output_dir)):
                    logging.info(f"Skipping template generation for existing {category} in {output_dir}")
                    continue

                for template_file in templates:
                    template = jinja_env.get_template(template_file)
                    output_from_parsed_template = template.render(data)

                    os.makedirs(output_dir, exist_ok=True)
                    output_file = os.path.basename(template_file.replace(".j2", ".yaml"))
                    output_path = os.path.join(output_dir, output_file)
                    
                    if os.path.exists(output_path):
                        with open(output_path, 'a') as f:
                            f.write('\n\n' + output_from_parsed_template)  # Add newlines before appending
                            logging.info(f"Appended template to existing file: {output_path}")
                    else:
                        with open(output_path, 'w') as f:
                            f.write(output_from_parsed_template)
                            logging.info(f"Template generated: {output_path}")

if __name__ == "__main__":
    main()