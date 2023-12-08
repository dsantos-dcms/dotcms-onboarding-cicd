import subprocess
import yaml
import os
import logging
import json
import base64

def update_region_yaml(region, onboarded_clients):
    """
    Update the region.yaml file with onboarded clients and their environments.
    """
    region_yaml_path = os.path.join(os.getcwd(), 'config', f'{region}.yaml')
    
    try:
        with open(region_yaml_path, 'r') as file:
            region_data = yaml.safe_load(file) or {}
    except FileNotFoundError:
        region_data = {}

    for client_name, environments in onboarded_clients.items():
        region_data.setdefault(client_name, []).extend(env for env in environments if env not in region_data.get(client_name, []))

    with open(region_yaml_path, 'w') as file:
        yaml.dump(region_data, file, default_flow_style=False)
            
def run_git_command(command):
    try:
        subprocess.run(command, check=True, shell=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running git command '{command}': {e}")

to_onboard_git_env_base64 = os.environ.get('ONBOARDED')    
# Decode git environment variable
to_onboard_git_env_decoded = base64.b64decode(to_onboard_git_env_base64).decode('utf-8')
# Load the JSON string into a Python dictionary
to_onboard = json.loads(to_onboard_git_env_decoded)
region = os.environ.get('AWS_REGION')
update_region_yaml(region, to_onboard)
