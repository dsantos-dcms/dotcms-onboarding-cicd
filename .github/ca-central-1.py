import yaml
import os
import json
import base64

def read_yaml_files(directory):
    data = []
    for file in os.listdir(directory):
        if file.endswith(".yaml"):
            full_path = os.path.join(directory, file)
            with open(full_path, 'r') as file:
                yaml_data = yaml.safe_load(file)
                data.append(yaml_data)
    return data

def find_new_customers_or_environments(customers_data, onboarded_file):
    with open(onboarded_file, 'r') as file:
        onboarded_data = yaml.safe_load(file)

    new_customers_or_environments = {}

    for customer, environments in customers_data.items():
        if customer not in onboarded_data:
            # Entire customer is new
            new_customers_or_environments[customer] = list(environments.keys())
        else:
            # Check for new environments
            for environment in environments:
                if environment not in onboarded_data[customer]:
                    if customer not in new_customers_or_environments:
                        new_customers_or_environments[customer] = []
                    new_customers_or_environments[customer].append(environment)
  
    return new_customers_or_environments

# Function usage
obtained_data = read_yaml_files('./customers/ca-central-1/')  # Replace with the correct path
# Consolidate all data into a single dictionary
consolidated_customers_data = {k: v for d in obtained_data for k, v in d.items()}

results = find_new_customers_or_environments(consolidated_customers_data, './config/ca-central-1.yaml')

# Convert the dictionary to a JSON string
json_str = json.dumps(results)

# Encode the JSON string to bytes
json_bytes = json_str.encode('utf-8')

# Base64 encode the bytes
base64_str = base64.b64encode(json_bytes).decode('utf-8')

print(base64_str)
