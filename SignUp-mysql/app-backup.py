

from flask import Flask, render_template, url_for, flash, redirect, request
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from decouple import config
from flask_cors import CORS
import os
import subprocess
import random
import base64
from upload_tf_file import upload_file_to_gitlab
import json
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from flask import Flask, jsonify


gitlab_url = "https://gitlab.com"
project_id = "51066584"
access_token = "glpat-G3RiTBsw4oQopnHQi9-x"
branch_name = "main"

app = Flask(__name__, static_url_path='/static')

CORS(app) 

app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
 

app.config['WTF_CSRF_ENABLED'] = False

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://admin:cockpitpro@cockpit-pro.cdcxjmndyjyl.ap-southeast-2.rds.amazonaws.com:3306/cockpit'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
 
 
 
class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    todo = db.relationship('todo', backref='items', lazy=True)
 
    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"
 
 
class todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200))
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.now)
    complete=db.Column(db.Boolean,default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
 
    def __repr__(self):
        return f"todo('{self.content}', '{self.date_posted}')"
 
class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(),Length(min=3, max=20)])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')
 
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('username already exist. Please choose a different one.')
 
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('email already exist. Please choose a different one.')





def RegistrationJSONForm(data):
    #print(data['username'])
    user = User.query.filter_by(username=data['username']).first()
    email = User.query.filter_by(username=data['email']).first()
    if user or email:
        return 0
    return 1
    
class LoginForm(FlaskForm):
    email = StringField('Email',
    validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')
 
 
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
 
 
@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html')
 
def get_authenticated_user_id():
    username = session.get('username')
    return username
 
 
@app.route('/dashboard')
def dashboard():
    if current_user.is_authenticated:
        username = current_user.username
        return render_template('dashboard.html', username=username)
    else:
        return redirect(url_for('login'))  # Redirect to login if not authenticated
 
 
 
@app.route('/cloud')
def cloud():
    return render_template('cloud.html')
 
 
@app.route('/aws')
def aws():
    return render_template('aws.html')




 
@app.route('/json_submit_form_aws', methods=['POST'])
def json_submit_form_aws():
# Get  AWS form data
    
    form = request.get_json()
    Access_key = form['access_key']
    secret_Access_key = form['secret_access_key']
    User_name = form['user_name']
    User_Id = str(int(random.random()))

    user_detail = {
        "user": User_name,
        
    }

    print("User name:", User_name)

    file_name = "user_name.json"

    with open(file_name, 'w') as file:
        json.dump(user_detail, file)
 
 
 
    # Write AWS form data to terraform.vars file
    with open('terraform.tfvars', 'w') as f:
        f.write(f'Username = "{User_name}"\n')
        f.write(f'Access_key = "{Access_key}"\n')
        f.write(f'secret_Access_key = "{secret_Access_key}"\n')
    
 
     ## starting the script
 
    # Azure Resource Group and Key Vault Configuration
    resource_group_name = "rupali-rg"  
    key_vault_name = User_name
    secrets_file_path = "./terraform.tfvars"
 
    
 
    # Replace underscores with hyphens in the Key Vault and Resource Group names
    key_vault_name = key_vault_name.replace("_", "-")
    resource_group_name = resource_group_name.replace("_", "-")
 
    
    subscription_id = '1ce8bf33-286c-42dd-b193-10c310dd14b7'
    client_id = '4b5bd0f1-f692-47dd-a186-c8bf1925a86b'
    client_secret = 'N6C8Q~IP4Ls3SeCGkN4gOI0zUYjAEhM0A_d4Aa1K'
    tenant_id = 'bddba232-ecf3-49b7-a5b2-7cd128fc6135'
    matching_secret_found = False
    credential = ClientSecretCredential(tenant_id, client_id, client_secret)
    keyvault_client = KeyVaultManagementClient(credential, subscription_id)
    # Read secrets from the file
    secrets = {}
    with open(secrets_file_path, "r") as file:
        for line in file:
            key, value = line.strip().split(" = ")
            secrets[key] = value
    with open("./terraform.tfvars", "r") as file:
       for line in file:
          if line.strip().startswith('Access_key'):
             key, value = line.strip().splite(' = ')
             Access_key = value    
    
 
    
    keyvaults = keyvault_client.vaults.list()
    for vault in keyvaults:
        vault_name = vault.name
        keyvault_url = f"https://{vault_name}.vault.azure.net/"
        Accesskey = SecretClient(vault_url=keyvault_url, credential=credential)
        key_name = "Access_key"
        try:
          key = Accesskey.get_secret(key_name)
          key_value = key.value
          decoded_bytes = base64.b64decode(key_value)
          decoded_string = decoded_bytes.decode('utf-8')
          if decoded_string == Access_key:
                print(f"Key Vault '{vault_name}' has the matching secret: '{secret_name}'")
                matching_secret_found = True
                break 
        except Exception as e:
             print(f"Key Vault '{vault_name}' does not contain the secret: '{secret_name}'")
    if not matching_secret_found:
       print("No matching secret found in any of the Key Vaults.")
       
    # Authenticate to Azure
       try:
            # Use Azure CLI to get the access token
            access_token = subprocess.check_output(["az", "account", "get-access-token", "--query", "accessToken", "-o", "tsv"]).decode("utf-8").strip()
       except subprocess.CalledProcessError:
            print("Error: Failed to obtain Azure access token. Make sure you are logged into Azure CLI.")
            exit(1)
       
 
    # Create Azure Key Vault in the specified Resource Group
       try:
        subprocess.check_call(["az", "keyvault", "create", "--name", key_vault_name, "--resource-group", resource_group_name, "--location", "southcentralus"])
        print(f"Azure Key Vault '{key_vault_name}' created successfully in Resource Group '{resource_group_name}'.")
       except subprocess.CalledProcessError:
        print(f"Azure Key Vault '{key_vault_name}' already exists or encountered an error during creation in Resource Group '{resource_group_name}'.")
 
    
 
    # Store secrets in Azure Key Vault
       for key, value in secrets.items():
        # Replace underscores with hyphens in the secret name
         key = key.replace("_", "-")
         encoded_value = base64.b64encode(value.encode("utf-8")).decode("utf-8")     
         command = f"az keyvault secret set --vault-name {key_vault_name} --name {key} --value {encoded_value} --output none --query 'value'"
        # command = f"az keyvault secret set --vault-name {key_vault_name} --name {key} --value {value} --output none --query 'value'"
 
    
 
         try:
            # Use Azure CLI to set the secret in the Key Vault
            subprocess.check_call(["bash", "-c", f'AZURE_ACCESS_TOKEN="{access_token}" {command}'])
            print(f"Secret '{key}' stored in Azure Key Vault '{key_vault_name}' successfully.")
         except subprocess.CalledProcessError as e:
            print(f"Error: Failed to store secret '{key}' in Azure Key Vault '{key_vault_name}'.")
            print(e)
 
    
 
       print("All secrets have been stored in Azure Key Vault.")
    
 
       os.remove(secrets_file_path)     
    
 
       with open(secrets_file_path, "w"):         pass
 
    ## ending the script
       return json.dumps( {
            "message": 'Credential Succesfully added',
            "statusCode": 200
       }) 
    #return render_template('./create_aws.html')
 
@app.route('/submit_form', methods=['POST'])
def submit_form_aws():
# Get  AWS form data

    Access_key = request.form.get('Access_key')
    secret_Access_key = request.form.get('secret_Access_key')
    User_name = request.form.get('User_name')
    User_Id = str(int(random.random()))

    user_detail = {
        "user": User_name,
        
    }

    print("User name:", User_name)

    file_name = "user_name.json"

    with open(file_name, 'w') as file:
        json.dump(user_detail, file)
 
 
 
    # Write AWS form data to terraform.vars file
    with open('terraform.tfvars', 'w') as f:
        f.write(f'Access_key = "{Access_key}"\n')
        f.write(f'secret_Access_key = "{secret_Access_key}"\n')
    
 
     ## starting the script
 
    # Azure Resource Group and Key Vault Configuration
    resource_group_name = "rupali-rg"  
    key_vault_name = User_name
    secrets_file_path = "./terraform.tfvars"
 
    
 
    # Replace underscores with hyphens in the Key Vault and Resource Group names
    key_vault_name = key_vault_name.replace("_", "-")
    resource_group_name = resource_group_name.replace("_", "-")
 
    
    subscription_id = '1ce8bf33-286c-42dd-b193-10c310dd14b7'
    client_id = '4b5bd0f1-f692-47dd-a186-c8bf1925a86b'
    client_secret = 'N6C8Q~IP4Ls3SeCGkN4gOI0zUYjAEhM0A_d4Aa1K'
    tenant_id = 'bddba232-ecf3-49b7-a5b2-7cd128fc6135'
    matching_secret_found = False
    credential = ClientSecretCredential(tenant_id, client_id, client_secret)
    keyvault_client = KeyVaultManagementClient(credential, subscription_id)
    # Read secrets from the file
    secrets = {}
    with open(secrets_file_path, "r") as file:
        for line in file:
            key, value = line.strip().split(" = ")
            secrets[key] = value
    
    
 
    
 
    # Authenticate to Azure
    try:
        # Use Azure CLI to get the access token
        access_token = subprocess.check_output(["az", "account", "get-access-token", "--query", "accessToken", "-o", "tsv"]).decode("utf-8").strip()
    except subprocess.CalledProcessError:
        print("Error: Failed to obtain Azure access token. Make sure you are logged into Azure CLI.")
        exit(1)
 
 
    # Create Azure Key Vault in the specified Resource Group
    try:
        subprocess.check_call(["az", "keyvault", "create", "--name", key_vault_name, "--resource-group", resource_group_name, "--location", "southcentralus"])
        print(f"Azure Key Vault '{key_vault_name}' created successfully in Resource Group '{resource_group_name}'.")
    except subprocess.CalledProcessError:
        print(f"Azure Key Vault '{key_vault_name}' already exists or encountered an error during creation in Resource Group '{resource_group_name}'.")
 
    
 
    # Store secrets in Azure Key Vault
    for key, value in secrets.items():
        # Replace underscores with hyphens in the secret name
        key = key.replace("_", "-")
        encoded_value = base64.b64encode(value.encode("utf-8")).decode("utf-8")     
        command = f"az keyvault secret set --vault-name {key_vault_name} --name {key} --value {encoded_value} --output none --query 'value'"
        # command = f"az keyvault secret set --vault-name {key_vault_name} --name {key} --value {value} --output none --query 'value'"
 
    
 
        try:
            # Use Azure CLI to set the secret in the Key Vault
            subprocess.check_call(["bash", "-c", f'AZURE_ACCESS_TOKEN="{access_token}" {command}'])
            print(f"Secret '{key}' stored in Azure Key Vault '{key_vault_name}' successfully.")
        except subprocess.CalledProcessError as e:
            print(f"Error: Failed to store secret '{key}' in Azure Key Vault '{key_vault_name}'.")
            print(e)
 
    
 
    print("All secrets have been stored in Azure Key Vault.")
    
 
    os.remove(secrets_file_path)     
    
 
    with open(secrets_file_path, "w"):         pass
 
    ## ending the script
    # return json.dumps( {
    #         "message": 'Credential Succesfully added',
    #         "statusCode": 200
    # }) 
    return render_template('./create_aws.html')

@app.route('/aws_form', methods=['GET'])
def aws_form():
    return render_template('create_aws.html')
 
@app.route('/create_aws_form', methods=['GET'])
def create_aws_form():
    return render_template('create_aws.html')
 
@app.route('/success', methods=['GET'])
def success_aws():
    return render_template('success.html')


@app.route('/json_create_aws', methods=['POST'])
def json_create_aws():
    # Retrieve form data
    form = request.get_json()
    eks_name = form['eks_name']
    Region = form['region']
    instance_type = form['instance_type']
    eks_version = form['eks_version']
    desired_size = form['desired_size']
    max_size = form['max_size']
    min_size = form['min_size']
    cluster_type = form['cluster_type']
    
    eks_version = float(eks_version)
 
    # Create the content for terraform.tfvars
    with open('terraform.tfvars', 'w') as f:
        f.write(f'eks_name = "{eks_name}"\n')
        f.write(f'Region = "{Region}"\n')
        f.write(f'instance_type = "{instance_type}"\n')
        f.write(f'eks_version = "{eks_version}"\n')
        f.write(f'desired_size = "{desired_size}"\n')
        f.write(f'max_size = "{max_size}"\n')
        f.write(f'min_size = "{min_size}"\n')
        f.write(f'cluster_type = "{cluster_type}"\n')

    file_name = "./user_name.json"

    with open(file_name, 'r') as file:
        user_data = json.load(file)

    file_name = f'terraform-{user_data["user"]}.tfvars'
    file_path = f'templates/user-data/{file_name}'

    tf_config = f'''
eks_name = "{eks_name}"
Region = "{Region}"
instance_type = "{instance_type}"
eks_version = "{eks_version}"
desired_size = "{desired_size}"
max_size = "{max_size}"
min_size = "{min_size}"
cluster_type = "{cluster_type}"
'''
    print("Configuration:", tf_config)

    print("Configuration:", tf_config)

    
    print("Uploading tf file to gitlab")
    upload_file_to_gitlab(file_path, tf_config, project_id, access_token, gitlab_url, branch_name)
    print("Tf File uploaded successfully")


    # You can also redirect the user to a success page if needed
    return json.dumps({
        "message": "pipeline triggerd eks will be created..."
    })


@app.route('/create_aws', methods=['POST'])
def create_aws():
    # Retrieve form data
    eks_name = request.form.get('eks_name')
    Region = request.form.get('Region')
    instance_type = request.form.get('instance_type')
    eks_version = request.form.get('eks_version')
    desired_size = request.form.get('desired_size')
    max_size = request.form.get('max_size')
    min_size = request.form.get('min_size')
    cluster_type = request.form.get('cluster_type')
    
    eks_version = float(eks_version)
 
    # Create the content for terraform.tfvars
    with open('terraform.tfvars', 'w') as f:
        f.write(f'eks_name = "{eks_name}"\n')
        f.write(f'Region = "{Region}"\n')
        f.write(f'instance_type = "{instance_type}"\n')
        f.write(f'eks_version = "{eks_version}"\n')
        f.write(f'desired_size = "{desired_size}"\n')
        f.write(f'max_size = "{max_size}"\n')
        f.write(f'min_size = "{min_size}"\n')
        f.write(f'cluster_type = "{cluster_type}"\n')

    file_name = "./user_name.json"

    with open(file_name, 'r') as file:
        user_data = json.load(file)

    file_name = f'terraform-{user_data["user"]}.tfvars'
    file_path = f'templates/user-data/{file_name}'

    tf_config = f'''
eks_name = "{eks_name}"
Region = "{Region}"
instance_type = "{instance_type}"
eks_version = "{eks_version}"
desired_size = "{desired_size}"
max_size = "{max_size}"
min_size = "{min_size}"
cluster_type = "{cluster_type}"
'''
    print("Configuration:", tf_config)

    print("Configuration:", tf_config)

    
    print("Uploading tf file to gitlab")
    upload_file_to_gitlab(file_path, tf_config, project_id, access_token, gitlab_url, branch_name)
    print("Tf File uploaded successfully")


    # You can also redirect the user to a success page if needed
    return render_template('success.html')
 
#azure form
@app.route('/azure')
def azure():
    return render_template('azure.html')

@app.route('/submit_form_azure', methods=['POST'])
def submit_form_azure():
    # Get  azure form data
    subscription_id = request.form.get('subscription_id')
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')
    tenant_id = request.form.get('tenant_id')
    User_name = request.form.get('User_name')
    User_Id = str(int(random.random()))
 
    # Write Azure form data to terraform.vars file
    with open('terraform.tfvars', 'w') as f:
        f.write(f'username = "{User_name}"\n')
        f.write(f'subscription_id = "{subscription_id}"\n')
        f.write(f'client_id = "{client_id}"\n')
        f.write(f'client_secret = "{client_secret}"\n')
        f.write(f'tenant_id = "{tenant_id}"\n')
   
    ## starting the script
 
    # Azure Resource Group and Key Vault Configuration
    resource_group_name = "rupali-rg"  
    key_vault_name = User_name
    secrets_file_path = "./terraform.tfvars"


    user_detail = {
        "user": User_name
    }

    print("User name:", User_name)

    file_name = "user_name.json"

    with open(file_name, 'w') as file:
        json.dump(user_detail, file)

 
   # Replace underscores with hyphens in the Key Vault and Resource Group names
    key_vault_name = key_vault_name.replace("_", "-")
    resource_group_name = resource_group_name.replace("_", "-")    
    subscription_id = '1ce8bf33-286c-42dd-b193-10c310dd14b7'
    client_id = '4b5bd0f1-f692-47dd-a186-c8bf1925a86b'
    client_secret = 'N6C8Q~IP4Ls3SeCGkN4gOI0zUYjAEhM0A_d4Aa1K'
    tenant_id = 'bddba232-ecf3-49b7-a5b2-7cd128fc6135'
    matching_secret_found = False
    credential = ClientSecretCredential(tenant_id, client_id, client_secret)
    keyvault_client = KeyVaultManagementClient(credential, subscription_id)
    # Read secrets from the file
    secrets = {}
    with open(secrets_file_path, "r") as file:
        for line in file:
            key, value = line.strip().split(" = ")
            secrets[key] = value
    with open("./terraform.tfvars", "r") as file:
     for line in file:
        if line.strip().startswith('client_secret'):
            key, value = line.strip().split(' = ')
            # print(value)
            client_secret = value
 
    # print (client_secret)
 
    keyvaults = keyvault_client.vaults.list()
    for vault in keyvaults:
        vault_name = vault.name
        keyvault_url = f"https://{vault_name}.vault.azure.net/"
        secret_client = SecretClient(vault_url=keyvault_url, credential=credential)
        secret_name = "client-secret"
        try:
            secret = secret_client.get_secret(secret_name)
            secret_value = secret.value
            decoded_bytes = base64.b64decode(secret_value)
            decoded_string = decoded_bytes.decode('utf-8')
            # print(decoded_string)
            if decoded_string == client_secret:
                print(f"Key Vault '{vault_name}' has the matching secret: '{secret_name}'")
                matching_secret_found = True
                break  # Stop the loop when a matching secret is found
        except Exception as e:
            print(f"Key Vault '{vault_name}' does not contain the secret: '{secret_name}'")
    if not matching_secret_found:
        print("No matching secret found in any of the Key Vaults.")
 
    # Authenticate to Azure
 
        try:
            # Use Azure CLI to get the access token
            access_token = subprocess.check_output(["az", "account", "get-access-token", "--query", "accessToken", "-o", "tsv"]).decode("utf-8").strip()
        except subprocess.CalledProcessError:
            print("Error: Failed to obtain Azure access token. Make sure you are logged into Azure CLI.")
            exit(1)
 
        # Create Azure Key Vault in the specified Resource Group
        try:
            subprocess.check_call(["az", "keyvault", "create", "--name", key_vault_name, "--resource-group", resource_group_name, "--location", "southcentralus"])
            print(f"Azure Key Vault '{key_vault_name}' created successfully in Resource Group '{resource_group_name}'.")
        except subprocess.CalledProcessError:
            print(f"Azure Key Vault '{key_vault_name}' already exists or encountered an error during creation in Resource Group '{resource_group_name}'.")
 
        
        # Store secrets in Azure Key Vault
        for key, value in secrets.items():
            # Replace underscores with hyphens in the secret name
            key = key.replace("_", "-")
            encoded_value = base64.b64encode(value.encode("utf-8")).decode("utf-8")     
            command = f"az keyvault secret set --vault-name {key_vault_name} --name {key} --value {encoded_value} --output none --query 'value'"
            # command = f"az keyvault secret set --vault-name {key_vault_name} --name {key} --value {value} --output none --query 'value'"
 
            try:
                # Use Azure CLI to set the secret in the Key Vault
                subprocess.check_call(["bash", "-c", f'AZURE_ACCESS_TOKEN="{access_token}" {command}'])
                print(f"Secret '{key}' stored in Azure Key Vault '{key_vault_name}' successfully.")
            except subprocess.CalledProcessError as e:
                print(f"Error: Failed to store secret '{key}' in Azure Key Vault '{key_vault_name}'.")
                print(e)
 
        
        print("All secrets have been stored in Azure Key Vault.")
        
        os.remove(secrets_file_path)     
        
        with open(secrets_file_path, "w"):         pass
    
    ## ending the script

    return render_template('create_aks.html')



@app.route('/json_submit_form_azure', methods=['POST'])
def json_submit_form_azure():
    # Get  azure form data
    form = request.get_json()
    subscription_id = form['subscription_id']
    client_id = form['client_id']
    client_secret = form['client_secret']
    tenant_id = form['tenant_id']
    User_name = form['User_name']
    User_Id = str(int(random.random()))
 
    # Write Azure form data to terraform.vars file
    with open('terraform.tfvars', 'w') as f:
        f.write(f'username = "{User_name}"\n')
        f.write(f'subscription_id = "{subscription_id}"\n')
        f.write(f'client_id = "{client_id}"\n')
        f.write(f'client_secret = "{client_secret}"\n')
        f.write(f'tenant_id = "{tenant_id}"\n')
   
    ## starting the script
 
    # Azure Resource Group and Key Vault Configuration
    resource_group_name = "rupali-rg"  
    key_vault_name = User_name
    secrets_file_path = "./terraform.tfvars"


    user_detail = {
        "user": User_name,
        
    }

    print("User name:", User_name)

    file_name = "user_name.json"

    with open(file_name, 'w') as file:
        json.dump(user_detail, file)

    

 
   # Replace underscores with hyphens in the Key Vault and Resource Group names
    key_vault_name = key_vault_name.replace("_", "-")
    resource_group_name = resource_group_name.replace("_", "-")    
    subscription_id = '1ce8bf33-286c-42dd-b193-10c310dd14b7'
    client_id = '4b5bd0f1-f692-47dd-a186-c8bf1925a86b'
    client_secret = 'N6C8Q~IP4Ls3SeCGkN4gOI0zUYjAEhM0A_d4Aa1K'
    tenant_id = 'bddba232-ecf3-49b7-a5b2-7cd128fc6135'
    matching_secret_found = False
    credential = ClientSecretCredential(tenant_id, client_id, client_secret)
    keyvault_client = KeyVaultManagementClient(credential, subscription_id)
    # Read secrets from the file
    secrets = {}
    with open(secrets_file_path, "r") as file:
        for line in file:
            key, value = line.strip().split(" = ")
            secrets[key] = value
    with open("./terraform.tfvars", "r") as file:
     for line in file:
        if line.strip().startswith('client_secret'):
            key, value = line.strip().split(' = ')
            # print(value)
            client_secret = value
 
    # print (client_secret)
 
    keyvaults = keyvault_client.vaults.list()
    for vault in keyvaults:
        vault_name = vault.name
        keyvault_url = f"https://{vault_name}.vault.azure.net/"
        secret_client = SecretClient(vault_url=keyvault_url, credential=credential)
        secret_name = "client-secret"
        try:
            secret = secret_client.get_secret(secret_name)
            secret_value = secret.value
            decoded_bytes = base64.b64decode(secret_value)
            decoded_string = decoded_bytes.decode('utf-8')
            # print(decoded_string)
            if decoded_string == client_secret:
                print(f"Key Vault '{vault_name}' has the matching secret: '{secret_name}'")
                matching_secret_found = True
                break  # Stop the loop when a matching secret is found
        except Exception as e:
            print(f"Key Vault '{vault_name}' does not contain the secret: '{secret_name}'")
    if not matching_secret_found:
        print("No matching secret found in any of the Key Vaults.")
 
    # Authenticate to Azure
 
        try:
            # Use Azure CLI to get the access token
            access_token = subprocess.check_output(["az", "account", "get-access-token", "--query", "accessToken", "-o", "tsv"]).decode("utf-8").strip()
        except subprocess.CalledProcessError:
            print("Error: Failed to obtain Azure access token. Make sure you are logged into Azure CLI.")
            exit(1)
 
        # Create Azure Key Vault in the specified Resource Group
        try:
            subprocess.check_call(["az", "keyvault", "create", "--name", key_vault_name, "--resource-group", resource_group_name, "--location", "southcentralus"])
            print(f"Azure Key Vault '{key_vault_name}' created successfully in Resource Group '{resource_group_name}'.")
        except subprocess.CalledProcessError:
            print(f"Azure Key Vault '{key_vault_name}' already exists or encountered an error during creation in Resource Group '{resource_group_name}'.")
            return json.dumps({
                "message" : "Azure Key Vault '{}' already exists or encountered an error during creation in Resource Group '{}'".format(key_vault_name, resource_group_name)
            }),409
 
        
        # Store secrets in Azure Key Vault
        for key, value in secrets.items():
            # Replace underscores with hyphens in the secret name
            key = key.replace("_", "-")
            encoded_value = base64.b64encode(value.encode("utf-8")).decode("utf-8")     
            command = f"az keyvault secret set --vault-name {key_vault_name} --name {key} --value {encoded_value} --output none --query 'value'"
            # command = f"az keyvault secret set --vault-name {key_vault_name} --name {key} --value {value} --output none --query 'value'"
 
            try:
                # Use Azure CLI to set the secret in the Key Vault
                subprocess.check_call(["bash", "-c", f'AZURE_ACCESS_TOKEN="{access_token}" {command}'])
                print(f"Secret '{key}' stored in Azure Key Vault '{key_vault_name}' successfully.")
            except subprocess.CalledProcessError as e:
                print(f"Error: Failed to store secret '{key}' in Azure Key Vault '{key_vault_name}'.")
                print(e)
 
        
        print("All secrets have been stored in Azure Key Vault.")
        
        os.remove(secrets_file_path)     
        
        with open(secrets_file_path, "w"):         pass
     
    ## ending the script

    return json.dumps( {
            "message": 'Credential Succesfully added',
            "statusCode": 200
    })
   # flash('Credential Succesfully added.', 'success')

@app.route('/create_aks',methods=['GET'])
def get_create_aks():
    return render_template('create_aks.html')
 
 
@app.route('/azure_form', methods=['GET'])
def azure_form():
    return render_template('create_aks.html')
 
@app.route('/create_aks_form', methods=['GET'])
def create_aks_form():
    return render_template('create_aks.html')
 
@app.route('/success', methods=['GET'])
def success_aks():
    return render_template('success.html')
 
@app.route('/create_aks', methods=['POST'])
def create_aks():
    # Retrieve form data
    resource_group = request.form.get('resource_group')
    Region = request.form.get('Region')
    availability_zones = request.form.getlist('availability_zones[]')  # Use getlist to get multiple selected values
    aks_name = request.form.get('aks_name')
    aks_version = request.form.get('aks_version')
    node_count = request.form.get('node_count')
    cluster_type = request.form.get('cluster_type')


    file_name = "./user_name.json"

    with open(file_name, 'r') as file:
        user_data = json.load(file)

        

    user_data["rg_name"] = resource_group
    user_data["Region"] = Region
    user_data["availability_zones"] = availability_zones
    user_data["aks_name"] = aks_name
    user_data["aks_version"] = aks_version
    user_data["node_count"] = node_count
    user_data["cluster_type"] = cluster_type


    print("user name is:", user_data["user"])

    file_name = f'terraform-{user_data["user"]}.tfvars'
    
    aks_version = float(aks_version)
    
    # Initialize variables for vm_name and vm_pass
    vm_name = None
    vm_pass = None

    # Process form data based on Cluster Type
    if cluster_type == 'Private':
        vm_name = request.form.get('vm_name')
        vm_pass = request.form.get('vm_pass')

    # Convert availability_zones to a string containing an array
    availability_zones_str = '[' + ', '.join(['"' + zone + '"' for zone in availability_zones]) + ']'

    with open(file_name, 'w') as f:
        f.write(f'resource_group = "{resource_group}"\n')
        f.write(f'Region = "{Region}"\n')
        f.write(f'availability_zones = {availability_zones_str}\n')
        f.write(f'aks_name = "{aks_name}"\n') 
        f.write(f'aks_version = "{aks_version}"\n')
        f.write(f'node_count = "{node_count}"\n')
        f.write(f'cluster_type = "{cluster_type}"\n')
        if vm_name is not None:
            f.write(f'vm_name = "{vm_name}"\n')
            f.write(f'vm_pass = "{vm_pass}"\n')

    file_path = f'templates/user-data/{file_name}'

    if vm_name is not None:
        # Include vm_name and vm_pass if vm_name is not None
        tf_config = f'''
rg_name = "{resource_group}"
region = "{Region}"
availability_zones = "{availability_zones}"
aks_name = "{aks_name}"
aks_version = "{aks_version}"
node_count = "{node_count}"
vm_name = "{vm_name}"
vm_pass = "{vm_pass}"'''
    else:
        tf_config = f'''
rg_name = "{resource_group}"
region = "{Region}"
availability_zones = "{availability_zones}"
aks_name = "{aks_name}"
aks_version = "{aks_version}"
node_count = "{node_count}"'''
   
    print("Configuration:", tf_config)
    
    print("Uploading tf file to gitlab")
    upload_file_to_gitlab(file_path, tf_config, project_id, access_token, gitlab_url, branch_name)
    print("Tf File uploaded successfully")

    #os.remove("terraform.tfvars")
    # return json.dumps( {
    #         "message": 'pipeline is triggered! You are now able to log in ',
    #         "statusCode": 200
    #     })
    return jsonify(user_data)

    os.remove(file_name)
    os.remove("user_name.json")
    return json.dumps( {
            "message": 'pipeline is triggered! You are now able to log in ',
            "statusCode": 200
        })

    # return render_template('success.html')


 
@app.route('/json_create_aks', methods=['POST'])
def json_create_aks():
    # Retrieve form data
    form = request.get_json()
    resource_group = form['resource_group']
    Region = form['Region']
    availability_zones = form.get('availability_zones', [])  # Use getlist to get multiple selected values
    aks_name = form['aks_name']
    aks_version = form['aks_version']
    node_count = form['node_count']
    cluster_type = form['cluster_type']
    
    file_name = "./user_name.json"

    try:
        if os.path.exists(file_name):
            with open(file_name, 'r') as file:
                user_data = json.load(file)
        else:
            return json.dumps({
                "message": "Failed to trigger pipeline user already trigged the pipeline"
            }), 409  # Use 404 to indicate "Not Found" if the file is not found
    except FileNotFoundError:
        return json.dumps({
            "message": "Failed to trigger pipeline user already trigged the pipeline"
        }), 409
    except IOError as e:
        return json.dumps({
        "message": f"Failed to read the file: {str(e)}"
        }), 500 

    print("user name is:", user_data["user"])

    file_name = f'terraform-{user_data["user"]}.tfvars'
    
    aks_version = float(aks_version)
    
    # Initialize variables for vm_name and vm_pass
    vm_name = None
    vm_pass = None

    # Process form data based on Cluster Type
    if cluster_type == 'Private':
        vm_name = request.form.get('vm_name')
        vm_pass = request.form.get('vm_pass')

    # Convert availability_zones to a string containing an array
    availability_zones_str = '[' + ', '.join(['"' + zone + '"' for zone in availability_zones]) + ']'

    with open(file_name, 'w') as f:
        f.write(f'resource_group = "{resource_group}"\n')
        f.write(f'Region = "{Region}"\n')
        f.write(f'availability_zones = {availability_zones_str}\n')
        f.write(f'aks_name = "{aks_name}"\n') 
        f.write(f'aks_version = "{aks_version}"\n')
        f.write(f'node_count = "{node_count}"\n')
        f.write(f'cluster_type = "{cluster_type}"\n')
        if vm_name is not None:
            f.write(f'vm_name = "{vm_name}"\n')
            f.write(f'vm_pass = "{vm_pass}"\n')

    file_path = f'templates/user-data/{file_name}'

    if vm_name is not None:
        # Include vm_name and vm_pass if vm_name is not None
        tf_config = f'''
rg_name = "{resource_group}"
region = "{Region}"
availability_zones = "{availability_zones}"
aks_name = "{aks_name}"
aks_version = "{aks_version}"
node_count = "{node_count}"
vm_name = "{vm_name}"
vm_pass = "{vm_pass}"'''
    else:
        tf_config = f'''
rg_name = "{resource_group}"
region = "{Region}"
availability_zones = "{availability_zones}"
aks_name = "{aks_name}"
aks_version = "{aks_version}"
node_count = "{node_count}"'''
   
    print("Configuration:", tf_config)

    
    print("Uploading tf file to gitlab")
    upload_file_to_gitlab(file_path, tf_config, project_id, access_token, gitlab_url, branch_name)
    print("Tf File uploaded successfully")


    os.remove(file_name)
    os.remove("user_name.json")
    return json.dumps( {
            "message": 'pipeline is triggered! You are now able to log in ',
            "statusCode": 200
        })

@app.route('/gcp')
def gcp():
    return render_template('gcp.html')
 
@app.route('/submit_form_gke', methods=['POST'])
def submit_form_gcp():
    # Check if a file was uploaded
    if 'jsonFile' not in request.files:
        return json.dumps( {
            "message": 'failed to create key-vault'
        }),409
 
    json_file = request.files['jsonFile']
 
    # Check if the file has a filename
    if json_file.filename == '':
        return render_template('./file_submit.html')
 
    # Check if the file is a JSON file
    if not json_file.filename.endswith('.json'):
        return render_template('./submit.html')
    
    # Specify the directory where you want to save the JSON file
    save_directory = './'
 
    # Save the JSON file with its original filename
    json_file.save(f"{save_directory}/{json_file.filename}")
 
    User_name = request.form.get('User_name')
    User_Id = str(int(random.random()))
 
    # Azure Key Vault and Secrets Configuration
    key_vault_name = User_name
 
    resource_group_name = "rupali-rg"
    location = "westus2"
    secrets_file_path = json_file.filename
 
        # Create Azure Key Vault if it doesn't exist
    create_kv_command = f"az keyvault create --name {key_vault_name} --resource-group {resource_group_name} --location {location}"
    try:
            subprocess.check_output(create_kv_command, shell=True)
            print(f"Azure Key Vault '{key_vault_name}' created successfully in Resource Group '{resource_group_name}'.")
    except subprocess.CalledProcessError:
            print(f"Error: Failed to create Azure Key Vault.")
            exit(1)
 
        # Authenticate to Azure
    try:
            # Use Azure CLI to get the access token
            access_token = subprocess.check_output(["az", "account", "get-access-token", "--query", "accessToken", "-o", "tsv"]).decode("utf-8").strip()
    except subprocess.CalledProcessError:
            print("Error: Failed to obtain Azure access token. Make sure you are logged into Azure CLI.")
            exit(1)
 
        # Read the entire content of the JSON file
    with open(secrets_file_path, 'r') as json_file:
            secrets_content = json_file.read()
 
 
        # Store the entire JSON content as a secret
    secret_name = "your-secret-name"
    encoded_value = base64.b64encode(secrets_content.encode("utf-8")).decode("utf-8")     
    command = f"az keyvault secret set --vault-name {key_vault_name} --name {secret_name} --value {encoded_value} --output none --query 'value'"
          # Replace with your desired secret name
    # command = f"az keyvault secret set --vault-name {key_vault_name} --name {secret_name} --value '{secrets_content}' --output none --query 'value'"
    try:
            # Use Azure CLI to set the secret in the Key Vault
            subprocess.check_call(["bash", "-c", f'AZURE_ACCESS_TOKEN="{access_token}" {command}'])
            print(f"Secret '{secret_name}' has been stored in Azure Key Vault.")
    except subprocess.CalledProcessError as e:
            print(f"Error: Failed to store secret '{secret_name}' in Azure Key Vault.")
            print(e)
 
        
 
    print("Secret has been stored in Azure Key Vault.")
    os.remove(secrets_file_path)    
 
    
    return json.dumps( {
            "message": 'Credential Succesfully added',
            "statusCode": 200
    })
   # return render_template('create_gke.html')
   
#gcp
@app.route('/gcp_form', methods=['GET'])
def gcp_form():
    return render_template('create_gke.html')
 
@app.route('/create_gke_form', methods=['GET'])
def create_gke_form():
    return render_template('create_gke.html')
 
@app.route('/success', methods=['GET'])
def success_gke():
    return render_template('success.html')
 
@app.route('/create_gke', methods=['POST'])
def create_gke():
    # Retrieve form data
    project = request.form.get('project')
    Region = request.form.get('Region')
    gke_name = request.form.get('gke_name')
    gke_version = request.form.get('gke_version')
    node_count = request.form.get('node_count')
    cluster_type = request.form.get('cluster_type')
    
    gke_version = float(gke_version)
 
    # Initialize variables for vm_name and vm_pass
    vm_name = None
    vm_pass = None
 
    # Process form data based on Cluster Type
    if cluster_type == 'Private':
        vm_name = request.form.get('vm_name')
        vm_pass = request.form.get('vm_pass')
 
    # Create the content for terraform.tfvars
    with open('terraform.tfvars', 'w') as f:
        f.write(f'project = "{project}"\n')
        f.write(f'Region = "{Region}"\n')
        f.write(f'gke_name = "{gke_name}"\n')
        f.write(f'gke_version = "{gke_version}"\n')
        f.write(f'node_count = "{node_count}"\n')
        f.write(f'cluster_type = "{cluster_type}"\n')
        if vm_name is not None:
            f.write(f'vm_name = "{vm_name}"\n')
            f.write(f'vm_pass = "{vm_pass}"\n')

    file_name = "./user_name.json"

    with open(file_name, 'r') as file:
        user_data = json.load(file)

    file_name = f'terraform-{user_data["user"]}.tfvars'
    file_path = f'templates/user-data/{file_name}'


    tf_config = f'''
    project = "{project}"
    Region = "{Region}"
    gke_name = "{gke_name}"
    gke_version = "{gke_version}"
    node_count = "{node_count}"
    cluster_type = "{cluster_type}"
    vm_name = "{vm_name}"  
    vm_pass = "{vm_pass}" 
    '''




    # Print the tf_config (optional)
    print("Configuration:", tf_config)

    # Upload the tfvars file to GitLab
    print("Uploading tfvars file to GitLab")
    upload_file_to_gitlab(file_path, tf_config, project_id, access_token, gitlab_url, branch_name)
    print("Tfvars File uploaded successfully")

    # You can also redirect the user to a success page if needed
    
    return render_template('success.html')

@app.route('/json_create_gke', methods=['POST'])
def json_create_gke():
    # Retrieve form data
    form = request.get_json()
    project = form['project']
    Region = form['Region']
    gke_name = form['gke_name']
    gke_version = form['gke_version']
    node_count = form['node_count']
    cluster_type = form['cluster_type']
    
    gke_version = float(gke_version)
 
    # Initialize variables for vm_name and vm_pass
    vm_name = None
    vm_pass = None
 
    # Process form data based on Cluster Type
    if cluster_type == 'Private':
        vm_name = request.form.get('vm_name')
        vm_pass = request.form.get('vm_pass')
 
    # Create the content for terraform.tfvars
    with open('terraform.tfvars', 'w') as f:
        f.write(f'project = "{project}"\n')
        f.write(f'Region = "{Region}"\n')
        f.write(f'gke_name = "{gke_name}"\n')
        f.write(f'gke_version = "{gke_version}"\n')
        f.write(f'node_count = "{node_count}"\n')
        f.write(f'cluster_type = "{cluster_type}"\n')
        if vm_name is not None:
            f.write(f'vm_name = "{vm_name}"\n')
            f.write(f'vm_pass = "{vm_pass}"\n')

    file_name = "./user_name.json"

    with open(file_name, 'r') as file:
        user_data = json.load(file)

    file_name = f'terraform-{user_data["user"]}.tfvars'
    file_path = f'templates/user-data/{file_name}'


    tf_config = f'''
    project = "{project}"
    Region = "{Region}"
    gke_name = "{gke_name}"
    gke_version = "{gke_version}"
    node_count = "{node_count}"
    cluster_type = "{cluster_type}"
    vm_name = "{vm_name}"  
    vm_pass = "{vm_pass}" 
    '''




    # Print the tf_config (optional)
    print("Configuration:", tf_config)

    # Upload the tfvars file to GitLab
    print("Uploading tfvars file to GitLab")
    upload_file_to_gitlab(file_path, tf_config, project_id, access_token, gitlab_url, branch_name)
    print("Tfvars File uploaded successfully")

    # You can also redirect the user to a success page if needed
    return json.dumps( {
            "message": 'gke created Succesfully',
            "statusCode": 200
    })
    #return render_template('success.html')



@app.route("/index")
@login_required
def index():
    todos=todo.query.filter_by(user_id=current_user.id)
    return render_template('index.html',todos=todos)
 
 
@app.route("/about")
def about():
    return render_template('about.html', title='About')
 
 
@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
 
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()

        return json.dumps( {
            "message": 'Your account has been created! You are now able to log in ',
            "statusCode": 200
        }), 200
   #     flash('Your account has been created! You are now able to log in', 'success')
    #    return redirect(url_for('login'))
    #return render_template('register.html', title='Register', form=form)
    return json.dumps({
	   "message": 'Invalid or not mathced with defined expression',
	   "statusCode": 401
	}), 401

@app.route("/jsonRegister", methods=['POST'])
def josnRegister():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = request.get_json()
    if RegistrationJSONForm(form):
        hashed_password = bcrypt.generate_password_hash(form['password']).decode('utf-8')
        user = User(username=form['username'], email=form['email'], password=hashed_password)
        db.session.add(user)
        db.session.commit()
        return json.dumps( {
                "message": 'Your account has been created! You are now able to log in ',
                "statusCode": 200
            }), 200
    return json.dumps({
	   "message": 'duplicate username or email',
	   "statusCode": 401
	}), 401
   #     flash('Your account has been created! You are now able to log in', 'success')
    #    return redirect(url_for('login'))
    #return render_template('register.html', title='Register', form=form)
    #return json.dumps({
     #      "message": 'Invalid or not mathced with defined expression',
      #     "statusCode": 401
       # }), 401
@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash('Login successful.', 'success')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

 
 
@app.route("/JsonLogin", methods=['POST'])
def JsonLogin():
    form = request.get_json()
    user = User.query.filter_by(email=form['email']).first()
    if user:
        decoded = bcrypt.check_password_hash(user.password, form['password'])
        print(decoded)
        if user and decoded:
            return json.dumps( {
                "message": 'Login successful!',
                "statusCode": 200
            })
        else: 
            return json.dumps( {
            "message": 'Login Unsuccessful. Please check email and password',
            "statusCode": 401
            }), 401
    else:
        return json.dumps( {
            "message": 'Login Unsuccessful. Please check email and password',
            "statusCode": 401
            }), 401           

@app.route("/logout")
def logout():
    logout_user()
    flash('Logout successful.', 'success')
    return redirect(url_for('home'))
 
 
 
 
@app.route("/account")
@login_required
def account():
    
    return render_template('account.html', title='Account')
 
@app.route("/add",methods=["POST"])
@login_required
def add():
    user_id=current_user.id
    if request.form['todoitem'] != "" :
        todos=todo(content=request.form['todoitem'],complete=False,user_id=user_id)
        db.session.add(todos)
        db.session.commit()
    else:
        flash('cannot add empty list', 'danger')
        return redirect(url_for("index"))
        
    return redirect(url_for("index"))
 
 
@app.route("/complete/<int:id>")
@login_required
def complete(id):
    ToDo= todo.query.get(id)
 
    if not ToDo:
        return redirect("/index")
 
    if ToDo.complete:
        ToDo.complete=False
    else:
        ToDo.complete=True
 
    db.session.add(ToDo)
    db.session.commit()
    
    return redirect("/index")
 
@app.route("/delete/<int:id>")
@login_required
def delete(id):
    ToDo=todo.query.get(id)
    if not ToDo:
        return redirect("/index")
    
    db.session.delete(ToDo)
    db.session.commit()
 
    return redirect("/index")
 
 
if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0',port=4000)
