from packaging import version
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
from google.cloud import container_v1
from googleapiclient import discovery
from google.oauth2 import service_account
import os
import subprocess
import random
import base64
from azure.mgmt.containerservice import ContainerServiceClient
from upload_tf_file import upload_file_to_gitlab
import json
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from flask import Flask, jsonify
import hcl
import requests

# Your Flask setup code

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

gitlab_url = "https://gitlab.com"
project_id = "51819357"
access_token = "glpat-EmyFa2Kj5NCy8gUiu4qG"    
branch_name = "featurebrach1"
app = Flask(__name__, static_url_path='/static')

CORS(app) 

app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
 

app.config['WTF_CSRF_ENABLED'] = False

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://admin:cockpitpro@cockpit-database.c3xcuwqpwvp4.ap-south-1.rds.amazonaws.com:3306/cockpit'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
 
 
class UsernameTable(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)

    def __repr__(self):
        return f"UsernameTable('{self.username}')"
class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    todo = db.relationship('todo', backref='items', lazy=True)
 
    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

class Data(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    cloudname = db.Column(db.String(20), nullable=False)
    clustername = db.Column(db.String(20), nullable=False)
 
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
 
 
#@app.route('/dashboard')
#def dashboard():
#    if current_user.is_authenticated:
#        username = current_user.username
#        return render_template('dashboard.html', username=username)
#    else:
#        return redirect(url_for('login'))  # Redirect to login if not authenticated
 



@app.route('/final-dashboard', methods=['GET', 'POST'])
def dashboard():
    if current_user.is_authenticated:
        username = current_user.username
        return render_template('final-dashboard.html', username=username)
    else:
        return redirect(url_for('login'))

@app.route('/dashboard-cloud', methods=['GET', 'POST'])
def dashboard_cloud():
    if current_user.is_authenticated:
        username = current_user.username
        return render_template('dashboard-cloud.html', username=username)
    else:
        return redirect(url_for('login'))

@app.route('/show-details-aws', methods=['GET', 'POST'])
def show_details_aws():
    if current_user.is_authenticated:
        username = current_user.username
        key_vault_url = f"https://{username}.vault.azure.net/"
    
        # Use DefaultAzureCredential to automatically authenticate
        credential = DefaultAzureCredential()

        # Create a SecretClient using the Key Vault URL
        secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

        # Retrieve the secrets
        secret_access_key = secret_client.get_secret("secret-Access-key").value
        access_key = secret_client.get_secret("Access-key").value

        return render_template('show-details-aws.html', access_key=access_key, secret_access_key=secret_access_key, username=username)
    else:
        return redirect(url_for('login'))

def export_azure_credentials():
    os.environ["AZURE_CLIENT_ID"] = "4b5bd0f1-f692-47dd-a186-c8bf1925a86b"
    os.environ["AZURE_CLIENT_SECRET"] = "N6C8Q~IP4Ls3SeCGkN4gOI0zUYjAEhM0A_d4Aa1K"
    os.environ["AZURE_TENANT_ID"] = "bddba232-ecf3-49b7-a5b2-7cd128fc6135"
    os.environ["AZURE_SUBSCRIPTION_ID"] = "1ce8bf33-286c-42dd-b193-10c310dd14b7"
export_azure_credentials()
@app.route('/json-show-details-aws', methods=['POST'])
def json_show_details_aws():
    if current_user.is_authenticated:
        username = current_user.username
        key_vault_url = f"https://{username}.vault.azure.net/"
    
        # Use DefaultAzureCredential to automatically authenticate
        credential = DefaultAzureCredential()

        # Create a SecretClient using the Key Vault URL
        secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

        # Retrieve the secrets
        secret_access_key = secret_client.get_secret("secret-Access-key").value
        access_key = secret_client.get_secret("Access-key").value

        # Return JSON response
        response_data = {
            "access_key": access_key,
            "secret_access_key": secret_access_key,
            "username": username
        }

        return jsonify(response_data),200
    else:
        return jsonify({"error": "no secrets found"}), 401





@app.route('/show-details-azure', methods=['GET', 'POST'])
def show_details_azure():
    if current_user.is_authenticated:
        username = current_user.username
        key_vault_url = f"https://{username}.vault.azure.net/"
    
        # Use DefaultAzureCredential to automatically authenticate
        credential = DefaultAzureCredential()
        
        # Create a SecretClient using the Key Vault URL
        secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

        # Retrieve the secret containing your Azure credentials
        secret_id = "client-id"
        secret_secret = "client-secret"
        secret_subscription = "subscription-id"
        secret_tenant = "tenant-id"

        client_id = secret_client.get_secret(secret_id).value
        client_secret = secret_client.get_secret(secret_secret).value
        subscription_id = secret_client.get_secret(secret_subscription).value
        tenant_id = secret_client.get_secret(secret_tenant).value
        return render_template('show-details-azure.html', username=username, client_id=client_id, client_secret=client_secret, subscription_id=subscription_id, tenant_id=tenant_id)
        
    else:
        return redirect(url_for('login'))


@app.route('/json-show-details-azure', methods=['POST'])
def json_show_details_azure():
    if current_user.is_authenticated:
        username = current_user.username
        key_vault_url = f"https://{username}.vault.azure.net/"
    
        # Use DefaultAzureCredential to automatically authenticate
        credential = DefaultAzureCredential()
        
        # Create a SecretClient using the Key Vault URL
        secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

        # Retrieve the secret containing your Azure credentials
        secret_id = "client-id"
        secret_secret = "client-secret"
        secret_subscription = "subscription-id"
        secret_tenant = "tenant-id"

        client_id = secret_client.get_secret(secret_id).value
        client_secret = secret_client.get_secret(secret_secret).value
        subscription_id = secret_client.get_secret(secret_subscription).value
        tenant_id = secret_client.get_secret(secret_tenant).value

        # Return JSON response
        response_data = {
            "username": username,
            "client_id": client_id,
            "client_secret": client_secret,
            "subscription_id": subscription_id,
            "tenant_id": tenant_id
        }

        return jsonify(response_data), 200
    else:
        return jsonify({"error": "no secrets found"}), 401


@app.route('/show-details-gcp', methods=['GET', 'POST'])
def show_details_gcp():
    if current_user.is_authenticated:
        username = current_user.username
        key_vault_url = f"https://{username}.vault.azure.net/"
    
    # Use DefaultAzureCredential to automatically authenticate
        credential = DefaultAzureCredential()
        
        # Create a SecretClient using the Key Vault URL
        secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

        # Retrieve the secrets
        secret_name = "your-secret-name"
        secret = secret_client.get_secret(secret_name)
        secret_value = secret.value

        return render_template('show-details-gcp.html', secret_value=secret_value, username=username)
        
    else:
        return redirect(url_for('login'))
        
@app.route('/json-show-details-gcp', methods=['POST'])
def json_show_details_gcp():
    if current_user.is_authenticated:
        username = current_user.username
        key_vault_url = f"https://{username}.vault.azure.net/"
    
        # Use DefaultAzureCredential to automatically authenticate
        credential = DefaultAzureCredential()
        
        # Create a SecretClient using the Key Vault URL
        secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

        # Retrieve the secrets
        secret_name = "your-secret-name"
        secret = secret_client.get_secret(secret_name)
        secret_value = secret.value

        # Return JSON response
        response_data = {
            "username": username,
            "secret_value": secret_value
        }

        return jsonify(response_data), 200
        
    else:
        return jsonify({"error": "no secrets found"}), 401




@app.route('/create-cluster', methods=['GET', 'POST'])
def create_cluster():
    if current_user.is_authenticated:
        username = current_user.username
        return render_template('create-cluster.html', username=username)
    else:
        return redirect(url_for('login'))



@app.route('/my-cluster', methods=['GET', 'POST'])
def my_cluster():
    if current_user.is_authenticated:
        username = current_user.username
        return render_template('my-cluster.html', username=username)
    else:
        return redirect(url_for('login'))
@app.route('/my-cluster-details-aws', methods=['GET', 'POST'])
def my_cluster_details_aws():
    if current_user.is_authenticated:
        username = current_user.username
        # Azure Key Vault details for AWS
        key_vault_url_aws = "https://aws-final.vault.azure.net/"
        access_key_secret = "Access-key"
        secret_access_key_secret = "secret-Access-key"

        # Retrieve credentials from Azure Key Vault
        credential_aws = DefaultAzureCredential()
        secret_client_aws = SecretClient(vault_url=key_vault_url_aws, credential=credential_aws)

        # Retrieve the secrets from Key Vault
        aws_access_key = secret_client_aws.get_secret(access_key_secret).value
        aws_secret_access_key = secret_client_aws.get_secret(secret_access_key_secret).value
        regin = request.form.get('tenant_id')
        # Set up Boto3 client with retrieved credentials and region
        eks_client = boto3.client(
            'eks',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_access_key,
            region_name=regin
        )

        clusters_data = []

        # List ready or healthy EKS clusters in the specified AWS region
        try:
            eks_clusters = eks_client.list_clusters()
            for cluster_name in eks_clusters['clusters']:
                cluster_info = eks_client.describe_cluster(name=cluster_name)
                if cluster_info['cluster']['status'] == 'ACTIVE':
                    clusters_data.append({"name": cluster_name})
        except Exception as e:
            print(f"Error listing ready or healthy clusters in us-east-1: {str(e)}")

        return render_template('my-cluster-details-aws.html', username=username, cluster=clusters_data)
    else:
        return redirect(url_for('login'))



@app.route('/json-my-cluster-details-aws', methods=['POST'])
def json_my_cluster_details_aws():
    if current_user.is_authenticated:
        # Azure Key Vault details for AWS
        key_vault_url_aws = "https://aws-final.vault.azure.net/"
        access_key_secret = "Access-key"
        secret_access_key_secret = "secret-Access-key"

        # Retrieve credentials from Azure Key Vault
        credential_aws = DefaultAzureCredential()
        secret_client_aws = SecretClient(vault_url=key_vault_url_aws, credential=credential_aws)

        # Retrieve the secrets from Key Vault
        aws_access_key = secret_client_aws.get_secret(access_key_secret).value
        aws_secret_access_key = secret_client_aws.get_secret(secret_access_key_secret).value
        region = request.form.get('region')  # Assuming 'region' is the name attribute of the input field

        # Set up Boto3 client with retrieved credentials and region
        eks_client = boto3.client(
            'eks',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_access_key,
            region_name=region
        )

        clusters_data = []

        try:
            # List ready or healthy EKS clusters in the specified AWS region
            eks_clusters = eks_client.list_clusters()
            for cluster_name in eks_clusters['clusters']:
                cluster_info = eks_client.describe_cluster(name=cluster_name)
                if cluster_info['cluster']['status'] == 'ACTIVE':
                    clusters_data.append({"name": cluster_name})

            # Return the clusters_data as JSON response
            return jsonify({"clusters": clusters_data}),200

        except Exception as e:
            error_message = f"Error listing ready or healthy clusters in {region}: {str(e)}"
            return jsonify({"error": error_message}), 500  # Return error message with status code 500

    else:
        return jsonify({"error": "User not authenticated"}), 401 




@app.route('/my-cluster-details', methods=['GET', 'POST'])
def my_cluster_details():
    if current_user.is_authenticated:
        username = current_user.username
        return render_template('my-cluster-details.html', username=username)
    else:
        return redirect(url_for('login'))


@app.route('/my-cluster-details-azure', methods=['GET', 'POST'])
def my_cluster_details_azure():
    if current_user.is_authenticated:
        username = current_user.username
        # Azure Key Vault details
        key_vault_url = f"https://{username}.vault.azure.net/"
        client_id_secret = "client-id"
        client_secret_secret = "client-secret"
        subscription_id_secret = "subscription-id"
        tenant_id_secret = "tenant-id"

        # Retrieve credentials from Azure Key Vault
        credential = DefaultAzureCredential()

        # Create a SecretClient using the Key Vault URL
        secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

        # Retrieve the secrets from Key Vault
        client_id = secret_client.get_secret(client_id_secret).value
        client_secret = secret_client.get_secret(client_secret_secret).value
        subscription_id = secret_client.get_secret(subscription_id_secret).value
        tenant_id = secret_client.get_secret(tenant_id_secret).value

        # Set up the ContainerServiceClient with retrieved credentials
        aks_client = ContainerServiceClient(credential, subscription_id)

        # List AKS clusters in the subscription
        aks_clusters = aks_client.managed_clusters.list()
        healthy_clusters = [cluster.name for cluster in aks_clusters
                        if cluster.provisioning_state.lower() == "succeeded"
                        and cluster.agent_pool_profiles[0].provisioning_state.lower() == "succeeded"]
        # Print healthy or ready AKS clusters
        # print("Healthy Azure Kubernetes Service Clusters:")
        # for aks_cluster in aks_clusters:
        #     if aks_cluster.provisioning_state.lower() == "succeeded" and aks_cluster.agent_pool_profiles[0].provisioning_state.lower() == "succeeded":
        #         print(f" - {aks_cluster.name}")

        return render_template('my-cluster-details-azure.html', username=username, aks_clusters=healthy_clusters )
    else:
        return redirect(url_for('login'))


@app.route('/json-my-cluster-details-azure', methods=['POST'])
def json_my_cluster_details_azure():
    if current_user.is_authenticated:
        username = current_user.username
        # Azure Key Vault details
        key_vault_url = f"https://{username}.vault.azure.net/"
        client_id_secret = "client-id"
        client_secret_secret = "client-secret"
        subscription_id_secret = "subscription-id"
        tenant_id_secret = "tenant-id"

        # Retrieve credentials from Azure Key Vault
        credential = DefaultAzureCredential()

        # Create a SecretClient using the Key Vault URL
        secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

        # Retrieve the secrets from Key Vault
        client_id = secret_client.get_secret(client_id_secret).value
        client_secret = secret_client.get_secret(client_secret_secret).value
        subscription_id = secret_client.get_secret(subscription_id_secret).value
        tenant_id = secret_client.get_secret(tenant_id_secret).value

        # Set up the ContainerServiceClient with retrieved credentials
        aks_client = ContainerServiceClient(credential, subscription_id)

        # List AKS clusters in the subscription
        aks_clusters = aks_client.managed_clusters.list()
        healthy_clusters = [cluster.name for cluster in aks_clusters
                            if cluster.provisioning_state.lower() == "succeeded"
                            and cluster.agent_pool_profiles[0].provisioning_state.lower() == "succeeded"]

        # Return the list of healthy AKS clusters as JSON response
        return jsonify({"username": username, "aks_clusters": healthy_clusters}), 200

    else:
        return jsonify({"error": "User not authenticated"}), 401 
    


@app.route('/json-my-cluster-details-gcp', methods=['POST'])
def json_my_cluster_details_gcp():
    if current_user.is_authenticated:
        username = current_user.username
        # Azure Key Vault details for GCP
        key_vault_url_gcp = f"https://{username}.vault.azure.net/"
        gcp_credentials_secret = "your-secret-name"  # Update with your actual secret name

        # Retrieve credentials from Azure Key Vault
        credential_gcp = DefaultAzureCredential()
        secret_client_gcp = SecretClient(vault_url=key_vault_url_gcp, credential=credential_gcp)

        # Retrieve the GCP credentials JSON from Key Vault
        try:
            gcp_credentials_json = secret_client_gcp.get_secret(gcp_credentials_secret).value

            # Parse the JSON string into a dictionary
            gcp_credentials_dict = json.loads(gcp_credentials_json)

            # Use the parsed dictionary to create a service account credentials object
            gcp_credentials = service_account.Credentials.from_service_account_info(gcp_credentials_dict)
        except Exception as e:
            print(f"Error retrieving or parsing GCP credentials: {e}")

        # Use the service account credentials for the discovery build
        service = discovery.build('container', 'v1', credentials=gcp_credentials)
        gcp_projects = ['golden-plateau-401906']

        # List to store GKE clusters data
        clusters_data = []

        for project in gcp_projects:
            request = service.projects().locations().clusters().list(parent=f"projects/{project}/locations/-")
            response = request.execute()

            if 'clusters' in response:
                for cluster in response['clusters']:
                    clusters_data.append({project})
        
        # Return the list of GKE clusters data as a JSON response
        return jsonify({"username": username, "clusters_data": clusters_data}), 200
    else:
        return jsonify({"error": "User not authenticated"}), 401 




@app.route('/my-cluster-details-gcp', methods=['GET', 'POST'])
def my_cluster_details_gcp():
    if current_user.is_authenticated:
        username = current_user.username
        # Azure Key Vault details for GCP
        key_vault_url_gcp = f"https://{username}.vault.azure.net/"
        gcp_credentials_secret = "your-secret-name"  # Update with your actual secret name

        # Retrieve credentials from Azure Key Vault
        credential_gcp = DefaultAzureCredential()
        secret_client_gcp = SecretClient(vault_url=key_vault_url_gcp, credential=credential_gcp)

        # Retrieve the GCP credentials JSON from Key Vault
        try:
            gcp_credentials_json = secret_client_gcp.get_secret(gcp_credentials_secret).value

            # Parse the JSON string into a dictionary
            gcp_credentials_dict = json.loads(gcp_credentials_json)

            # Use the parsed dictionary to create a service account credentials object
            gcp_credentials = service_account.Credentials.from_service_account_info(gcp_credentials_dict)
        except Exception as e:
            print(f"Error retrieving or parsing GCP credentials: {e}")

        # Use the service account credentials for the discovery build
        service = discovery.build('container', 'v1', credentials=gcp_credentials)
        gcp_projects = ['golden-plateau-401906']

        # List to store GKE clusters data
        clusters_data = []

        for project in gcp_projects:
            request = service.projects().locations().clusters().list(parent=f"projects/{project}/locations/-")
            response = request.execute()

            if 'clusters' in response:
                for cluster in response['clusters']:
                    clusters_data.append({project})
        return render_template('my-cluster-details-gcp.html', username=username, clusters_data=clusters_data)
    else:
        return redirect(url_for('login'))


@app.route('/cluster-creation-status', methods=['GET', 'POST'])
def cluster_creation_status():
    if current_user.is_authenticated:
        username = current_user.username
        return render_template('cluster-creation-status.html', username=username)
    else:
        return redirect(url_for('login'))

gitlab_api_url = f'https://gitlab.com/api/v4/projects/{project_id}/jobs'

@app.route('/cluster-details', methods=['GET', 'POST'])
def cluster_details():
    if current_user.is_authenticated:
        try:
            # Fetch the latest job from GitLab
            response = requests.get(gitlab_api_url, headers={'PRIVATE-TOKEN': access_token})
            response.raise_for_status()
            latest_job_id = response.json()[0]['id']

            # Fetch job logs
            logs_url = f'https://gitlab.com/api/v4/projects/{project_id}/jobs/{latest_job_id}/trace'
            logs_response = requests.get(logs_url, headers={'PRIVATE-TOKEN': access_token})
            logs_response.raise_for_status()
            job_logs = logs_response.text

            return render_template('cluster-details.html', username=current_user.username, job_id=latest_job_id, job_logs=job_logs)
        except requests.exceptions.RequestException as e:
            error_message = f"Error fetching data from GitLab: {str(e)}"
            return render_template('cluster-details.html', username=current_user.username, error_message=error_message)
    else:
        return redirect(url_for('login'))



       
@app.route('/cluster-details-azure', methods=['GET', 'POST'])
def cluster_details_azure():
    if current_user.is_authenticated:
        username = current_user.username
        return render_template('cluster-details-azure.html', username=username)
    else:
        return redirect(url_for('login'))

@app.route('/cluster-details-gcp', methods=['GET', 'POST'])
def cluster_details_gcp():
    if current_user.is_authenticated:
        username = current_user.username
        return render_template('cluster-details-gcp.html', username=username)
    else:
        return redirect(url_for('login'))


# showing Job id from gitlab

# GitLab API endpoint for jobs
# gitlab_api_url = f'https://gitlab.com/api/v4/projects/{project_id}/jobs'

# @app.route('/show-job-id', methods=['GET', 'POST'])
# def show_job_id():
#     try:
#         # Fetch the latest job from GitLab
#         response = requests.get(gitlab_api_url, headers={'PRIVATE-TOKEN': access_token})
#         response.raise_for_status()
#         latest_job_id = response.json()[0]['id']
#     except requests.exceptions.RequestException as e:
#         return f"Error fetching data from GitLab: {str(e)}"

#     return render_template('cluster-details.html', job_id=latest_job_id)
 

 
@app.route('/cloud')
def cloud():
    return render_template('cloud.html')


@app.route('/cloud_del')
def cloud_del():
    return render_template('cloud_del.html')


@app.route('/aws_del')
def aws_del():
    return render_template('aws_del.html')


@app.route('/az_del')
def az_del():
    return render_template('az_del.html')


@app.route('/gcp_del')
def gcp_del():
    return render_template('gcp_del.html')

 
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
             key, value = line.strip().split(" = ")
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
         # decoded_bytes = base64.b64decode(key_value)
         # decoded_string = decoded_bytes.decode('utf-8')
          if key_value == Access_key:
                print(f"Key Vault '{vault_name}' has the matching secret: '{key_name}'")
                matching_secret_found = True
                break 
        except Exception as e:
             print(f"Key Vault '{vault_name}' does not contain the secret: '{key_name}'")
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
         #encoded_value = base64.b64encode(value.encode("utf-8")).decode("utf-8")     
         #command = f"az keyvault secret set --vault-name {key_vault_name} --name {key} --value {encoded_value} --output none --query 'value'"
         command = f"az keyvault secret set --vault-name {key_vault_name} --name {key} --value {value} --output none --query 'value'"
 
    
 
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
        #encoded_value = base64.b64encode(value.encode("utf-8")).decode("utf-8")     
        #command = f"az keyvault secret set --vault-name {key_vault_name} --name {key} --value {encoded_value} --output none --query 'value'"
        command = f"az keyvault secret set --vault-name {key_vault_name} --name {key} --value {value} --output none --query 'value'"
 
    
 
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

@app.route('/delete_aks', methods=['POST'])
def delete_aks():
    
    aks_name = request.form.get('aks_name')
    resource_group = request.form.get('resource_group')
    
    with open('file.txt', 'w') as f:
        f.write(f'eks-name = "{aks_name}"\n')
        f.write(f'resource_group = "{resource_group}"\n')
        
    
    file_path = f'azure-delete/file.txt'
    tf_config = f''' 
    aks_name = "{aks_name}"
    resourse_group = "{resource_group}"
    '''
    print("Configuration:", tf_config)
    print("Uploading tf file to gitlab")
    upload_file_to_gitlab(file_path, tf_config, project_id, access_token, gitlab_url, branch_name)
    print("Tf File uploaded successfully")
    return render_template('success.html')

@app.route('/json_delete_aks', methods=['POST'])
def json_delete_aks():
    try:
       aks_name = request.form.get('aks_name')
       resource_group = request.form.get('resource_group')
    
       with open('file.txt', 'w') as f:
         f.write(f'aks-name = "{aks_name}"\n')
         f.write(f'resource_group = "{resource_group}"\n')

       file_path = f'azure-delete/file.txt'
       tf_config = f''' 
       aks_name = "{aks_name}"
       resourse_group = "{resource_group}"
       '''
       print("Configuration:", tf_config)
       print("Uploading tf file to gitlab")
       upload_file_to_gitlab(file_path, tf_config, project_id, access_token, gitlab_url, branch_name)
       print("Tf File uploaded successfully")

       response_data = {'status': 'success', 'message': 'Delete request triggered the pipeline please wait sometime...'}
       return jsonify(response_data),202

    except Exception as e:
        error_message = f"An error occurred: {str(e)}"
        response_data = {'status': 'error', 'message': error_message}
        return jsonify(response_data),404


@app.route('/delete_gke', methods=['POST'])
def delete_gke():
    gke_name = request.form.get('gke_name')
    region = request.form.get('region')
    projecct_id = request.form.get('project_id')
    with open('file.txt', 'w') as f:
        f.write(f'gke-name = "{gke_name}"\n')
        f.write(f'region = "{region}"\n')
        f.write(f'project_id = "{projecct_id}"\n')
    file_path = f'gke-delete/file.txt'
    tf_config = f''' 
    gke_name = "{gke_name}"
    region = "{region}"
    project_id = "{projecct_id}"
    '''
    print("Configuration:", tf_config)
    print("Uploading tf file to gitlab")
    upload_file_to_gitlab(file_path, tf_config, project_id, access_token, gitlab_url, branch_name)
    print("Tf File uploaded successfully")
    return render_template('success.html')

@app.route('/json_delete_gke', methods=['POST'])
def json_delete_gke():
  try:
    gke_name = request.form.get('gke_name')
    region = request.form.get('region')
    project_id = request.form.get('project_id')

    with open('file.txt', 'w') as f:
        f.write(f'gke-name = "{gke_name}"\n')
        f.write(f'region = "{region}"\n')
        f.write(f'project_id = "{project_id}"\n')

    file_path = f'gke-delete/file.txt'
    tf_config = f''' 
    gke_name = "{gke_name}"
    region = "{region}"
    project_id = "{project_id}"
    '''
    print("Configuration:", tf_config)
    print("Uploading tf file to gitlab")
    upload_file_to_gitlab(file_path, tf_config, project_id, access_token, gitlab_url, branch_name)
    print("Tf File uploaded successfully")
    response_data = {'status': 'success', 'message': 'Delete request triggered the pipeline please wait sometime...'}
    return jsonify(response_data),202

  except Exception as e:
        error_message = f"An error occurred: {str(e)}"
        response_data = {'status': 'error', 'message': error_message}
        return jsonify(response_data),404




@app.route('/delete_eks', methods=['POST'])
def delete_eks():
    
    eks_name = request.form.get('eks_name')
    Region = request.form.get('Region')
    Node = request.form.get('ng_name')
    with open('file.txt', 'w') as f:
        f.write(f'eks-name = "{eks_name}"\n')
        f.write(f'region = "{Region}"\n')
        f.write(f'node = "{Node}"\n')
    
    file_path = f'aws-delete/file.txt'
    tf_config = f''' 
    eks_name = "{eks_name}"
    region = "{Region}"
    node = "{Node}"
    '''
    print("Configuration:", tf_config)
    print("Uploading tf file to gitlab")
    upload_file_to_gitlab(file_path, tf_config, project_id, access_token, gitlab_url, branch_name)
    print("Tf File uploaded successfully")
    return render_template('success.html')

@app.route('/json_delete_eks', methods=['POST'])
def json_delete_eks():
    try:
        form = request.get_json()
        eks_name = form['eks_name']
        region = form['region']
        node = form['node']

        with open('file.txt', 'w') as f:
            f.write(f'eks-name = "{eks_name}"\n')
            f.write(f'region = "{region}"\n')
            f.write(f'node = "{node}"\n')

        file_path = 'aws-delete/file.txt'
        tf_config = f''' 
        eks_name = "{eks_name}"
        region = "{region}"
        node = "{node}"
        '''
        print("Configuration:", tf_config)
        print("Uploading tf file to gitlab")
        upload_file_to_gitlab(file_path, tf_config, project_id, access_token, gitlab_url, branch_name)
        print("Tf File uploaded successfully")

        # Return JSON response
        response_data = {'status': 'success', 'message': 'Delete request triggered the pipeline please wait sometime...'}
        return jsonify(response_data),202

    except Exception as e:
        error_message = f"An error occurred: {str(e)}"
        response_data = {'status': 'error', 'message': error_message}
        return jsonify(response_data),404

@app.route('/json_create_aws', methods=['POST'])
def json_create_aws():
    # Retrieve form data
    form = request.get_json()
    eks_name = form['cluster_name']
    Region = form['region']
    instance_type = form['instance_type']
    eks_version = form['eks_version']
    desired_size = form['desired_size']
    max_size = form['max_size']
    min_size = form['min_size']
    cluster_type = form['cluster_type']
    
    # user = Data(username=user_data["user"], cloudname='aws', clustername=user_data["eks_name"])
    # db.session.add(user)
    # db.session.commit()
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
    file_path = f'aws/templates/{file_name}'

    tf_config = f'''
cluster_name = "{eks_name}"
region = "{Region}"
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
    eks_name = request.form.get('cluster_name')
    Region = request.form.get('region')
    instance_type = request.form.get('instance_type')
    eks_version = request.form.get('eks_version')
    desired_size = request.form.get('desired_size')
    max_size = request.form.get('max_size')
    min_size = request.form.get('min_size')
    cluster_type = request.form.get('cluster_type')
    
    eks_version = str(eks_version)
    eks_version = version.parse(eks_version)
 
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
  
    user = Data(username=user_data["user"], cloudname='aws', clustername=eks_name)
    db.session.add(user)
    db.session.commit()
    file_name = f'terraform-{user_data["user"]}.tfvars'
    file_path = f'aws/templates/{file_name}'

    tf_config = f'''
cluster_name = "{eks_name}"
region = "{Region}"
instance_type = "{instance_type}"
eks_version = "{eks_version}"
desired_size = "{desired_size}"
max_size = "{max_size}"
min_size = "{min_size}"
cluster_type = "{cluster_type}"
'''
    print("Configuration:", tf_config)

    # print("Configuration:", tf_config)

    
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
          #  decoded_bytes = base64.b64decode(secret_value)
         #   decoded_string = decoded_bytes.decode('utf-8')
            # print(decoded_string)
            if secret_value == client_secret:
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
            #encoded_value = base64.b64encode(value.encode("utf-8")).decode("utf-8")     
            #command = f"az keyvault secret set --vault-name {key_vault_name} --name {key} --value {encoded_value} --output none --query 'value'"
            command = f"az keyvault secret set --vault-name {key_vault_name} --name {key} --value {value} --output none --query 'value'"
 
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
            #decoded_bytes = base64.b64decode(secret_value)
            #decoded_string = decoded_bytes.decode('utf-8')
            # print(decoded_string)
            if secret_value == client_secret:
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
           # encoded_value = base64.b64encode(value.encode("utf-8")).decode("utf-8")     
            #command = f"az keyvault secret set --vault-name {key_vault_name} --name {key} --value {encoded_value} --output none --query 'value'"
            command = f"az keyvault secret set --vault-name {key_vault_name} --name {key} --value {value} --output none --query 'value'"
 
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
    user = Data(username=user_data["user"], cloudname='azure', clustername=user_data["aks_name"])
    db.session.add(user)
    db.session.commit()
    file_name = f'terraform-{user_data["user"]}.tfvars'
    

    
    aks_version = version.parse(aks_version)
    
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
    file_path = f'azure/template/{file_name}'
    if vm_name is not None:
        # Include vm_name and vm_pass if vm_name is not None
        tf_config = f'''
rg_name = "{resource_group}"
rg_location = "{Region}"
availability_zones = "{availability_zones}"
aks_name = "{aks_name}"
aks_version = "{aks_version}"
node_count = "{node_count}"
private_cluster_enabled = "true"
vm_name = "{vm_name}"
vm_pass = "{vm_pass}"'''
    else:
        tf_config = f'''
rg_name = "{resource_group}"
rg_location = "{Region}"
availability_zones = "{availability_zones}"
aks_name = "{aks_name}"
aks_version = "{aks_version}"
node_count = "{node_count}"
private_cluster_enabled = "false"'''   
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
    file_path = f'azure/template/{file_name}'    

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

    #file_path = f'templates/user-data/{file_name}'

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
            "message": 'pipeline is triggered! aks will be created.. ',
            "statusCode": 200
        })

@app.route('/gcp')
def gcp():
    return render_template('gcp.html')
@app.route('/submit_form_gke', methods=['GET'])
def create_gcp():
    # Retrieve form data
    project = request.form.get('project')
    Region = request.form.get('Region')
    gke_name = request.form.get('gke_name')
    gke_version = request.form.get('gke_version')
    node_count = request.form.get('node_count')
    cluster_type = request.form.get('cluster_type')
    gke_version = str(gke_version)
    gke_version = version.parse(gke_version)
 
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
    user = Data(username=user_data["user"], cloudname='gcp', clustername=gke_name)
    db.session.add(user)
    db.session.commit()
    file_name = f'terraform-{user_data["user"]}.tfvars'
    file_path = f'/gcp/templates/{file_name}'


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
    
    file_content = json_file.read()
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
    secret_name = "your-secret"
    # encoded_value = base64.b64encode(secrets_content.encode("utf-8")).decode("utf-8")     
    # command = f"az keyvault secret set --vault-name {key_vault_name} --name {secret_name} --value '{encoded_value}' --output none --query 'value'"
          # Replace with your desired secret name
    command = f"az keyvault secret set --vault-name {key_vault_name} --name {secret_name} --value '{secrets_content}' --output none --query 'value'"
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

@app.route('/json_submit_form_gke', methods=['POST'])
def json_submit_form_gcp():
    # Check if a file was uploaded
    if 'jsonFile' not in request.files:
        return jsonify({"message": 'No file part'}), 400

    json_file = request.files['jsonFile']

    # Check if the file has a filename
    if json_file.filename == '':
        return jsonify({"message": 'No file selected'}), 400

    # Check if the file is a JSON file
  #  if not json_file.filename.endswith('.json'):
   #     return jsonify({"message": 'Invalid file type. Please upload a JSON file'}), 400

    # Specify the directory where you want to save the JSON file
    save_directory = './'

    # Save the JSON file with its original filename
    file_path = os.path.join(save_directory, json_file.filename)
    json_file.save(file_path)

    User_name = request.form.get('User_name')
    User_Id = str(int(random.random()))

    # Azure Key Vault and Secrets Configuration
    key_vault_name = User_name
    resource_group_name = "rupali-rg"
    location = "westus2"
    secrets_file_path = file_path

    # Create Azure Key Vault if it doesn't exist
    create_kv_command = f"az keyvault create --name {key_vault_name} --resource-group {resource_group_name} --location {location}"
    try:
        subprocess.check_output(create_kv_command, shell=True)
        print(f"Azure Key Vault '{key_vault_name}' created successfully in Resource Group '{resource_group_name}'.")
    except subprocess.CalledProcessError:
        print(f"Error: Failed to create Azure Key Vault.")
        os.remove(file_path)  # Remove the uploaded file if creation of Key Vault fails
        return jsonify({"message": 'Failed to create Azure Key Vault'}), 500

    # Authenticate to Azure
    try:
        access_token = subprocess.check_output(["az", "account", "get-access-token", "--query", "accessToken", "-o", "tsv"]).decode("utf-8").strip()
    except subprocess.CalledProcessError:
        print("Error: Failed to obtain Azure access token. Make sure you are logged into Azure CLI.")
        os.remove(file_path)  # Remove the uploaded file if access token retrieval fails
        return jsonify({"message": 'Failed to obtain Azure access token'}), 500

    # Read the entire content of the JSON file
    with open(secrets_file_path, 'r') as json_file:
        secrets_content = json_file.read()

    # Store the entire JSON content as a secret
    secret_name = "your-secret-name"
    encoded_value = base64.b64encode(secrets_content.encode("utf-8")).decode("utf-8")
    command = f"az keyvault secret set --vault-name {key_vault_name} --name {secret_name} --value {encoded_value} --output none --query 'value'"

    try:
        subprocess.check_call(["bash", "-c", f'AZURE_ACCESS_TOKEN="{access_token}" {command}'])
        print(f"Secret '{secret_name}' has been stored in Azure Key Vault.")
    except subprocess.CalledProcessError as e:
        print(f"Error: Failed to store secret '{secret_name}' in Azure Key Vault. {e}")
        os.remove(file_path)  # Remove the uploaded file if storing secret fails
        return jsonify({"message": 'Failed to store secret in Azure Key Vault'}), 500

    print("Secret has been stored in Azure Key Vault.")
    os.remove(file_path)  # Remove the uploaded file after processing

    return jsonify({"message": 'Credential Successfully added', "statusCode": 200})





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
    user = Data(username=user_data["user"], cloudname='gcp', clustername=gke_name)
    db.session.add(user)
    db.session.commit()
    file_name = f'terraform-{user_data["user"]}.tfvars'
    file_path = f'/gcp/templates/{file_name}'


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
    file_path = f'gcp/template/{file_name}'


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
            "message": 'Pipeline triggered! gke will be created...',
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
 
@app.route("/register", methods=['GET','POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
 
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()

        
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

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
# @app.route("/login", methods=['GET', 'POST'])#
# def login():
#   if current_user.is_authenticated:
#        return redirect(url_for('dashboard'))
#   form = LoginForm()
#   if form.validate_on_submit():
#      user = User.query.filter_by(email=form.email.data).first()
#      if user and bcrypt.check_password_hash(user.password, form.password.data):
#          login_user(user, remember=form.remember.data)
#          next_page = request.args.get('next')
#          flash('Login successful.', 'success')
#          return redirect(next_page) if next_page else redirect(url_for('dashboard'))
#      else:
#             flash('Login Unsuccessful. Please check email and password', 'danger')
#   return render_template('login.html', title='Login', form=form)
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
            
            # Access the username from the user object and use it as needed
            username = user.username
            new_username_record = UsernameTable(username=username)
            db.session.add(new_username_record)
            db.session.commit()
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


@app.route('/eks-output')
def eks_page():
    eks_name = "anuj987"
    region = "US West (N. California)"
    instance_type = "t3.medium"
    eks_version = "1.27"
    desired_size = "2"
    max_size = "2"
    min_size = "2"
    cluster_type = "Private"

    return render_template('eks_page.html', eks_name=eks_name, region=region, instance_type=instance_type,
                           eks_version=eks_version, desired_size=desired_size, max_size=max_size, min_size=min_size,
                           cluster_type=cluster_type)

@app.route('/aks-output')
def aks_page():
    rg_name = "manjari"
    region = "East US"
    availability_zones = "['zone1','zone2']"
    aks_name = "manjari"
    aks_version = "1.24"
    node_count = "1"

    return render_template('aks_page.html', rg_name=rg_name, region=region, availability_zones=availability_zones,
                           aks_name=aks_name, aks_version=aks_version, node_count=node_count)

@app.route('/gke-output')
def gke_page():
    project = "myproject"
    region = "None"
    gke_name = "asdf"
    gke_version = "2.0"
    node_count = "2"
    cluster_type = "Public"
    vm_name = "None"
    vm_pass = "None"

    return render_template('gke_page.html', project=project, region=region, gke_name=gke_name,
                           gke_version=gke_version, node_count=node_count, cluster_type=cluster_type,
                           vm_name=vm_name, vm_pass=vm_pass)






 
 
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
