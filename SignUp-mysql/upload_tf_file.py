import gitlab

def upload_file_to_gitlab(file_path, tf_config, project_id, access_token, gitlab_url, branch_name):
    try:
        gl = gitlab.Gitlab(gitlab_url, private_token=access_token)
        project = gl.projects.get(project_id)

        # Check if the file exists
        existing_file = None
        try:
            existing_file = project.files.get(file_path, ref=branch_name)
            print(f"Existing file: {existing_file}")
        except gitlab.exceptions.GitlabGetError as e:
            if e.response_code != 404:  # Any error other than file not found
                return f'Failed to check if file exists: {str(e)}'
                

        # If the file doesn't exist, create a new one
        if existing_file is None:
            project.files.create(
                {
                    "file_path": file_path,
                    "branch": branch_name,
                    "content": tf_config,
                    "commit_message": f"Added tf",
                }
            )
            return f'New Terraform configuration with the user is created and pushed to GitLab successfully.'
        else:
            # Update the existing content with the new data
            existing_content = existing_file.decode().decode("utf-8")
            new_content = tf_config
            existing_file.content = new_content
            existing_file.save(branch=branch_name, commit_message=f"Update var.tf")
            return f'Terraform configuration for the user already exists, and the data is updated and pushed to GitLab successfully.'

    except Exception as e:
        raise e
        # return f"Failed to create/update Terraform configuration in GitLab: {str(e)}"
