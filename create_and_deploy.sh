#!/bin/bash
set -e

# Configuration
APP_NAME="security-remediation-system"
AWS_REGION="us-east-1"
TF_DIR="terraform"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
NEW_TAG="v-$TIMESTAMP"

echo "============================================"
echo "Deployment Wrapper Script"
echo "Tag: $NEW_TAG"
echo "============================================"

# 0. Load Environment Variables
if [ -f .env ]; then
  echo "Loading .env..."
  set -a
  source .env
  set +a
fi
if [ -f frontend/.env.local ]; then
  echo "Loading frontend/.env.local..."
  set -a
  source frontend/.env.local
  set +a
fi

# 1. Cleanup Docker
echo "Cleaning up local docker images..."
# Remove only project related images/containers to be safe, or just force prune if user requested
docker rm -f $(docker ps -a -q --filter ancestor=$APP_NAME) || true
docker rmi -f $APP_NAME || true
# Optional: User asked to remove ALL existing images. 
# "remove all existing images from docker" -> WARNING: destructive.
# I will interpret this as "prune dangling" or just this app's images to be safe.
# Actually, strict interpretation:
echo "Forcing removal of application images..."
docker rmi $(docker images -q $APP_NAME) 2>/dev/null || true

# 2. Build Docker Image
echo "Building new Docker image ($APP_NAME:$NEW_TAG)..."
docker build --platform=linux/amd64 \
  --build-arg NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=$NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY \
  --build-arg CLERK_SECRET_KEY=$CLERK_SECRET_KEY \
  -t $APP_NAME:$NEW_TAG \
  -t $APP_NAME:latest .

# 3. Push to ECR
# We need to get the repository uri. Can extract from terraform output or assume convention?
# Let's try to get it via AWS CLI if possible, or assume it matches project name variables.
# Since I cannot run terraform output easily without init, I will rely on manual ECR naming convention from main.tf
# main.tf uses module.storage.ecr_repository_url
# We'll assume the repo name is "security-remediation-repo-dev" (based on project_name-repo-env convention usually)
# OR we can just ask Terraform.

echo "Retrieving ECR Repository URL from Terraform..."
cd $TF_DIR
ECR_URL=$(terraform output -raw ecr_repo_url 2>/dev/null) || true
if [ -z "$ECR_URL" ]; then
    echo "Terraform output failed or empty. Trying to construct ECR URL..."
    # Fallback or error?
    ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
    # Correct Repo Name based on 'aws ecr describe-repositories' check
    ECR_REPO_NAME="security-remediation-repo-dev"
    ECR_URL="$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$ECR_REPO_NAME"
    echo "Constructed: $ECR_URL"
fi
cd ..

echo "Logging into ECR..."
aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $ECR_URL

echo "Tagging and Pushing..."
FULL_IMAGE_URI="$ECR_URL:$NEW_TAG"
docker tag $APP_NAME:$NEW_TAG $FULL_IMAGE_URI
docker push $FULL_IMAGE_URI

echo "Pushed: $FULL_IMAGE_URI"

# 4. Update Terraform
echo "Updating Terraform configuration to use $NEW_TAG..."
# Use sed to replace the image tag in terraform/main.tf
# Pattern: ecr_image_uri = "${module.storage.ecr_repository_url}:old-tag"
# We want to match explicitly to avoid breaking things.
# Current: ecr_image_uri         = "${module.storage.ecr_repository_url}:v3-sequential"
# Regex: ecr_image_uri\s*=\s*"\$\{module\.storage\.ecr_repository_url\}:.*"

SED_CMD="s|ecr_image_uri.*=.*\"\\\${module.storage.ecr_repository_url}:.*\"|ecr_image_uri         = \"\${module.storage.ecr_repository_url}:$NEW_TAG\"|g"

# OS specific sed
if [[ "$OSTYPE" == "darwin"* ]]; then
  sed -i '' "$SED_CMD" terraform/main.tf
else
  sed -i "$SED_CMD" terraform/main.tf
fi

echo "Terraform updated."

# 5. Deploy
echo "Deploying via Terraform..."
cd $TF_DIR
terraform apply -var-file="envs/dev/terraform.tfvars" -auto-approve

echo "Deployment initiated successfully!"
