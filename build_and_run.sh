#!/bin/bash
set -e

APP_NAME="security-remediation-system"

if [ -f .env ]; then
  echo "Loading .env file..."
  export $(grep -v '^#' .env | xargs)
fi

if [ -f frontend/.env.local ]; then
  echo "Loading frontend/.env.local file..."
  export $(grep -v '^#' frontend/.env.local | xargs)
fi

if [ -z "$NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY" ]; then
  echo "ERROR: NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY is not set!"
  echo "Please check .env or frontend/.env.local"
  exit 1
else
  echo "Clerk Key found: ${NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY:0:10}..."
fi

echo "docker building $APP_NAME --platform=linux/amd64..."
# Using --load to load the linux/amd64 image into Docker runtime on Mac
docker build \
  --platform=linux/amd64 \
  --build-arg NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=$NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY \
  --build-arg CLERK_SECRET_KEY=$CLERK_SECRET_KEY \
  -t $APP_NAME . 

echo "Starting container on port 8000..."
echo "Access App at http://localhost:8000 (IMPORTANT: Do NOT use 0.0.0.0)"
echo "API at http://localhost:8000/api/v1"
echo "Env: APP_ENV=local_mock (Running with mock queue/storage)"

docker run --rm -it \
  -p 8000:8000 \
  -e APP_ENV=local_mock \
  -e PORT=8000 \
  -e NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY \
  -e CLERK_SECRET_KEY \
  -e OPENAI_API_KEY \
  -e DEEPSEEK_API_KEY \
  $APP_NAME
