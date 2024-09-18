#!/bin/bash

# Define the Docker image name
IMAGE_NAME="secure-file-app"

# Define the Docker container port and local port mapping
LOCAL_PORT=8501
CONTAINER_PORT=8501

# Delete any existing Docker image with the same name
echo "Deleting existing Docker image (if any)..."
docker rmi -f $IMAGE_NAME

# Delete any existing temporary files or artifacts (if necessary)
echo "Cleaning up old build artifacts..."
rm -f temp_file encrypted_* decrypted_*

# Build the Docker image
echo "Building the Docker image..."
docker build -t $IMAGE_NAME .

# Run the Docker container
echo "Running the Docker container..."
docker run -p $LOCAL_PORT:$CONTAINER_PORT $IMAGE_NAME
