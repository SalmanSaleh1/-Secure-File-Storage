# Use the official Python image from the Docker Hub
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install the Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the Streamlit application into the container
COPY app/ .

# Expose the port the app will run on
EXPOSE 8501

# Command to run the Streamlit app
CMD ["streamlit", "run", "secure_file_streamlit.py"]