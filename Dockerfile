# Start by pulling the python image
FROM python:latest

# Copy the requirements file into the image
RUN mkdir -p /PVT

# Switch working directory
WORKDIR /PVT
COPY . /PVT

# Install the dependencies and packages in the requirements file
RUN pip install --upgrade pip && pip install -r requirements.txt

# Expose the port
EXPOSE 8443

# Configure the container to run in an executed manner
ENTRYPOINT [ "python" ]

# Run redeye
CMD ["pvt.py", "--web", "--port", "8443"]
