# Use Python 3.11 slim image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    openjdk-17-jre-headless \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Download and install Procyon decompiler
RUN mkdir -p /usr/share/java && \
    wget -O /usr/share/java/procyon-decompiler.jar \
    https://github.com/mstrobel/procyon/releases/download/v0.6.0/procyon-decompiler-0.6.0.jar

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p models temp_decompiled logs

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Expose port
EXPOSE 8000

# Install curl for health checks
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Health check disabled for ECS - using ALB health checks instead
# HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
#     CMD curl -f http://localhost:8000/ || exit 1

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]