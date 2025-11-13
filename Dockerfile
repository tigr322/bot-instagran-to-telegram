FROM python:3.11-slim

# Environment hygiene
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# ffmpeg is useful for yt-dlp (even though the code avoids merges)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies first for better caching
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the app
COPY . ./

# Run as non-root
RUN useradd -m -u 10001 appuser && chown -R appuser:appuser /app
USER appuser

# Long polling, no ports to expose
CMD ["python", "bot.py"]
