FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY tests/ ./tests
COPY configs/ ./configs
CMD ["pytest", "-m", "sil", "--junitxml=/results/results.xml"]
