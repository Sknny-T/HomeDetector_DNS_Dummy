FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY web.py .
COPY static ./static

EXPOSE 5000

CMD ["python", "web.py", "--web-host", "0.0.0.0", "--web-port", "5000"]