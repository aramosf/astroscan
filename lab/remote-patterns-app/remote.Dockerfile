FROM python:3.12-slim
COPY remote_server.py /remote_server.py
CMD ["python", "/remote_server.py"]
