FROM python:3.11-slim
RUN pip install asyncua --no-cache-dir
WORKDIR /opcua
COPY server.py /opcua/server.py
EXPOSE 4840
CMD ["python3", "/opcua/server.py"]
