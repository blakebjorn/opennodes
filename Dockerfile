# Base Image - can't use python:alpine-3.7 because MSSQL drivers don't support alpine linux
FROM python:3.9-alpine
ENV PYTHONUNBUFFERED=1

RUN apk --no-cache add g++ postgresql-dev

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir python-dotenv

COPY . .
CMD ['python', 'daemon.py']
