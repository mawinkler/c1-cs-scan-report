FROM python:3.7

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

COPY requirements.txt /usr/src/app
RUN pip3 install --no-cache-dir -r requirements.txt

COPY scan-report.py /usr/src/app
COPY config.yml /usr/src/app
COPY smartcheck.png /usr/src/app

ENTRYPOINT [ "python", "./scan-report.py"]
