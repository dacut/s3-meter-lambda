FROM amazonlinux:latest
VOLUME ["/export"]
RUN yum install -y python35-virtualenv zip
RUN mkdir -p /webapp
RUN virtualenv-3.5 --python=python3 /webapp/venv
ENV VIRTUAL_ENV=/webapp/venv PATH=/webapp/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

COPY requirements.txt /webapp
WORKDIR /webapp
RUN pip install -r requirements.txt

COPY s3meter.py /webapp
RUN zip /lambda.zip s3meter.py
WORKDIR /webapp/venv/lib/python3.5/site-packages
RUN zip -r /lambda.zip .
