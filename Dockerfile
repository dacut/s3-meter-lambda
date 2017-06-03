FROM amazonlinux:latest
VOLUME ["/export"]
RUN yum install -y binutils gcc python35-virtualenv zip
RUN mkdir -p /webapp
RUN virtualenv-3.5 --python=python3 /webapp/venv
ENV VIRTUAL_ENV=/webapp/venv
ENV PATH=/webapp/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV LANG=en_US.UTF-8
WORKDIR /webapp
RUN pip install boto3
RUN pip install redis
RUN pip install flask
RUN pip install meterer
RUN pip install zappa
RUN rm -rf /webapp/venv/lib/python3.5/site-packages/concurrent
RUN rm -rf /webapp/venv/lib/python3.5/site-packages/concurrent-*.dist-info

COPY s3meter.py /webapp
COPY zappa_settings.json /webapp
COPY static /webapp/static
COPY templates /webapp/templates
ENV AWS_ACCESS_KEY_ID=ignored
ENV AWS_SECRET_ACCESS_KEY=ignored
RUN zappa package
RUN mv s3meter-prod-*.zip /lambda.zip
