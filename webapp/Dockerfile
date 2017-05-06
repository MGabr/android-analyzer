#
# Dockerfile to build "Android Analyzer Service" container images
#
FROM ubuntu:16.04

MAINTAINER Markus Gabriel e1326657@student.tuwien.ac.at

# Installing required linux packages
# * tools used in setup
# * python 2 (for app)
RUN apt-get update && apt-get install -y \
    git wget unzip \
    python-pip

# Downloading and installing python dependencies of app
RUN pip2 install --upgrade pip && pip2 install \
	flask Flask-Uploads Flask-Session Flask-Sqlalchemy subprocess32 enum34 Flask-login bcrypt\
	Flask-Testing \
	celery

ADD . .

# Setting locale, to prevent errors with special characters
RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

# Android analyzer app
EXPOSE 4008
ENTRYPOINT ["python2", "-m"]
CMD ["src.android_analyzer"]

# TODO: Deployment with uwsgi
# ENTRYPOINT ["uwsgi", "--http", "127.0.0.1:4008", "--module", "src.android_analyzer", "--processes", "1", "--threads", "8"]

