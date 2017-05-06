#
# Dockerfile to build "Android Analyzer Service" container images
#
FROM ubuntu:16.04

MAINTAINER Markus Gabriel e1326657@student.tuwien.ac.at

# Installing required linux packages
# * tools used in setup
# * python 2 (for app)
# * dependencies for androguard
RUN apt-get update && apt-get install -y \
    wget \
	python-pip \
	openjdk-8-jdk openjdk-8-source libssl-dev libffi-dev libxml2-dev libxslt1-dev libjpeg8-dev zlib1g-dev g++

# Downloading and installing apktool
RUN wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool
RUN wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.2.1.jar
RUN mv apktool_2.2.1.jar apktool.jar
RUN chmod a+x apktool.jar apktool

# Downloading and installing python dependencies of app
RUN pip2 install --upgrade pip && pip2 install \
	androguard \
	celery

# Get python code
ADD . .

# Setting locale, to prevent errors with special characters
RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

ENTRYPOINT celery worker -A src.task.celery -Q static_queue --loglevel=info