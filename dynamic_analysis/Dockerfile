#
# Dockerfile to build "Android Analyzer Service" container images
#
FROM ubuntu:16.04

MAINTAINER Markus Gabriel e1326657@student.tuwien.ac.at

# Installing required linux packages
# * tools used in setup
# * jdk and kvm (hw acceleration) for emulator
RUN apt-get update && apt-get install -y \
    git wget unzip \
    openjdk-8-jdk openjdk-8-doc openjdk-8-source kvm

# Downloading and installing android SDK
# Downloading and installing required platform (API level 24, Android 7)
RUN wget https://dl.google.com/android/repository/tools_r25.2.3-linux.zip
ENV ANDROID_HOME="${pwd}/android-sdk-linux"
RUN mkdir android-sdk-linux
RUN unzip tools_r25.2.3-linux -d ${ANDROID_HOME}
ENV PATH="${PATH}:$ANDROID_HOME/emulator:$ANDROID_HOME/tools/bin:$ANDROID_HOME/tools:$ANDROID_HOME/platform-tools"
RUN yes | sdkmanager "tools" "platform-tools"
RUN yes | sdkmanager "emulator"
RUN yes | sdkmanager "platforms;android-24"
RUN yes | sdkmanager "system-images;android-24;google_apis;x86_64"
RUN yes | sdkmanager "add-ons;addon-google_apis-google-24"

# Installing required linux packages
# * python 2
# * dependencies for androguard and mitmproxy
# * dependencies to display emulator gui
# * rabbitmq for dynamic analysis / emulator parallelization
RUN apt-get update && apt-get install -y \
	python-pip \
	libssl-dev libffi-dev libxml2-dev libxslt1-dev libjpeg8-dev zlib1g-dev g++

# Downloading and installing python dependencies of app
RUN pip2 install --upgrade pip && pip2 install \
    subprocess32  \
	git+https://github.com/MGabr/AndroidViewClient.git \
	celery

# Downloading and installing mitmproxy
RUN pip2 install --upgrade pip && pip2 install mitmproxy==0.18.2

# Create avd required for current server version
RUN echo "no" | avdmanager create avd --name Nexus_5_API_24 --package "system-images;android-24;google_apis;x86_64" --tag google_apis

# Get python code
ADD . .

# Setting locale, to prevent errors with special characters
RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

ENTRYPOINT celery worker -A src.task.celery -Q dynamic_queue --loglevel=info