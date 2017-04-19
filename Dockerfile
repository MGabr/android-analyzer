#
# Dockerfile to build "Android Analyzer Service" container images
#
FROM ubuntu:16.04

MAINTAINER Markus Gabriel e1326657@student.tuwien.ac.at

# Setting locale, to prevent errors with special characters
RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

# Installing required linux packages
# * jdk and kvm (acceleration) for emulator
# * dependencies for androguard and mitmproxy
RUN dpkg --add-architecture i386
RUN apt-get update && apt-get install -y \
	git wget unzip python-pip \
	openjdk-8-jdk openjdk-8-doc openjdk-8-source \
	kvm \
	libssl-dev libffi-dev libxml2-dev libxslt1-dev libjpeg8-dev zlib1g-dev g++

# Downloading and installing apktool
RUN wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool
RUN wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.2.1.jar
RUN mv apktool_2.2.1.jar apktool.jar
RUN chmod a+x apktool.jar apktool

# Downloading and installing python dependencies
RUN pip install --upgrade pip && pip install \
	mitmproxy==0.18.2 \
	androguard \
	flask Flask-Uploads Flask-Session Flask-Sqlalchemy subprocess32 Flask-login bcrypt\
	Flask-Testing \
	git+https://github.com/MGabr/AndroidViewClient.git

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

# Create avd required for current server version
RUN echo "no" | avdmanager create avd --name Nexus_5_API_24 --package "system-images;android-24;google_apis;x86_64" --tag google_apis

# Setting up ssh key for gitlab private repository cloning
# Make sure a key accepted by gitlab.sba-research.org is in the current directory and named id_rsa!"
RUN mkdir /root/.ssh/
COPY id_rsa /root/.ssh/id_rsa
RUN touch /root/.ssh/known_hosts
RUN ssh-keyscan -p 3022 gitlab.sba-research.org >> /root/.ssh/known_hosts

# Downloading android-analyzer sources
RUN git clone ssh://git@gitlab.sba-research.org:3022/theses/android-analyzer.git

# Android analyzer app
EXPOSE 4008
WORKDIR android-analyzer
ENTRYPOINT ["python", "-m"]
CMD ["src.android_analyzer"]

# TODO: Deployment with uwsgi
#ENTRYPOINT ["uwsgi", "--http", "127.0.0.1:4008", "--module", "src.android_analyzer", "--processes", "1", "--threads", "8"]



