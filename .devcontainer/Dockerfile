################################################################################
# LIGHTKEEPER                                                                  #
################################################################################
FROM ubuntu:20.04 AS lightkeeper
ARG http_proxy
ARG https_proxy

ENV http_proxy=$http_proxy
ENV https_proxy=$https_proxy

ENV DEBIAN_FRONTEND="noninteractive"

RUN apt-get update && \
    apt-get install -y \
    openjdk-17-jdk \
    wget \
    unzip \
    curl \
    git

# GHIDRA
ENV GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.1.1_build/ghidra_11.1.1_PUBLIC_20240614.zip
ENV GHIDRA_ZIP=ghidra_11.1.1_PUBLIC_20240614.zip
ENV GHIDRA_DIR=ghidra_11.1.1_PUBLIC
RUN wget $GHIDRA_URL
RUN unzip -d /opt $GHIDRA_ZIP

# GRADLE
ENV GRADLE_URL=https://services.gradle.org/distributions/gradle-8.11.1-bin.zip
ENV GRADLE_ZIP=gradle-8.11.1-bin.zip
RUN wget $GRADLE_URL
RUN unzip -d /opt/gradle $GRADLE_ZIP
ENV PATH=$PATH:/opt/gradle/gradle-8.11.1/bin

# VSCODE
ARG VSCODE_COMMIT_ID
ENV VSCODE_COMMIT_ID=$VSCODE_COMMIT_ID
WORKDIR /root/.vscode-server/bin
RUN curl -sL https://update.code.visualstudio.com/commit:${VSCODE_COMMIT_ID}/server-linux-x64/stable -o stable
RUN tar xf stable
RUN mv vscode-server-linux-x64 ${VSCODE_COMMIT_ID}
