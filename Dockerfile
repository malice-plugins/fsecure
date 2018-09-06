####################################################
# GOLANG BUILDER
####################################################
FROM golang:1.11 as go_builder

COPY . /go/src/github.com/malice-plugins/fsecure
WORKDIR /go/src/github.com/malice-plugins/fsecure
RUN go get -u github.com/golang/dep/cmd/dep && dep ensure
RUN go build -ldflags "-s -w -X main.Version=v$(cat VERSION) -X main.BuildTime=$(date -u +%Y%m%d)" -o /bin/avscan

####################################################
# PLUGIN BUILDER
####################################################
FROM ubuntu:bionic

LABEL maintainer "https://github.com/blacktop"

LABEL malice.plugin.repository = "https://github.com/malice-plugins/fsecure.git"
LABEL malice.plugin.category="av"
LABEL malice.plugin.mime="*"
LABEL malice.plugin.docker.engine="*"

# Create a malice user and group first so the IDs get set the same way, even as
# the rest of this may change over time.
RUN groupadd -r malice \
  && useradd --no-log-init -r -g malice malice \
  && mkdir /malware \
  && chown -R malice:malice /malware

ENV FSECURE_VERSION 11.10.68

# Install Requirements
RUN buildDeps='wget rpm ca-certificates' \
  && apt-get update -qq \
  && apt-get install -yq $buildDeps lib32stdc++6 psmisc \
  && echo "===> Install F-Secure..." \
  && cd /tmp \
  && wget -q https://download.f-secure.com/corpro/ls/trial/fsls-${FSECURE_VERSION}-rtm.tar.gz \
  && tar zxvf fsls-${FSECURE_VERSION}-rtm.tar.gz \
  && cd fsls-${FSECURE_VERSION}-rtm \
  && chmod a+x fsls-${FSECURE_VERSION} \
  && ./fsls-${FSECURE_VERSION} --auto standalone lang=en --command-line-only \
  && fsav --version \
  && echo "===> Update F-Secure..." \
  && cd /tmp \
  && wget -q http://download.f-secure.com/latest/fsdbupdate9.run \
  && mv fsdbupdate9.run /opt/f-secure/ \
  && echo "===> Clean up unnecessary files..." \
  && apt-get purge -y --auto-remove $buildDeps && apt-get clean \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /root/.gnupg

# Ensure ca-certificates is installed for elasticsearch to use https
RUN apt-get update -qq && apt-get install -yq --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Update F-Secure
RUN echo "===> Update F-Secure Database..." \
  && mkdir -p /opt/malice \
  && /etc/init.d/fsaua start \
  && /etc/init.d/fsupdate start \
  && /opt/f-secure/fsav/bin/dbupdate /opt/f-secure/fsdbupdate9.run; exit 0

# Add EICAR Test Virus File to malware folder
ADD http://www.eicar.org/download/eicar.com.txt /malware/EICAR

COPY update.sh /opt/malice/update
COPY --from=go_builder /bin/avscan /bin/avscan

WORKDIR /malware

ENTRYPOINT ["/bin/avscan"]
CMD ["--help"]

####################################################
# https://download.f-secure.com/corpro/ls/trial/fsls-11.10.68-rtm.tar.gz
