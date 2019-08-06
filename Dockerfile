FROM scratch
MAINTAINER Brian Hechinger <wonko@4amlunch.net>

ADD auth-web-linux-amd64 auth-web
ADD ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
VOLUME /etc/chremoas

ENTRYPOINT ["/auth-web"]
