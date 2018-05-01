FROM scratch
MAINTAINER Brian Hechinger <wonko@4amlunch.net>

ADD auth-web-linux-amd64 auth-web
VOLUME /etc/chremoas

ENTRYPOINT ["/auth-web", "--configuration_file", "/etc/chremoas/chremoas.yaml"]
