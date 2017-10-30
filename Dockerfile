FROM arm32v6/alpine
LABEL maintainer="maurer.it@gmail.com"

RUN apk update && apk upgrade && apk add ca-certificates

ADD ./auth-web /
WORKDIR /

RUN rm -rf /var/cache/apk/*

ENV MICRO_REGISTRY_ADDRESS chremoas-consul:8500

CMD [""]
ENTRYPOINT ["./auth-web"]
