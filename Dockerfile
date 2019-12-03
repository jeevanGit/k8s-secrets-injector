FROM golang:1.12 AS builder
WORKDIR /
COPY . /

FROM alpine:3.8
RUN apk update && apk add --no-cache --update ca-certificates curl jq && update-ca-certificates
COPY --from=builder ./bin/secret-injector /usr/local/bin/secret-injector
COPY ./test/my-application-script.sh  /my-application-script.sh
COPY config.json /config.json
RUN mkdir -p /etc/secrets

ENTRYPOINT ["/bin/sh", "-c", "/usr/local/bin/secret-injector /my-application-script.sh && sleep 1000"]
#ENTRYPOINT ["/bin/sh"]
