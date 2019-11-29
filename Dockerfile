FROM golang:1.12 AS builder
WORKDIR /
COPY . /

#FROM alpine:3.8
FROM vault
RUN apk update && apk add --no-cache --update ca-certificates curl jq && update-ca-certificates
COPY --from=builder ./bin/secret-injector /usr/local/bin/secret-injector

ENTRYPOINT ["/bin/sh", "-c", "/usr/local/bin/secret-injector && sleep 20000"]
