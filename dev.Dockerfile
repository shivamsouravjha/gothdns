FROM golang:1.23-alpine3.20

RUN apk update &&  \
    apk add --no-cache make build-base bind-tools

WORKDIR /app

ENV CGO_ENABLED=1

CMD ["sleep", "infinity"]