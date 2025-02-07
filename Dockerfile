FROM golang:1.23-alpine3.20 as compilation

COPY ./ /opt/polardns
RUN cd /opt/polardns  \
    && go mod vendor -v \
    && go build -o /opt/polardns/polardns

FROM alpine:3.21

COPY --from=compilation /opt/polardns/polardns /opt/polardns

CMD /opt/polardns