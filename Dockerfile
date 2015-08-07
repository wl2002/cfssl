FROM golang:1.4.2

WORKDIR /go/src/github.com/cloudflare/cfssl

ENV GOPATH /go/src/github.com/cloudflare/cfssl:/go
ENV USER root

RUN go get github.com/cloudflare/cf-tls/tls
RUN go get github.com/cloudflare/go-metrics
RUN go get github.com/cloudflare/redoctober/core
RUN go get github.com/dgryski/go-rc2
RUN go get golang.org/x/crypto/ocsp
RUN go get github.com/GeertJohan/go.rice

ADD . /go/src/github.com/cloudflare/cfssl

RUN go build -tags nopkcs11 ./cmd/cfssl/...

RUN git clone https://github.com/cloudflare/cfssl_trust.git /etc/cfssl

EXPOSE 80
CMD ["./cfssl", "serve", "-address=0.0.0.0", "-port=80"]