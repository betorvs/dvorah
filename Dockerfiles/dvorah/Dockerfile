FROM golang:1.25.8 AS builder

RUN mkdir -p /go/src/github.com/betorvs/dvorah/cmd/dvorah
COPY go.* /go/src/github.com/betorvs/dvorah/
COPY cmd/dvorah/*.go /go/src/github.com/betorvs/dvorah/cmd/dvorah/
COPY cmd/bee/*.go /go/src/github.com/betorvs/dvorah/cmd/bee/

RUN mkdir -p /go/src/github.com/betorvs/dvorah/pkg/webhook/admission
RUN mkdir -p /go/src/github.com/betorvs/dvorah/pkg/webhook/cosign
RUN mkdir -p /go/src/github.com/betorvs/dvorah/pkg/webhook/cache
RUN mkdir -p /go/src/github.com/betorvs/dvorah/pkg/webhook/metrics
RUN mkdir -p /go/src/github.com/betorvs/dvorah/pkg/otelutils
RUN mkdir -p /go/src/github.com/betorvs/dvorah/pkg/config

COPY pkg/webhook/admission/*.go /go/src/github.com/betorvs/dvorah/pkg/webhook/admission/
COPY pkg/webhook/cosign/*.go /go/src/github.com/betorvs/dvorah/pkg/webhook/cosign/
COPY pkg/webhook/cache/*.go /go/src/github.com/betorvs/dvorah/pkg/webhook/cache/
COPY pkg/webhook/metrics/*.go /go/src/github.com/betorvs/dvorah/pkg/webhook/metrics/
COPY pkg/otelutils/*.go /go/src/github.com/betorvs/dvorah/pkg/otelutils/
COPY pkg/config/*.go /go/src/github.com/betorvs/dvorah/pkg/config/

WORKDIR /go/src/github.com/betorvs/dvorah

RUN go mod download
ARG VERSION=dev
RUN go build -ldflags "-X main.Version=${VERSION}" -o dvorah cmd/dvorah/*
RUN go build -ldflags "-X main.Version=${VERSION}" -o bee cmd/bee/*

FROM gcr.io/distroless/base-debian12:latest

COPY --from=builder /go/src/github.com/betorvs/dvorah/dvorah /bin/dvorah
COPY --from=builder /go/src/github.com/betorvs/dvorah/bee /bin/bee

USER 65534

ENTRYPOINT ["/bin/dvorah"]