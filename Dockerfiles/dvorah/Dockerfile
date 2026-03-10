FROM golang:1.24.5 AS builder

RUN mkdir -p /go/src/github.com/betorvs/dvorah/cmd/dvorah
COPY go.* /go/src/github.com/betorvs/dvorah/
COPY cmd/dvorah/*.go /go/src/github.com/betorvs/dvorah/cmd/dvorah/

RUN mkdir -p /go/src/github.com/betorvs/dvorah/pkg/webhook/admission
RUN mkdir -p /go/src/github.com/betorvs/dvorah/pkg/webhook/cosign
RUN mkdir -p /go/src/github.com/betorvs/dvorah/pkg/webhook/cache
RUN mkdir -p /go/src/github.com/betorvs/dvorah/pkg/webhook/metrics
RUN mkdir -p /go/src/github.com/betorvs/dvorah/pkg/otelutils

COPY pkg/webhook/admission/*.go /go/src/github.com/betorvs/dvorah/pkg/webhook/admission/
COPY pkg/webhook/cosign/*.go /go/src/github.com/betorvs/dvorah/pkg/webhook/cosign/
COPY pkg/webhook/cache/*.go /go/src/github.com/betorvs/dvorah/pkg/webhook/cache/
COPY pkg/webhook/metrics/*.go /go/src/github.com/betorvs/dvorah/pkg/webhook/metrics/
COPY pkg/otelutils/*.go /go/src/github.com/betorvs/dvorah/pkg/otelutils/

WORKDIR /go/src/github.com/betorvs/dvorah

RUN go mod download
RUN go build -o dvorah cmd/dvorah/*

FROM gcr.io/distroless/base-debian12:latest

COPY --from=builder /go/src/github.com/betorvs/dvorah/dvorah /bin/dvorah

USER 65534

ENTRYPOINT ["/bin/dvorah"]