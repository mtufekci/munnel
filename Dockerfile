# Multi-stage build for the munnel tunnel server.
# The client is meant to run on developer machines; the server goes on a VPS.
FROM golang:1.25-alpine AS build
ARG VERSION=dev
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/munnel-server ./cmd/server

FROM scratch
COPY --from=build /out/munnel-server /munnel-server
# Control plane (clients connect here: 7001 plaintext, 7002 TLS) and public
# HTTP ingress.
EXPOSE 7001 7002 8080
ENTRYPOINT ["/munnel-server"]
