# syntax=docker/dockerfile:1.7
#
# This Dockerfile is consumed by GoReleaser. The binary is built outside
# the Docker context (by goreleaser's Go cross-compile) and placed in the
# build context as ./oidcgate before `docker buildx build` runs.
#
# To build locally without goreleaser:
#   go build -o oidcgate ./cmd/oidcgate
#   docker build -f cmd/oidcgate/Dockerfile -t oidcgate:dev .
FROM gcr.io/distroless/static-debian12:nonroot

ARG TARGETOS
ARG TARGETARCH

LABEL org.opencontainers.image.title="oidcgate"
LABEL org.opencontainers.image.description="Standalone OIDC forward-auth daemon for nginx/Caddy/Traefik/HAProxy/Envoy"
LABEL org.opencontainers.image.source="https://github.com/lukaszraczylo/traefikoidc"
LABEL org.opencontainers.image.documentation="https://github.com/lukaszraczylo/traefikoidc/blob/main/docs/OIDCGATE.md"
LABEL org.opencontainers.image.licenses="MIT"

COPY oidcgate /usr/local/bin/oidcgate

EXPOSE 8080

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/oidcgate"]
CMD ["--config", "/etc/oidcgate/config.yaml"]
