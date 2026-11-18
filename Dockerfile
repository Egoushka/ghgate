# syntax=docker/dockerfile:1
# A static binary on distroless: no shell, no package manager. Secrets arrive as environment variables.
# golang:1.27 (go.mod says 1.27) and distroless static-debian12:nonroot, both pinned by index digest.
FROM --platform=$BUILDPLATFORM golang:1.27@sha256:205c7636d74e0ffbe3d007162df7d74f859f5a8c8322dfb9f907977686c126cf AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w" -o /out/ghgate ./cmd/ghgate
# The image has no shell, so the state directory is made here and handed to uid 65532 (nonroot).
RUN mkdir -m 0700 /state

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/ghgate /ghgate
COPY --from=build --chown=65532:65532 /state /state
USER 65532:65532
EXPOSE 8899 8898
ENTRYPOINT ["/ghgate"]
CMD ["serve", "--config", "/etc/ghgate/ghgate.json"]
