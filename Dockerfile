# syntax=docker/dockerfile:1

FROM golang:1.24-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/USERNAME/mancar/internal/version.Version=${VERSION}" \
      -o /out/mancard ./cmd/mancard

# distroless/static: no shell, no package manager, runs as an unprivileged user.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/mancard /mancard
USER nonroot:nonroot
EXPOSE 8080
# The image has no curl; the binary checks itself.
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 CMD ["/mancard", "healthcheck"]
ENTRYPOINT ["/mancard"]
CMD ["serve"]
