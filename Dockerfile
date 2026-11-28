# Builds the image from this repository's working tree. Used for local builds as well as Anchore scans in github workflow
# Base images are pinned by digest and kept up to date by Dependabot (see .github/dependabot.yml)

######
## Stage 1: Build application with Go's build tools
######
FROM docker.io/library/golang:1.27.4-alpine3.24@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build

COPY . /app
WORKDIR /app

ARG GOOS=linux
ENV GO111MODULE=on
# A static binary needs no C library at runtime, so the final image carries no glibc shim
ENV CGO_ENABLED=0

# download dependencies
RUN go mod download

# Set build-time variables
RUN go version
RUN go test ./...

# build binaries
RUN go build -ldflags="-X main.buildTimestamp=$(date '+%Y%m%d%H%M%S')" -o threagile cmd/threagile/main.go

# add the -race parameter to go build call in order to instrument with race condition detector: https://blog.golang.org/race-detector
# NOTE: copy files with final name to send to final build

# copy assets
RUN cp /app/demo/example/threagile.yaml /app/demo/example/threagile-example-model.yaml
RUN cp /app/demo/stub/threagile.yaml /app/demo/stub/threagile-stub-model.yaml


######
## Stage 2: Make final small image
######
FROM docker.io/library/alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS finalize

# label used in other scripts to filter
LABEL type="threagile"

# The pinned base image lags behind Alpine's security fixes, so upgrade the packages it ships
RUN apk upgrade --no-cache

# add certificates, graphviz, fonts
RUN apk add --update --no-cache ca-certificates
RUN apk add --update --no-cache graphviz ttf-freefont

# clean apk cache
RUN rm -rf /var/cache/apk/*

# add non-privileged user
WORKDIR /app
RUN adduser --disabled-password --gecos "" --home "$(pwd)" --no-create-home threagile

RUN mkdir -p /app /data
RUN chown -R threagile:threagile /app /data

USER threagile

COPY --from=build --chown=threagile:threagile /app/threagile /app/
COPY --from=build --chown=threagile:threagile /app/LICENSE.txt /app/
COPY --from=build --chown=threagile:threagile /app/report/template/background.pdf /app/
COPY --from=build --chown=threagile:threagile /app/report/threagile-logo.png /app/report/
COPY --from=build --chown=threagile:threagile /app/support/openapi.yaml /app/
COPY --from=build --chown=threagile:threagile /app/support/schema.json /app/
COPY --from=build --chown=threagile:threagile /app/support/live-templates.txt /app/
COPY --from=build --chown=threagile:threagile /app/demo/example/threagile-example-model.yaml /app/
COPY --from=build --chown=threagile:threagile /app/demo/stub/threagile-stub-model.yaml /app/
COPY --from=build --chown=threagile:threagile /app/server /app/server

ENV PATH=/app:$PATH
ENV GIN_MODE=release

ENTRYPOINT ["/app/threagile"]
CMD ["help"]
