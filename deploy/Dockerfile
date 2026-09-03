# Multi-stage build: Node builds the SPA, Go embeds it and compiles a static
# binary, and the runtime image carries neither toolchain.
#
# The result is one artifact with no runtime dependencies, which is what makes the
# deployment story "copy a binary or run one container" rather than "install a
# runtime, a package manager, and a web server".

# --------------------------------------------------------------- frontend ----
FROM node:22-alpine AS frontend

# vite.config.ts writes its build to ../backend/internal/web/dist, a path relative
# to the frontend directory, so this stage mirrors the repo layout rather than
# flattening it. Build somewhere else and the output lands outside the stage's
# working tree with nothing for the backend stage to copy.
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json* ./
# `npm ci` when a lockfile exists so builds are reproducible; fall back to
# `install` so a fresh checkout without one still builds.
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

COPY frontend/ ./
# No `|| true` here: a swallowed build failure turns into a confusing "not found"
# on the COPY in the next stage instead of the actual compiler error.
RUN npm run build

# ---------------------------------------------------------------- backend ----
FROM golang:1.23-alpine AS backend

# git is needed only so the build can stamp a VCS revision when one is present.
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src

# Dependencies first: this layer is cached unless go.mod or go.sum changes, which
# is most of the build time on a code-only edit.
COPY backend/go.mod backend/go.sum* ./

COPY backend/ ./

RUN go mod tidy && go mod download
# .dockerignore keeps the committed placeholder dist/ out of the build context, so
# this COPY is what satisfies the `//go:embed all:dist` directive -- without it the
# backend does not compile at all.
COPY --from=frontend /src/backend/internal/web/dist ./internal/web/dist

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

# CGO_ENABLED=0 with the pure-Go SQLite driver gives a genuinely static binary, so
# the runtime image needs no libc at all.
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath \
      -ldflags "-s -w \
        -X github.com/axt-term/axt-term/backend/internal/buildinfo.Version=${VERSION} \
        -X github.com/axt-term/axt-term/backend/internal/buildinfo.Commit=${COMMIT} \
        -X github.com/axt-term/axt-term/backend/internal/buildinfo.Date=${BUILD_DATE}" \
      -o /out/axt-term ./cmd/axt-term \
 && go build -trimpath -ldflags "-s -w" -o /out/axt-admin ./cmd/axt-admin

# ---------------------------------------------------------------- runtime ----
FROM alpine:3.21

# ca-certificates for any operator-configured outbound integration; tzdata so
# audit timestamps render in the operator's zone. Nothing else is installed:
# there is no shell tooling for an attacker to reach through the application.
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -g 10001 -S axt \
 && adduser -u 10001 -S -G axt -h /var/lib/axt-term axt

COPY --from=backend /out/axt-term /usr/local/bin/axt-term
COPY --from=backend /out/axt-admin /usr/local/bin/axt-admin

# The data directory holds the database with encrypted credentials and the session
# recordings, so it is owned by the service user and not world-readable.
RUN mkdir -p /var/lib/axt-term/recordings \
 && chown -R axt:axt /var/lib/axt-term \
 && chmod 750 /var/lib/axt-term \
 && chmod 700 /var/lib/axt-term/recordings

USER axt:axt
WORKDIR /var/lib/axt-term
VOLUME ["/var/lib/axt-term"]

ENV AXT_HTTP_ADDR=:8080 \
    AXT_DATA_DIR=/var/lib/axt-term \
    AXT_LOG_FORMAT=json

EXPOSE 8080

# busybox wget is already present in alpine, so the healthcheck needs no extra
# package and no flag on the binary.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -q -O- http://127.0.0.1:8080/healthz >/dev/null || exit 1

# The server handles SIGTERM itself and shuts down in a defined order, so no init
# wrapper is needed.
ENTRYPOINT ["/usr/local/bin/axt-term"]
