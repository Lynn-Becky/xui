FROM golang:1.26.5 AS builder
WORKDIR /root
COPY . .
RUN go build -pgo=default.pgo -o x-ui .

FROM alpine:3.23 AS xray
ARG TARGETARCH=amd64
ARG XRAY_VERSION=v26.6.27
RUN apk add --no-cache curl unzip \
    && case "${TARGETARCH}" in \
         amd64) archive="Xray-linux-64.zip" ;; \
         arm64) archive="Xray-linux-arm64-v8a.zip" ;; \
         *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && base="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}" \
    && curl -fL "${base}/${archive}" -o /tmp/xray.zip \
    # Verify against the digest XTLS publishes alongside each asset. Without
    # this the binary that the container runs as root is accepted purely on the
    # strength of the transport, with nothing to compare it against.
    && curl -fL "${base}/${archive}.dgst" -o /tmp/xray.dgst \
    && expected="$(grep -iE '^(SHA2-256|SHA256)=' /tmp/xray.dgst | head -n1 | cut -d= -f2 | tr -d '[:space:]')" \
    && if [ -z "${expected}" ]; then echo "no SHA-256 digest published for ${archive}" >&2; exit 1; fi \
    && actual="$(sha256sum /tmp/xray.zip | cut -d' ' -f1)" \
    && if [ "${expected}" != "${actual}" ]; then \
         echo "xray checksum mismatch: expected ${expected}, got ${actual}" >&2; exit 1; \
       fi \
    && mkdir /out \
    && unzip -j /tmp/xray.zip xray -d /out \
    && mv /out/xray "/out/xray-linux-${TARGETARCH}" \
    && chmod 0755 "/out/xray-linux-${TARGETARCH}"

# Debian 13. Debian 11's LTS ends 2026-08-31, after which ca-certificates, glibc
# and zlib stop receiving security updates; it also predates the builder's glibc.
FROM debian:13-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
WORKDIR /root
COPY --from=builder /root/x-ui /root/x-ui
# Only the data files, not all of bin/: a wider copy pulls in whatever the build
# context happens to hold, including the generated bin/config.json with the
# builder's live inbound secrets. See also .dockerignore.
COPY bin/geoip.dat bin/geosite.dat /root/bin/
COPY --from=xray /out/ /root/bin/
VOLUME [ "/etc/x-ui" ]

# The panel deliberately still runs as root: it supervises the Xray child, which
# commonly binds privileged ports (443/80) for its inbounds, and the documented
# deployment uses --network=host. Dropping to a non-root user here would break
# those installs. The blast radius is reduced instead by the panel writing its
# database and Xray config 0600, and by not shipping a fixed credential — on
# first start it generates a random administrator password and prints it once to
# the container log.
#
# For a tighter deployment, publish the panel port explicitly instead of sharing
# the host network:
#   docker run -d -v $PWD/db:/etc/x-ui -p 127.0.0.1:54321:54321 x-ui
CMD [ "./x-ui" ]
