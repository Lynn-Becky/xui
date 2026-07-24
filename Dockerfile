FROM golang:1.26.5 AS builder
WORKDIR /root
COPY . .
RUN go build -pgo=default.pgo -o x-ui .

FROM alpine:3.22 AS xray
ARG TARGETARCH=amd64
ARG XRAY_VERSION=v26.6.27
RUN apk add --no-cache curl unzip \
    && case "${TARGETARCH}" in \
         amd64) archive="Xray-linux-64.zip" ;; \
         arm64) archive="Xray-linux-arm64-v8a.zip" ;; \
         *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && curl -fL "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/${archive}" -o /tmp/xray.zip \
    && mkdir /out \
    && unzip -j /tmp/xray.zip xray -d /out \
    && mv /out/xray "/out/xray-linux-${TARGETARCH}"

FROM debian:11-slim
RUN apt-get update && apt-get install -y --no-install-recommends -y ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
WORKDIR /root
COPY --from=builder /root/x-ui /root/x-ui
COPY bin/. /root/bin/.
COPY --from=xray /out/ /root/bin/
VOLUME [ "/etc/x-ui" ]
CMD [ "./x-ui" ]
