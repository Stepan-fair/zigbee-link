FROM ghcr.io/home-assistant/base:2026.08.0
ARG BUILD_VERSION
ARG BUILD_ARCH
LABEL io.hass.version="${BUILD_VERSION}" io.hass.type="app" io.hass.arch="${BUILD_ARCH}"
RUN apk add --no-cache python3 iproute2
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /opt/zigbee-link
COPY app ./app
COPY run.sh /run.sh
RUN chmod 0755 /run.sh
ENTRYPOINT []
CMD ["/run.sh"]
