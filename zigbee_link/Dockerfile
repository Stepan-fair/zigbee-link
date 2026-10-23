FROM ghcr.io/home-assistant/base:3.24-2026.08.0
ARG BUILD_VERSION
ARG BUILD_ARCH
LABEL io.hass.version="${BUILD_VERSION}" io.hass.type="app" io.hass.arch="${BUILD_ARCH}"
RUN apk add --no-cache python3 py3-pip iproute2 nftables \
    && python3 -m pip install --no-cache-dir --target /opt/zigbee-deps paho-mqtt==2.1.0 aiohttp==3.14.5
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/opt/zigbee-deps
WORKDIR /opt/zigbee-link
COPY app ./app
COPY run.sh /run.sh
RUN chmod 0755 /run.sh
ENTRYPOINT []
CMD ["/run.sh"]
