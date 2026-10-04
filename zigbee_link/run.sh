#!/bin/sh
set -eu
cd /opt/zigbee-link
exec python3 -m app.main
