#!/bin/sh
# Stop the service before its binary goes.
#
# Only on removal, never on an upgrade: rpm runs this with an argument of 1 when
# a newer version is replacing this one, and stopping there would drop every
# tunnel on a package update.
set -e

if [ -d /run/systemd/system ] && [ "${1:-0}" != "1" ] && [ "${1:-}" != "upgrade" ]; then
    systemctl stop nostmesh >/dev/null 2>&1 || true
    systemctl disable nostmesh >/dev/null 2>&1 || true
fi
