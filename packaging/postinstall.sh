#!/bin/sh
# Register the unit without starting it.
#
# A node with no configuration cannot serve, so enabling the service here would
# guarantee a failed start on every fresh install. The operator writes a
# configuration and then enables it.
set -e

chown root:nostmesh /etc/nostmesh 2>/dev/null || true

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true

    # On an upgrade the service may be running an older binary. Restarting it is
    # the operator's decision, not the package's: a mesh node dropping its
    # tunnels is a visible event, and doing it silently during an unattended
    # upgrade is worse than running the previous version a while longer.
    if systemctl is-active --quiet nostmesh 2>/dev/null; then
        echo "nostmesh is running the previous binary; restart it when convenient:"
        echo "  systemctl restart nostmesh"
    fi
fi

if [ ! -f /etc/nostmesh/nostmesh.json ]; then
    echo "NostMesh installed. To start a node:"
    echo "  cp /etc/nostmesh/nostmesh.json.example /etc/nostmesh/nostmesh.json"
    echo "  \$EDITOR /etc/nostmesh/nostmesh.json"
    echo "  nostmesh identity init --state-dir /var/lib/nostmesh"
    echo "  systemctl enable --now nostmesh"
    echo
    echo "The wireguard module must be loaded before the service starts:"
    echo "  echo wireguard > /etc/modules-load.d/wireguard.conf"
fi
