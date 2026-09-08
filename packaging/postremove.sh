#!/bin/sh
# Forget the unit; keep everything an operator would miss.
#
# The state directory holds this node's private key and its network journal, and
# the configuration is the operator's own work. Neither is removed: a package
# that deleted a node's identity on uninstall would make reinstalling it a
# different node, and the journal is what reconciliation reads to clean up
# interfaces a crash left behind.
#
# The service account stays for the same reason — it owns those files.
set -e

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
