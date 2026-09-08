#!/bin/sh
# Create the service account before any file is installed.
#
# The unit runs as User=nostmesh, and a unit whose user does not exist fails
# with status=217/USER — which reports a permission problem rather than a
# missing account, and is what a field test hit.
set -e

if ! getent group nostmesh >/dev/null 2>&1; then
    groupadd --system nostmesh
fi

if ! getent passwd nostmesh >/dev/null 2>&1; then
    useradd --system \
        --gid nostmesh \
        --no-create-home \
        --home-dir /var/lib/nostmesh \
        --shell /usr/sbin/nologin \
        --comment "NostMesh overlay network node" \
        nostmesh
fi
