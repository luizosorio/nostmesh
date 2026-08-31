#!/bin/sh
# Generate a node configuration for the multi-host verification.
#
# The verification runs across three real hosts, and the premise that hosts are
# synchronized only through git applies to this file as much as to the code: the
# configuration is generated on each host from arguments rather than copied to
# it.
#
# The identities it names are throwaway, generated for one verification run.
# Anything published to a public relay is permanent and observable, so a node's
# real identity is never used here.
#
# Usage:
#   scripts/lab-config.sh <name> <overlay-cidr> <listen-port> \
#       <peer-nostr-pubkey> <peer-alias> <peer-allowed-cidr> [state-dir]

set -eu

if [ $# -lt 6 ]; then
    echo "usage: $0 <name> <overlay-cidr> <listen-port> <peer-pubkey> <peer-alias> <peer-allowed-cidr> [state-dir]" >&2
    exit 2
fi

name=$1
overlay=$2
port=$3
peer_key=$4
peer_alias=$5
peer_allowed=$6
state_dir=${7:-/tmp/nmstate}

# Public relays and public STUN. Both are third-party infrastructure: the relays
# see only ciphertext addressed to a throwaway identity, and a STUN server's
# answer is treated as an unverified candidate like any other.
cat <<EOF
{
  "node": {
    "name": "${name}",
    "state_dir": "${state_dir}",
    "overlay_address": "${overlay}",
    "listen_port": ${port},
    "mtu": 1420,
    "relays": [
      "wss://nos.lol",
      "wss://relay.damus.io",
      "wss://relay.primal.net"
    ],
    "observers": [
      "stun.l.google.com:19302",
      "stun1.l.google.com:19302"
    ]
  },

  "log": { "level": "info", "format": "text" },

  "policy": {
    "default_action": "deny",
    "accept_default_route": false,
    "max_sessions": 8,
    "authorized_peers": [
      {
        "public_key": "${peer_key}",
        "alias": "${peer_alias}",
        "actions": ["session"],
        "allowed_ips": ["${peer_allowed}"]
      }
    ]
  },

  "peers": []
}
EOF
