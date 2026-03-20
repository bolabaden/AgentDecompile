#!/bin/sh
CONF=/home/user/.config/containers/containers.conf
grep -q 'dns_servers' "$CONF" 2>/dev/null || sed -i '/^\[containers\]$/a dns_servers = ["1.1.1.1", "8.8.8.8"]' "$CONF"
cat "$CONF"
