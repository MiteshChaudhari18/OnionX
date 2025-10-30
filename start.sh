#!/usr/bin/env bash
set -euo pipefail

# Generate minimal torrc that listens on localhost
cat > /etc/tor/torrc <<'EOF'
SocksPort 127.0.0.1:9050
ControlPort 127.0.0.1:9051
CookieAuthentication 0
Log notice stdout
EOF

# Start Tor in background
/usr/bin/tor -f /etc/tor/torrc &

# Wait for Tor SOCKS to be ready
for i in {1..30}; do
  if nc -z 127.0.0.1 9050 2>/dev/null; then
    echo "Tor SOCKS is up"
    break
  fi
  echo "Waiting for Tor... ($i)"
  sleep 1
done

# Launch Streamlit app
exec streamlit run app.py --server.port ${PORT:-5000} --server.address 0.0.0.0
