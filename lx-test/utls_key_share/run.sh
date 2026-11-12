#!/usr/bin/env bash
# SPEC 156: tls.utls.key_share against a live Xray TLS inbound, TCP and XHTTP.
#
# Xray: two VLESS inbounds with security tls and a self-signed certificate —
# raw TCP and XHTTP (alpn h2). A relay in front of each prints the size of the
# first TLS record. Client: uTLS chrome_155, key_share "" and "classical".
# Each run curls a loopback HTTP server through a mixed inbound and checks the
# body, the ClientHello size and the Xray "accepted" line.
#
#   XRAY=/path/to/xray SING_BOX=/path/to/sing-box lx-test/utls_key_share/run.sh
#
# Expected: "" sends the X25519MLKEM768 share (>= 1216 B), "classical" fits in
# one TCP segment without it (< 1184 B); both reach the server. Loopback only.
set -u

XRAY=${XRAY:?set XRAY to an Xray-core binary}
SING_BOX=${SING_BOX:?set SING_BOX to a sing-box-lx binary with with_utls and with_xhttp}
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/utls_key_share.XXXXXX")
TCP_PORT=${TCP_PORT:-24441}
XHTTP_PORT=${XHTTP_PORT:-24442}
RELAY_TCP_PORT=${RELAY_TCP_PORT:-24443}
RELAY_XHTTP_PORT=${RELAY_XHTTP_PORT:-24444}
MIXED_PORT=${MIXED_PORT:-24445}
HTTP_PORT=${HTTP_PORT:-24446}
UUID=7c0e5f4e-2a0a-4c8e-9a51-5c1f3f0a8b12
PIDS=()
cleanup() {
	for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null; done
	wait 2>/dev/null
}
trap cleanup EXIT

listening() {
	(exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}
wait_port() {
	for _ in $(seq 50); do
		listening "$1" && return 0
		sleep 0.2
	done
	return 1
}

cd "$WORK" || exit 1
"$SING_BOX" generate tls-keypair localhost >keypair.pem || exit 1
awk '/BEGIN PRIVATE KEY/,/END PRIVATE KEY/' keypair.pem >key.pem
awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' keypair.pem >cert.pem

cat >xray.json <<JSON
{
  "log": {"loglevel": "info"},
  "inbounds": [
    {
      "listen": "127.0.0.1", "port": $TCP_PORT, "protocol": "vless",
      "settings": {"clients": [{"id": "$UUID"}], "decryption": "none"},
      "streamSettings": {
        "network": "raw", "security": "tls",
        "tlsSettings": {"certificates": [{"certificateFile": "$WORK/cert.pem", "keyFile": "$WORK/key.pem"}]}
      }
    },
    {
      "listen": "127.0.0.1", "port": $XHTTP_PORT, "protocol": "vless",
      "settings": {"clients": [{"id": "$UUID"}], "decryption": "none"},
      "streamSettings": {
        "network": "xhttp", "xhttpSettings": {"path": "/xh", "mode": "auto"}, "security": "tls",
        "tlsSettings": {"alpn": ["h2"], "certificates": [{"certificateFile": "$WORK/cert.pem", "keyFile": "$WORK/key.pem"}]}
      }
    }
  ],
  "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.1/32"]}]}}]
}
JSON

mkdir -p www && echo "utls-key-share-ok" >www/index.html
python3 -m http.server "$HTTP_PORT" --bind 127.0.0.1 --directory www >http.log 2>&1 &
PIDS+=($!)
"$XRAY" run -c xray.json >xray.log 2>&1 &
PIDS+=($!)
python3 "$HERE/relay.py" "$RELAY_TCP_PORT" "$TCP_PORT" >relay-tcp.log 2>&1 &
PIDS+=($!)
python3 "$HERE/relay.py" "$RELAY_XHTTP_PORT" "$XHTTP_PORT" >relay-xhttp.log 2>&1 &
PIDS+=($!)
for port in "$TCP_PORT" "$XHTTP_PORT" "$RELAY_TCP_PORT" "$RELAY_XHTTP_PORT" "$HTTP_PORT"; do
	if ! wait_port "$port"; then
		echo "nothing listens on 127.0.0.1:$port"
		cat xray.log
		exit 1
	fi
done

status=0
for transport in tcp xhttp; do
	for key_share in "" classical; do
		name="$transport-${key_share:-default}"
		if [ "$transport" = tcp ]; then
			port=$RELAY_TCP_PORT
			extra_tls=''
			transport_json=''
		else
			port=$RELAY_XHTTP_PORT
			extra_tls='"alpn": ["h2"],'
			transport_json=', "transport": {"type": "xhttp", "mode": "auto", "path": "/xh"}'
		fi
		cat >"sb-$name.json" <<JSON
{
  "log": {"level": "info"},
  "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": $MIXED_PORT}],
  "outbounds": [{
    "type": "vless", "tag": "$name", "server": "127.0.0.1", "server_port": $port, "uuid": "$UUID",
    "tls": {
      "enabled": true, "server_name": "localhost", "insecure": true, $extra_tls
      "utls": {"enabled": true, "fingerprint": "chrome_155", "key_share": "$key_share"}
    }$transport_json
  }]
}
JSON
		relay_log="relay-$transport.log"
		relay_before=$(wc -l <"$relay_log")
		xray_before=$(wc -l <xray.log)
		"$SING_BOX" run -c "sb-$name.json" >"sb-$name.log" 2>&1 &
		sb=$!
		wait_port "$MIXED_PORT"
		body=$(curl -sS --max-time 10 -x "socks5h://127.0.0.1:$MIXED_PORT" "http://127.0.0.1:$HTTP_PORT/" 2>&1)
		kill "$sb" 2>/dev/null
		wait "$sb" 2>/dev/null
		size=$(tail -n +"$((relay_before + 1))" "$relay_log" | awk '/^clienthello/ {print $2; exit}')
		accepted=$(tail -n +"$((xray_before + 1))" xray.log | grep -c "accepted")
		if [ -z "$key_share" ]; then
			size_ok=$([ "${size:-0}" -ge 1216 ] && echo yes)
		else
			size_ok=$([ "${size:-0}" -gt 0 ] && [ "${size:-0}" -lt 1184 ] && echo yes)
		fi
		if [ "$body" = "utls-key-share-ok" ] && [ "$size_ok" = yes ] && [ "$accepted" -gt 0 ]; then
			echo "$name: OK (ClientHello $size B, xray accepted $accepted)"
		else
			echo "$name: FAIL body=[$body] ClientHello=[$size] xray accepted=$accepted"
			grep -iE "warn|error" "sb-$name.log" | head -5
			status=1
		fi
	done
done
echo "logs: $WORK"
exit $status
