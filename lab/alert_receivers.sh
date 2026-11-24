#!/usr/bin/env bash
# Alert delivery to REAL receivers (issue 12): rsyslog receives the syslog alerts over UDP and TCP
# (RFC 6587 octet counting) and nginx the webhook POSTs over HTTP and HTTPS, all on loopback.
# `monitor` runs two cycles against 127.0.0.1; between them a TCP port opens, so the second cycle
# raises a port-opened alert and delivers it to every sink. lab/alert_receivers_check.py then
# compares what rsyslog parsed and what nginx received with the alerts monitor wrote.
#
#   INSTALL=1 bash lab/alert_receivers.sh       # installs rsyslog, nginx and openssl with apt
#
# HTTPS: nginx's certificate is signed by a private CA made here, and monitor gets that CA through
# SSL_CERT_FILE (the documented way to trust a private CA on Linux). A second HTTPS server with a
# self-signed certificate that is not trusted must receive nothing, and monitor must report the
# failed delivery.
#
# Environment: CLI (path of network-scope-cli, default target/release/), PYTHON (default python3),
# SUDO (default sudo), WORK (scratch directory), INSTALL=1 (apt).
#
# Status: passes on the ubuntu-latest runner (first run 2026-11-24: rsyslog 8.2512.0, nginx
# 1.28.3). Nothing here needs root except apt.
set -euo pipefail
export MSYS_NO_PATHCONV=1

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(dirname "$here")
PYTHON=${PYTHON:-python3}
CLI=${CLI:-$repo/target/release/network-scope-cli}
INSTALL=${INSTALL:-0}
SUDO=${SUDO-sudo}
WORK=${WORK:-$(mktemp -d)}
mkdir -p "$WORK"
WORK=$(cd "$WORK" && pwd)

# Ports (all on 127.0.0.1): syslog UDP and TCP, webhook HTTP, HTTPS (trusted CA), HTTPS
# (untrusted), nginx's internal answer, and the port that opens between the two monitor cycles.
SYSLOG_UDP=5514
SYSLOG_TCP=5601
HOOK_HTTP=18080
HOOK_HTTPS=18443
HOOK_UNTRUSTED=18444
HOOK_ANSWER=18081
OPEN_ALWAYS=18091
OPENED=18090

log() { echo "== $*"; }
pids=()
cleanup() {
  local status=$?
  for pid in "${pids[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null || true; done
  [ -f "$WORK/nginx.pid" ] && kill "$(cat "$WORK/nginx.pid")" 2>/dev/null || true
  if [ "$status" != 0 ]; then
    for f in "$WORK"/*.log "$WORK"/syslog.tsv "$WORK"/monitor.err "$WORK"/alerts.jsonl; do
      [ -f "$f" ] && { echo "---- $f"; tail -n 30 "$f"; }
    done 2>/dev/null || true
  fi
  exit "$status"
}
trap cleanup EXIT

wait_port() {
  for _ in $(seq 1 75); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then return 0; fi
    sleep 0.2
  done
  echo "port $1 did not open" >&2
  return 1
}

if [ "$INSTALL" = 1 ]; then
  log "installing rsyslog, nginx and openssl"
  $SUDO apt-get update -qq
  $SUDO apt-get install -y -qq --no-install-recommends rsyslog nginx openssl
  # The packaged nginx would hold port 80; ours runs on high ports as this user.
  $SUDO systemctl stop nginx 2>/dev/null || true
fi

log "certificates: a private CA, a server certificate it signs, and an untrusted one"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=Network Scope lab CA" \
  -keyout "$WORK/ca.key" -out "$WORK/ca.pem" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" \
  -keyout "$WORK/server.key" -out "$WORK/server.csr" 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > "$WORK/san.ext"
openssl x509 -req -in "$WORK/server.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" \
  -CAcreateserial -days 2 -extfile "$WORK/san.ext" -out "$WORK/server.pem" 2>/dev/null
# An ordinary server certificate (not a CA) that no trusted CA issued, so the rejection is for
# the unknown issuer and for nothing else.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=localhost" \
  -addext "subjectAltName=IP:127.0.0.1" -addext "basicConstraints=critical,CA:FALSE" \
  -addext "extendedKeyUsage=serverAuth" \
  -keyout "$WORK/untrusted.key" -out "$WORK/untrusted.pem" 2>/dev/null

log "rsyslog on udp/$SYSLOG_UDP and tcp/$SYSLOG_TCP"
mkdir -p "$WORK/rsyslog"
cat > "$WORK/rsyslog.conf" <<EOF
global(workDirectory="$WORK/rsyslog")
module(load="imudp")
module(load="imtcp")
# What rsyslog parsed from each message, one line per message (tab separated, msg last).
template(name="fields" type="list") {
  property(name="inputname") constant(value="\t")
  property(name="syslogfacility-text") constant(value="\t")
  property(name="syslogseverity-text") constant(value="\t")
  property(name="app-name") constant(value="\t")
  property(name="msgid") constant(value="\t")
  property(name="msg" droplastlf="on") constant(value="\n")
}
ruleset(name="alerts") {
  action(type="omfile" file="$WORK/syslog.tsv" template="fields")
}
input(type="imudp" address="127.0.0.1" port="$SYSLOG_UDP" ruleset="alerts")
input(type="imtcp" address="127.0.0.1" port="$SYSLOG_TCP" ruleset="alerts")
EOF
: > "$WORK/syslog.tsv"
# Ubuntu confines /usr/sbin/rsyslogd with an AppArmor profile that only allows writing under
# /var/log; a copy of the binary in WORK is not covered by it (the modules still load from the
# compiled-in directory).
cp "$(command -v rsyslogd)" "$WORK/rsyslogd"
"$WORK/rsyslogd" -v | head -n 1
"$WORK/rsyslogd" -N1 -f "$WORK/rsyslog.conf"
"$WORK/rsyslogd" -n -f "$WORK/rsyslog.conf" -i "$WORK/rsyslog.pid" > "$WORK/rsyslogd.log" 2>&1 &
pids+=($!)
wait_port "$SYSLOG_TCP"

log "nginx on $HOOK_HTTP (http), $HOOK_HTTPS (https, private CA), $HOOK_UNTRUSTED (https, untrusted)"
mkdir -p "$WORK/nginx-tmp"
cat > "$WORK/nginx.conf" <<EOF
daemon off;
pid $WORK/nginx.pid;
error_log $WORK/nginx-error.log info;
events {}
http {
  access_log off;
  client_body_temp_path $WORK/nginx-tmp/body;
  proxy_temp_path $WORK/nginx-tmp/proxy;
  fastcgi_temp_path $WORK/nginx-tmp/fastcgi;
  uwsgi_temp_path $WORK/nginx-tmp/uwsgi;
  scgi_temp_path $WORK/nginx-tmp/scgi;
  # The body is read (and logged) because the request is passed on to the answer server.
  client_body_buffer_size 64k;
  log_format hook escape=json '{"scheme":"\$scheme","method":"\$request_method","uri":"\$request_uri",'
                              '"type":"\$content_type","agent":"\$http_user_agent","body":"\$request_body"}';
  server {
    listen 127.0.0.1:$HOOK_HTTP;
    location = /hook { access_log $WORK/webhook-http.log hook; proxy_pass http://127.0.0.1:$HOOK_ANSWER/ok; }
  }
  server {
    listen 127.0.0.1:$HOOK_HTTPS ssl;
    listen [::1]:$HOOK_HTTPS ssl;
    ssl_certificate $WORK/server.pem;
    ssl_certificate_key $WORK/server.key;
    location = /hook { access_log $WORK/webhook-https.log hook; proxy_pass http://127.0.0.1:$HOOK_ANSWER/ok; }
  }
  server {
    listen 127.0.0.1:$HOOK_UNTRUSTED ssl;
    ssl_certificate $WORK/untrusted.pem;
    ssl_certificate_key $WORK/untrusted.key;
    location = /hook { access_log $WORK/webhook-untrusted.log hook; proxy_pass http://127.0.0.1:$HOOK_ANSWER/ok; }
  }
  server {
    listen 127.0.0.1:$HOOK_ANSWER;
    location = /ok { return 204; }
  }
}
EOF
nginx -v
nginx -t -c "$WORK/nginx.conf" -p "$WORK"
nginx -c "$WORK/nginx.conf" -p "$WORK" &
pids+=($!)
wait_port "$HOOK_HTTPS"
: > "$WORK/webhook-http.log"; : > "$WORK/webhook-https.log"; : > "$WORK/webhook-untrusted.log"

# A port that is open from the start, so the host is a known device after the first cycle (the
# first run records devices without alerting; port changes are compared for known hosts).
"$PYTHON" -I -m http.server "$OPEN_ALWAYS" --bind 127.0.0.1 --directory "$WORK" > "$WORK/open-always.log" 2>&1 &
pids+=($!)
wait_port "$OPEN_ALWAYS"

log "monitor: two cycles against 127.0.0.1; port $OPENED opens after the first"
: > "$WORK/alerts.jsonl"
SSL_CERT_FILE="$WORK/ca.pem" "$CLI" monitor 127.0.0.1 --ports "$OPENED,$OPEN_ALWAYS" --db "$WORK/inventory.sqlite" \
  --interval 8 --cycles 2 --alerts "$WORK/alerts.jsonl" \
  --syslog "udp://127.0.0.1:$SYSLOG_UDP,tcp://127.0.0.1:$SYSLOG_TCP" \
  --webhook "http://127.0.0.1:$HOOK_HTTP/hook,https://localhost:$HOOK_HTTPS/hook,https://127.0.0.1:$HOOK_UNTRUSTED/hook" \
  > "$WORK/monitor.out" 2> "$WORK/monitor.err" &
monitor=$!
pids+=($monitor)
for _ in $(seq 1 100); do
  grep -q "^Cycle 1:" "$WORK/monitor.err" && break
  sleep 0.2
done
grep -q "^Cycle 1:" "$WORK/monitor.err" || { echo "monitor did not finish its first cycle" >&2; exit 1; }
"$PYTHON" -I -m http.server "$OPENED" --bind 127.0.0.1 --directory "$WORK" > "$WORK/opened.log" 2>&1 &
pids+=($!)
wait_port "$OPENED"
wait "$monitor"
cat "$WORK/monitor.err"
# UDP and the file writer are asynchronous: give rsyslog a moment.
sleep 2

log "checking what the receivers got"
"$PYTHON" -I "$here/alert_receivers_check.py" "$WORK"
