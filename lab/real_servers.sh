#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright the Network Scope contributors
# SPDX-License-Identifier: MIT
# Network Scope against REAL servers (roadmap A6): Samba, OpenSSH, OpenSSL s_server and nginx on
# loopback, then lab/real_servers_check.py compares the scan with what the servers were told to do.
# Run by the CI job `real-servers` on ubuntu-latest:
#
#   INSTALL=1 bash lab/real_servers.sh          # installs the servers with apt, needs sudo
#   PARTS=tls bash lab/real_servers.sh          # only some parts: smb,ssh,tls,nginx
#
# Environment: CLI (path of network-scope-cli, default target/release/), PYTHON (default python3),
# SUDO (default sudo; set empty when already root), WORK (scratch directory), INSTALL=1 (apt).
#
# What runs where: smbd needs root (SMB detection only runs on port 445, which is privileged) and
# so does sshd; openssl s_server and nginx run as the current user on high ports. Everything binds
# 127.0.0.1. The servers, ports, suites and expected values are defined once, in the LAB table of
# real_servers_check.py, which this script reads (--shell-env).
#
# Status: written for the ubuntu-latest runner image (Ubuntu 24.04: Samba 4.19, OpenSSH 9.6, nginx
# 1.24, OpenSSL 3.0) and not yet run there. The openssl part was run on Windows (Git's OpenSSL).
set -euo pipefail
export MSYS_NO_PATHCONV=1   # Git Bash on Windows rewrites "/CN=..." arguments otherwise

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(dirname "$here")
PYTHON=${PYTHON:-python3}
CLI=${CLI:-$repo/target/release/network-scope-cli}
PARTS=${PARTS:-smb,ssh,tls,nginx}
INSTALL=${INSTALL:-0}
SUDO=${SUDO-sudo}
WORK=${WORK:-$(mktemp -d)}
mkdir -p "$WORK"

# A native Windows Python (Git Bash on a developer machine) needs Windows paths; elsewhere a no-op.
py_path() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else echo "$1"; fi; }
check="$(py_path "$here")/real_servers_check.py"

eval "$("$PYTHON" -I "$check" --shell-env)"

has() { case ",$PARTS," in *",$1,"*) return 0 ;; esac; return 1; }
log() { echo "== $*"; }

pids=()
cleanup() {
  local status=$?
  for pid in "${pids[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null || true; done
  # smbd and sshd run as root: kill by the pid files and by command line.
  if [ -n "$SUDO" ] || [ "$(id -u)" = 0 ]; then
    $SUDO pkill -f "[s]mbd .*$WORK" 2>/dev/null || true
    $SUDO pkill -f "[s]shd .*$WORK" 2>/dev/null || true
  fi
  if [ "$status" != 0 ]; then
    for log in "$WORK"/*.log "$WORK"/samba/log.*; do
      [ -f "$log" ] && { echo "---- $log"; tail -n 20 "$log"; }
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
  log "installing the servers"
  $SUDO apt-get update -qq
  $SUDO apt-get install -y -qq --no-install-recommends samba openssh-server nginx openssl
  # The packages start their own services (smbd on 445, nginx on 80): ours must be the only ones.
  $SUDO systemctl stop smbd nmbd samba-ad-dc nginx 2>/dev/null || true
  $SUDO systemctl disable smbd nmbd nginx 2>/dev/null || true
fi

openssl version
cert="$WORK/cert.pem"
key="$WORK/key.pem"
if has tls || has nginx; then
  log "certificate"
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$key" -out "$cert" -days 2 \
    -subj "/CN=$CERT_CN" -addext "subjectAltName=DNS:$CERT_CN,IP:127.0.0.1" >"$WORK/cert.log" 2>&1 ||
    { cat "$WORK/cert.log"; exit 1; }
fi

ports=()

if has tls; then
  log "openssl s_server A on $TLS_A_PORT (TLS 1.3 only: $TLS_A_SUITES, server order)"
  openssl s_server -accept "127.0.0.1:$TLS_A_PORT" -cert "$cert" -key "$key" -www -quiet \
    -tls1_3 -ciphersuites "$TLS_A_SUITES" -serverpref >"$WORK/s_server_a.log" 2>&1 &
  pids+=($!)
  log "openssl s_server B on $TLS_B_PORT (TLS 1.2: $TLS_B_12, TLS 1.3: $TLS_B_13)"
  openssl s_server -accept "127.0.0.1:$TLS_B_PORT" -cert "$cert" -key "$key" -www -quiet \
    -cipher "$TLS_B_12" -ciphersuites "$TLS_B_13" -serverpref >"$WORK/s_server_b.log" 2>&1 &
  pids+=($!)
  wait_port "$TLS_A_PORT"
  wait_port "$TLS_B_PORT"
  ports+=("$TLS_A_PORT" "$TLS_B_PORT")
fi

if has nginx; then
  log "nginx on $NGINX_PORT (TLS 1.2: $NGINX_12, TLS 1.3: $NGINX_13)"
  mkdir -p "$WORK/nginx"
  cat >"$WORK/nginx.conf" <<EOF
daemon off;
pid $WORK/nginx.pid;
error_log $WORK/nginx-error.log;
events { worker_connections 64; }
http {
  access_log off;
  client_body_temp_path $WORK/nginx/body;
  proxy_temp_path $WORK/nginx/proxy;
  fastcgi_temp_path $WORK/nginx/fastcgi;
  uwsgi_temp_path $WORK/nginx/uwsgi;
  scgi_temp_path $WORK/nginx/scgi;
  server {
    listen 127.0.0.1:$NGINX_PORT ssl;
    ssl_certificate $cert;
    ssl_certificate_key $key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers $NGINX_12;
    ssl_prefer_server_ciphers on;
    ssl_conf_command Ciphersuites $NGINX_13;
    server_tokens on;
    location / { return 200 "ok\n"; }
  }
}
EOF
  nginx -t -c "$WORK/nginx.conf" -e "$WORK/nginx-test.log"
  nginx -c "$WORK/nginx.conf" -e "$WORK/nginx-error.log" >"$WORK/nginx.log" 2>&1 &
  pids+=($!)
  wait_port "$NGINX_PORT"
  ports+=("$NGINX_PORT")
fi

if has ssh; then
  log "sshd on $SSH_PORT"
  $SUDO mkdir -p /run/sshd
  $SUDO rm -f "$WORK/ssh_host_key" "$WORK/ssh_host_key.pub"
  $SUDO ssh-keygen -q -t ed25519 -N '' -f "$WORK/ssh_host_key"
  cat >"$WORK/sshd_config" <<EOF
Port $SSH_PORT
ListenAddress 127.0.0.1
HostKey $WORK/ssh_host_key
PidFile $WORK/sshd.pid
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
LogLevel ERROR
EOF
  $SUDO /usr/sbin/sshd -t -f "$WORK/sshd_config"
  $SUDO /usr/sbin/sshd -D -e -f "$WORK/sshd_config" >"$WORK/sshd.log" 2>&1 &
  pids+=($!)
  wait_port "$SSH_PORT"
  ports+=("$SSH_PORT")
fi

if has smb; then
  log "smbd on $SMB_PORT (SMB 3.1.1, signing mandatory, $SMB_ENCRYPTION, NetBIOS name $SMB_NETBIOS)"
  mkdir -p "$WORK/samba/"{lock,state,cache,pid,private,ncalrpc} "$WORK/share"
  cat >"$WORK/smb.conf" <<EOF
[global]
   workgroup = $SMB_WORKGROUP
   netbios name = $SMB_NETBIOS
   server role = standalone server
   server min protocol = SMB2_10
   server max protocol = SMB3_11
   server signing = mandatory
   server smb encrypt = desired
   server smb3 encryption algorithms = $SMB_ENCRYPTION
   smb ports = $SMB_PORT
   interfaces = lo 127.0.0.1/8
   bind interfaces only = yes
   disable netbios = yes
   map to guest = Bad User
   load printers = no
   disable spoolss = yes
   printcap name = /dev/null
   log file = $WORK/samba/log.%m
   lock directory = $WORK/samba/lock
   state directory = $WORK/samba/state
   cache directory = $WORK/samba/cache
   pid directory = $WORK/samba/pid
   private dir = $WORK/samba/private
   ncalrpc dir = $WORK/samba/ncalrpc
[lab]
   path = $WORK/share
   guest ok = yes
   read only = yes
EOF
  testparm -s "$WORK/smb.conf" >"$WORK/testparm.log" 2>&1 || { cat "$WORK/testparm.log"; exit 1; }
  # smbd keeps its own process group: with --no-process-group it shares the CI step's, and the
  # SIGTERM it sends to its group when it shuts down reached the GitHub runner itself.
  $SUDO smbd --foreground --debug-stdout -s "$WORK/smb.conf" >"$WORK/smbd.log" 2>&1 &
  pids+=($!)
  wait_port "$SMB_PORT"
  ports+=("$SMB_PORT")
fi

csv=$(IFS=,; echo "${ports[*]}")
log "scan 127.0.0.1 ports $csv"
"$CLI" scan 127.0.0.1 --ports "$csv" --fast --services --timeout 4000 --quiet \
  --db "$WORK/scan.sqlite" --output "$WORK/scan.json"

status=0
"$PYTHON" -I "$check" --scan "$(py_path "$WORK/scan.json")" --only "$PARTS" || status=$?
if [ "$status" != 0 ]; then
  echo "---- what the scan found on the lab ports"
  "$PYTHON" -I -c "import json,sys; h=json.load(open(sys.argv[1]))['hosts'][0]; print(json.dumps(h['identity'], indent=1, sort_keys=True))" "$(py_path "$WORK/scan.json")"
fi
exit "$status"
