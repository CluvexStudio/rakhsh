#!/usr/bin/env bash
# rakhsh — interactive installer / control panel.
# Set up either end of the tunnel, hand the other end a one-line setup link,
# add a proxy core (Iranian sites direct, the rest through the tunnel), run the
# web panel, tune the kernel, watch status, and tear it all down again.
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/CluvexStudio/rakhsh/main/install.sh)
#   sudo ./install.sh
#   sudo ./install.sh --join rakhsh://…      join straight from a setup link
#
# Binaries: found if already present (installed, next to this script, or a local
# cargo build under target/), otherwise downloaded from the GitHub release.
# Override with  RAKHSH_BIN=/path  /  RAKHSH_CONTROL_BIN=/path,
# or point elsewhere with  RAKHSH_REPO=owner/repo  RAKHSH_VERSION=v0.1.0
set -u

GH_REPO="${RAKHSH_REPO:-CluvexStudio/rakhsh}"
GH_VERSION="${RAKHSH_VERSION:-latest}"

# ─────────────────────────── theme · network / mesh ──────────────────
if [ -t 1 ] && [ "${NO_COLOR:-}" = "" ]; then
  B=$'\e[1m'; D=$'\e[2m'; R=$'\e[0m'
  RED=$'\e[38;5;203m'; GRN=$'\e[38;5;79m'; YEL=$'\e[38;5;221m'
  BLU=$'\e[38;5;75m'; MAG=$'\e[38;5;141m'; CYN=$'\e[38;5;44m'; GRY=$'\e[38;5;240m'; WIRE=$'\e[38;5;38m'
else
  B=; D=; R=; RED=; GRN=; YEL=; BLU=; MAG=; CYN=; GRY=; WIRE=
fi
NODE="●"; DOWN="○"; HUB="◆"; EDGE="▸"
ok(){   printf "  ${GRN}${NODE}${R} %s\n" "$*"; }
bad(){  printf "  ${RED}${DOWN}${R} %s\n" "$*"; }
info(){ printf "  ${CYN}${EDGE}${R} %s\n" "$*"; }
warn(){ printf "  ${YEL}△${R} %s\n" "$*"; }
die(){  printf "\n  ${RED}${DOWN} %s${R}\n\n" "$*"; exit 1; }
rule(){ printf "  ${GRY}╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌${R}\n"; }

# Scratch space. Fixed /tmp paths in a root script are a symlink waiting to happen.
TMPD=$(mktemp -d "${TMPDIR:-/tmp}/rakhsh-install.XXXXXX") || { echo "cannot create a temp dir"; exit 1; }
chmod 700 "$TMPD"
trap 'rm -rf "$TMPD"' EXIT INT TERM

# A pending node that resolves to online / offline.
step(){ # step "label" cmd...
  local label="$1"; shift
  printf "  ${CYN}◌${R} %s" "$label"
  if "$@" >"$TMPD/step" 2>&1; then
    printf "\r  ${GRN}${NODE}${R} %s\n" "$label"
  else
    printf "\r  ${RED}${DOWN}${R} %s\n" "$label"
    sed 's/^/      /' "$TMPD/step" | tail -4
    return 1
  fi
}

banner(){
  clear 2>/dev/null || true
  printf "\n"
  printf "   ${CYN}${B}rakhsh${R} ${GRY}·${R} ${MAG}${B}رخش${R}\n"
  printf "   ${GRY}fast ${WIRE}·${GRY} authenticated ${WIRE}·${GRY} camouflaged tunnel and proxy core${R}\n\n"
  printf "   ${GRN}${B}${NODE}${R}${WIRE}━━━━━━━${R}${BLU}${B}${HUB}${R}${WIRE}━━━━━━━${R}${GRN}${B}${NODE}${R}\n"
  printf "   ${GRY}entry   core    exit${R}\n"
  printf "\n"
}

ask(){ # ask "prompt" default varname
  local v; read -rp "  ${CYN}${EDGE}${R} $1 [$2]: " v; printf -v "$3" '%s' "${v:-$2}"
}
yesno(){ # yesno "prompt" y|n  -> 0 = yes
  local v; read -rp "  ${CYN}${EDGE}${R} $1 [$2]: " v; v=${v:-$2}
  case "$v" in y|Y|yes|YES) return 0;; *) return 1;; esac
}

# ─────────────────────────────── env ─────────────────────────────────
# $EUID is a bash builtin: it works even where `id`/`whoami` are disabled
# (some hosting images neuter them).
case "${1:-}" in -h|--help) ;; *) [ "${EUID:-1}" -eq 0 ] || die "run as root (sudo $0)";; esac

ARCH=$(uname -m 2>/dev/null); case "$ARCH" in ""|*isabled*) ARCH="${HOSTTYPE:-x86_64}";; esac
OS=$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-linux}")
CPUS=$(nproc 2>/dev/null); case "$CPUS" in ""|*[!0-9]*) CPUS=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo "?");; esac
pubip(){
  local ip
  ip=$(curl -fsS --max-time 4 https://api.ipify.org 2>/dev/null) \
    || ip=$(curl -fsS --max-time 4 https://ifconfig.me 2>/dev/null) \
    || ip=$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[0-9.]+' | head -1)
  echo "${ip:-}"
}
PUBIP=$(pubip)

CFGDIR=/etc/rakhsh
CFG=$CFGDIR/config.toml        # the tunnel      (service: rakhsh)
NODECFG=$CFGDIR/node.toml      # standalone node (service: rakhsh-node)
CTLCFG=$CFGDIR/control.toml    # the web panel   (service: rakhsh-control)
IRLIST=$CFGDIR/iran.txt
LINK_PREFIX="rakhsh://"

BIN="${RAKHSH_BIN:-}"
locate_bin(){
  [ -n "$BIN" ] && [ -x "$BIN" ] && return 0
  local d; d=$(cd "$(dirname "$0")" 2>/dev/null && pwd) || d="."
  local cands=(
    /usr/local/bin/rakhsh
    "$d/rakhsh"
    "$d/target/${ARCH}-unknown-linux-musl/release/rakhsh"
    "$d"/target/*/release/rakhsh
    "$d/target/release/rakhsh"
    "$d/target/debug/rakhsh"
    "$(command -v rakhsh 2>/dev/null || true)"
  )
  local c
  for c in "${cands[@]}"; do
    if [ -n "$c" ] && [ -x "$c" ]; then BIN="$c"; return 0; fi
  done
  return 1
}
# ─────────────────────────── fetching binaries ───────────────────────
dl(){ # dl <url> <dest>
  if command -v curl >/dev/null 2>&1; then curl -fsSL --retry 3 --max-time 180 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then wget -q --tries=3 -O "$2" "$1"
  else return 1; fi
}

gh_arch(){
  case "$ARCH" in
    x86_64|amd64)  echo x86_64-unknown-linux-musl;;
    aarch64|arm64) echo aarch64-unknown-linux-musl;;
    *) return 1;;
  esac
}

# Download one release asset to /usr/local/bin, checking its sha256 when the
# release publishes one.
fetch_release(){ # fetch_release <binary name>
  local name="$1" tgt base asset out sum
  tgt=$(gh_arch) || { bad "no prebuilt binary for ${B}$ARCH${R}"; return 1; }
  asset="$name-$tgt"
  if [ "$GH_VERSION" = latest ]; then
    base="https://github.com/$GH_REPO/releases/latest/download"
  else
    base="https://github.com/$GH_REPO/releases/download/$GH_VERSION"
  fi
  out="$TMPD/$name"
  printf "  ${CYN}◌${R} downloading %s (%s)" "$name" "$tgt"
  if ! dl "$base/$asset" "$out"; then
    printf "\r  ${RED}${DOWN}${R} downloading %s\n" "$name"
    info "no release asset at ${B}$base/$asset${R}"
    info "if the repository is private, the download needs a token — build locally instead"
    return 1
  fi
  if dl "$base/$asset.sha256" "$out.sha256" 2>/dev/null; then
    sum=$(awk '{print $1}' "$out.sha256")
    if [ "$(sha256sum "$out" | awk '{print $1}')" != "$sum" ]; then
      printf "\r  ${RED}${DOWN}${R} downloading %s\n" "$name"
      die "checksum mismatch for $asset — refusing to install it"
    fi
  else
    printf "\r  ${YEL}△${R} downloading %s ${GRY}(no published checksum)${R}\n" "$name"
  fi
  install -m 0755 "$out" "/usr/local/bin/$name" || return 1
  printf "\r  ${GRN}${NODE}${R} installed /usr/local/bin/%s      \n" "$name"
  return 0
}

ensure_bin(){
  if ! locate_bin; then
    info "rakhsh binary not found on this host"
    if yesno "download it from github.com/$GH_REPO?" y; then
      if fetch_release rakhsh; then BIN=/usr/local/bin/rakhsh; fi
    fi
  fi
  if ! locate_bin; then
    bad "no rakhsh binary."
    info "build it:  ${B}cargo zigbuild --release --target ${ARCH}-unknown-linux-musl${R}"
    info "then re-run from the project dir — it auto-finds ${B}target/.../release/rakhsh${R}"
    info "or copy it to ${B}/usr/local/bin/rakhsh${R}, or run ${B}sudo RAKHSH_BIN=/real/path ./install.sh${R}"
    die "need the binary to continue"
  fi
  if [ "$BIN" != /usr/local/bin/rakhsh ]; then
    install -m 0755 "$BIN" /usr/local/bin/rakhsh && BIN=/usr/local/bin/rakhsh
  fi
}

CTLBIN="${RAKHSH_CONTROL_BIN:-}"
locate_ctl(){
  [ -n "$CTLBIN" ] && [ -x "$CTLBIN" ] && return 0
  local d; d=$(cd "$(dirname "$0")" 2>/dev/null && pwd) || d="."
  local cands=(
    /usr/local/bin/rakhsh-control
    "$d/rakhsh-control"
    "$d/target/${ARCH}-unknown-linux-musl/release/rakhsh-control"
    "$d"/target/*/release/rakhsh-control
    "$d/target/release/rakhsh-control"
    "$d/control/target/release/rakhsh-control"
    "$d/control/target/debug/rakhsh-control"
    "$(command -v rakhsh-control 2>/dev/null || true)"
  )
  local c
  for c in "${cands[@]}"; do
    if [ -n "$c" ] && [ -x "$c" ]; then CTLBIN="$c"; return 0; fi
  done
  return 1
}
ensure_ctl(){
  if ! locate_ctl; then
    info "rakhsh-control binary not found on this host"
    if yesno "download it from github.com/$GH_REPO?" y; then
      fetch_release rakhsh-control && CTLBIN=/usr/local/bin/rakhsh-control
    fi
  fi
  if ! locate_ctl; then
    bad "no rakhsh-control binary."
    info "build it:  ${B}cargo build --release -p rakhsh-control${R}  (in control/)"
    info "or copy it to ${B}/usr/local/bin/rakhsh-control${R}, or run with ${B}RAKHSH_CONTROL_BIN=/real/path${R}"
    return 1
  fi
  if [ "$CTLBIN" != /usr/local/bin/rakhsh-control ]; then
    install -m 0755 "$CTLBIN" /usr/local/bin/rakhsh-control && CTLBIN=/usr/local/bin/rakhsh-control
  fi
  return 0
}

# Read one top-level "key = \"value\"" out of a TOML file.
toml_get(){ sed -n "s/^$2 *= *\"\([^\"]*\)\".*/\1/p" "$1" 2>/dev/null | head -1; }

panel_creds(){ # panel_creds  — print the URL, username and password of an installed panel
  local listen user pass host port
  listen=$(toml_get "$CTLCFG" listen); user=$(toml_get "$CTLCFG" username); pass=$(toml_get "$CTLCFG" password)
  port=${listen##*:}; host=${listen%:*}
  case "$host" in ""|0.0.0.0|"[::]"|"::") host="${PUBIP:-<server-ip>}";; esac
  printf "\n  ${B}Panel${R}\n"
  printf "   ${WIRE}├─${R} ${CYN}${HUB}${R} url       ${YEL}https://%s:%s${R}\n" "$host" "$port"
  printf "   ${WIRE}├─${R} ${CYN}${HUB}${R} username  ${B}%s${R}\n" "$user"
  if [ -n "$pass" ]; then
    printf "   ${WIRE}└─${R} ${CYN}${HUB}${R} password  ${B}%s${R}\n" "$pass"
  else
    printf "   ${WIRE}└─${R} ${RED}${DOWN}${R} password  ${RED}not set — the panel is open to anyone who can reach it${R}\n"
  fi
}

# Point the panel's first [[node]] at the service on this host. Only the FIRST
# commented unit/config_path: the ones below belong to the commented-out example
# node, and uncommenting those duplicates the keys and breaks the TOML.
wire_node(){ # wire_node <unit> <config path>
  sed -i "0,/^# unit = /s|^# unit = .*|unit = \"$1\"|" "$CTLCFG"
  sed -i "0,/^# config_path = /s|^# config_path = .*|config_path = \"$2\"|" "$CTLCFG"
}

svc_exists(){ [ -f "/etc/systemd/system/$1.service" ]; }

# Print the proxy endpoints found in the first [[inbound]] of a config.
proxy_info(){ # proxy_info <cfgfile>
  local f="$1"; [ -f "$f" ] || return 0
  local blk listen user pass host port cred=""
  blk=$(awk 'BEGIN{n=0} /^\[\[inbound\]\]/{n++; f=(n==1); next} /^\[/{f=0} f' "$f")
  [ -n "$blk" ] || return 0
  listen=$(printf '%s\n' "$blk" | sed -n 's/^listen *= *"\(.*\)".*/\1/p' | head -1)
  user=$(printf '%s\n' "$blk" | sed -n 's/^username *= *"\(.*\)".*/\1/p' | head -1)
  pass=$(printf '%s\n' "$blk" | sed -n 's/^password *= *"\(.*\)".*/\1/p' | head -1)
  host=${listen%:*}; port=${listen##*:}
  [ "$host" = "0.0.0.0" ] && host="${PUBIP:-<server-ip>}"
  [ -n "$user" ] && cred="${user}:${pass}@"
  printf "\n  ${B}Proxy endpoints${R}\n"
  printf "   ${WIRE}├─${R} ${CYN}${HUB}${R} SOCKS5  ${YEL}socks5://%s%s:%s${R}\n" "$cred" "$host" "$port"
  printf "   ${WIRE}└─${R} ${CYN}${HUB}${R} HTTP    ${YEL}http://%s%s:%s${R}\n" "$cred" "$host" "$port"
  case "$listen" in 127.*|localhost*|\[::1\]*) info "bound to loopback — reachable only from this machine";; esac
}

build_iran_list(){
  mkdir -p "$CFGDIR"
  step "building the Iranian IP list from the RIPE registry" "$BIN" rules iran -o "$IRLIST" \
    || warn "list not built — .ir domains still go direct; retry later from the menu"
}

# ─────────────────────────────── actions ─────────────────────────────
create_tunnel(){
  banner
  printf "  ${B}Create a new tunnel${R}  ${GRY}(run this on the server the other side will reach)${R}\n\n"
  rule

  if [ -f "$CFG" ]; then
    yesno "$CFG already exists — replace it? (a .bak copy is kept)" n || return 0
    cp "$CFG" "$CFG.bak"
  fi

  local role other_role carrier sni="" dir="" direct=0 addr lanes x c m e enc links_in
  printf "\n  This server is the…\n"
  printf "    ${CYN}1${R}) ${B}entry${R}   ${GRY}(inside Iran — users connect here)${R}\n"
  printf "    ${CYN}2${R}) ${B}exit${R}    ${GRY}(abroad — reaches the open internet)${R}\n"
  ask "choice" 1 x
  if [ "$x" = 2 ]; then role=exit; other_role=entry; else role=entry; other_role=exit; fi

  printf "\n  Carrier (how bytes cross the border):\n"
  printf "    ${CYN}1${R}) ${B}wss${R}    ${GRY}camouflaged HTTPS/WebSocket — probe-resistant ${GRN}(recommended)${R}\n"
  printf "    ${CYN}2${R}) ${B}quicv2${R} ${GRY}real QUIC v2 (passes the Iran filter)${R}\n"
  printf "    ${CYN}3${R}) ${B}tls${R}    ${GRY}plain TLS camouflage${R}\n"
  printf "    ${CYN}4${R}) ${B}kcp${R}    ${GRY}UDP ARQ for lossy links${R}\n"
  printf "    ${CYN}5${R}) ${B}tcp${R}    ${GRY}plain (fastest, no camouflage)${R}\n"
  ask "choice" 1 c
  case "$c" in 2) carrier=quicv2;; 3) carrier=tls;; 4) carrier=kcp;; 5) carrier=tcp;; *) carrier=wss;; esac
  case "$carrier" in wss|tls|ws) ask "SNI / fake host" www.bing.com sni;; esac

  printf "\n  Fallback carriers ${GRY}(optional — if the main carrier is blocked the tunnel moves to these by itself and back; see LINKS.md)${R}\n"
  printf "    any of ${B}quicv2 kcp tcp tls wss${R}, space-separated; ${B}CARRIER:PORT${R} for its own port (a TCP carrier can't reuse the tunnel's TCP port).\n"
  printf "    ${GRY}e.g.  quicv2 kcp${R}   — press Enter for none\n"
  ask "fallbacks" "" links_in
  local link_args=() l
  for l in $links_in; do link_args+=(--link "$l"); done

  printf "\n  Data protection ${GRY}(what the tunnel does to your bytes once connected — both ends get the same setting):${R}\n"
  printf "    ${CYN}1${R}) ${B}full${R}  ${GRY}AES-256-GCM on every byte ${GRN}(recommended)${R}\n"
  printf "    ${CYN}2${R}) ${B}none${R}  ${GRY}no protection after the handshake — fastest; only if your traffic is already encrypted end to end${R}\n"
  ask "choice" 1 e
  case "$e" in 2) enc=none;; *) enc=full;; esac
  case "$enc" in
    none) warn "encryption=none: both ends are still authenticated, but data on the wire is unprotected — it can be read and altered. Use it only for traffic that is already encrypted end to end." ;;
  esac

  printf "\n  Stream resumption ${GRY}(optional — when a lane drops, connections move to another lane and go on instead of being reset; both ends get it; costs some memory, see RESUME.md)${R}\n"
  local resume_args=()
  yesno "keep connections alive across lane drops?" n && resume_args=(--resume)

  printf "\n  Tunnel mode:\n"
  printf "    ${CYN}1${R}) reverse  ${GRY}exit dials the entry ${GRN}(default — entry has a public port)${R}\n"
  printf "    ${CYN}2${R}) direct   ${GRY}entry dials the exit${R}\n"
  ask "choice" 1 m
  [ "$m" = 2 ] && { direct=1; dir="--direct"; }

  local listen_role; [ "$direct" = 1 ] && listen_role=exit || listen_role=entry
  local def_ip="1.2.3.4"; [ "$role" = "$listen_role" ] && def_ip="${PUBIP:-1.2.3.4}"
  printf "\n  Public address of the ${B}${listen_role}${R} (what the other end dials):\n"
  ask "address" "${def_ip}:7000" addr

  printf "\n  Forwarded ports (blank to finish): ${B}listen=target${R}, e.g. 0.0.0.0:443=127.0.0.1:8443 — add ${B}/udp${R} for UDP.\n"
  local fwd_args=() f
  while :; do
    read -rp "  ${CYN}${EDGE}${R} forward: " f; [ -z "$f" ] && break
    fwd_args+=(--forward "$f")
  done
  [ ${#fwd_args[@]} -eq 0 ] && info "no forwards — fine if you only use the proxy core below"

  printf "\n  ${B}Core${R} ${GRY}an optional SOCKS5+HTTP proxy on the entry. It can send Iranian sites straight out\n  of Iran and everything else through the tunnel.${R}\n"
  local proxy_args=() plisten
  if yesno "expose a proxy on the entry?" n; then
    ask "proxy listen address (0.0.0.0:1080 shares it; a login is generated)" 127.0.0.1:1080 plisten
    proxy_args=(--proxy "$plisten")
    yesno "Iranian sites direct, everything else via the tunnel?" y && proxy_args+=(--split-iran)
  fi

  ask "parallel lanes" 4 lanes

  printf "\n"
  local init_out
  init_out=$("$BIN" init --tunnel-addr "$addr" --carrier "$carrier" ${sni:+--sni "$sni"} $dir --lanes "$lanes" --encryption "$enc" ${link_args[@]+"${link_args[@]}"} ${resume_args[@]+"${resume_args[@]}"} \
      ${fwd_args[@]+"${fwd_args[@]}"} ${proxy_args[@]+"${proxy_args[@]}"} 2>"$TMPD/err") \
    || { sed 's/^/      /' "$TMPD/err"; die "rakhsh init failed"; }
  ok "generated a matched key pair + token"

  rm -f "$TMPD/rk_e.toml" "$TMPD/rk_x.toml"
  awk -v d="$TMPD" '/^########## entry/{s="e";next} /^########## exit/{s="x";next} s{print > (d "/rk_" s ".toml")}' <<<"$init_out"
  local mine other
  if [ "$role" = entry ]; then mine=$TMPD/rk_e.toml; other=$TMPD/rk_x.toml; else mine=$TMPD/rk_x.toml; other=$TMPD/rk_e.toml; fi

  mkdir -p "$CFGDIR"
  cp "$mine" "$CFG"; chmod 600 "$CFG"
  ok "wrote this server's config → $CFG  (role=${B}$role${R}, carrier=${B}$carrier${R}, encryption=${B}$enc${R})"
  step "validating the config" "$BIN" check -c "$CFG" || die "generated config failed validation"

  grep -q 'rule_file' "$CFG" && build_iran_list
  step "installing systemd service (rakhsh.service)" "$BIN" install -c "$CFG" --name rakhsh

  local link; link="${LINK_PREFIX}$(base64 -w0 < "$other" 2>/dev/null || base64 < "$other" | tr -d '\n')"
  rm -f "$TMPD/rk_e.toml" "$TMPD/rk_x.toml"
  [ "$role" = entry ] && proxy_info "$CFG"
  printf "\n"; rule
  printf "\n  ${GRN}${B}Tunnel is up on this side.${R}  Now set up the ${B}${other_role}${R} server:\n\n"
  printf "    paste this one line into it — nothing else to answer:\n\n"
  printf "  ${YEL}bash <(curl -fsSL https://raw.githubusercontent.com/%s/main/install.sh) --join %s${R}\n\n" "$GH_REPO" "$link"
  printf "    ${GRY}or run the installer there and choose “Join with a setup link”, then paste:${R}\n\n"
  printf "  ${GRY}%s${R}\n\n" "$link"
  [ "$role" = exit ] && [ ${#proxy_args[@]} -gt 0 ] && info "the proxy lives on the entry — its endpoints (and login) are shown after you join there"
  info "the link carries the other end's keys + settings — treat it like a password."
  rule
}

join_link(){ # join_link [link]
  banner
  printf "  ${B}Join with a setup link${R}\n\n"
  local link="${1:-}"
  [ -z "$link" ] && read -rp "  ${CYN}${EDGE}${R} paste rakhsh:// link: " link
  [ -z "$link" ] && die "no link"
  local b64="${link#${LINK_PREFIX}}"
  local cfg; cfg=$(printf '%s' "$b64" | base64 -d 2>/dev/null) || die "bad link (base64 decode failed)"
  printf '%s' "$cfg" | grep -q 'role *=' || die "bad link (not a rakhsh config)"
  if [ -f "$CFG" ]; then
    yesno "$CFG already exists — replace it? (a .bak copy is kept)" n || return 0
    cp "$CFG" "$CFG.bak"
  fi
  mkdir -p "$CFGDIR"
  printf '%s\n' "$cfg" > "$CFG"; chmod 600 "$CFG"
  local role; role=$(grep -oP 'role *= *"\K[^"]+' "$CFG")
  ok "decoded config → $CFG (role=${B}$role${R})"
  step "validating the config" "$BIN" check -c "$CFG" || die "link config failed validation"
  grep -q 'rule_file' "$CFG" && build_iran_list
  step "installing systemd service (rakhsh.service)" "$BIN" install -c "$CFG" --name rakhsh
  proxy_info "$CFG"
  printf "\n  ${GRN}${B}Joined.${R} Both ends should now connect.\n"
}

create_node(){
  banner
  printf "  ${B}Proxy node${R}  ${GRY}standalone SOCKS5+HTTP proxy, direct out, no tunnel${R}\n\n"
  rule; printf "\n"
  if [ -f "$NODECFG" ]; then
    yesno "$NODECFG already exists — replace it? (a .bak copy is kept)" n || return 0
    cp "$NODECFG" "$NODECFG.bak"
  fi
  local plisten; ask "listen address (0.0.0.0:1080 shares it; a login is generated)" 127.0.0.1:1080 plisten
  mkdir -p "$CFGDIR"
  "$BIN" init-node --listen "$plisten" > "$NODECFG" || die "init-node failed"
  chmod 600 "$NODECFG"
  step "validating the config" "$BIN" check -c "$NODECFG" || die "node config failed validation"
  step "installing systemd service (rakhsh-node.service)" "$BIN" install -c "$NODECFG" --name rakhsh-node
  proxy_info "$NODECFG"
}

create_panel(){
  banner
  printf "  ${B}Control panel${R}  ${GRY}web panel over this node (and any others you add)${R}\n\n"
  rule; printf "\n"
  ensure_ctl || return 0

  if [ -f "$CTLCFG" ]; then
    ok "panel already set up"
    panel_creds
    printf "\n"
    if yesno "generate a new password?" n; then
      local new; new=$(tr -dc 'a-km-zA-HJ-NP-Z2-9' </dev/urandom 2>/dev/null | head -c 20)
      [ ${#new} -eq 20 ] || die "could not generate a password"
      sed -i "s/^password *=.*/password = \"$new\"/" "$CTLCFG"
      chmod 600 "$CTLCFG"
      svc_exists rakhsh-control && step "restarting rakhsh-control" systemctl restart rakhsh-control
      ok "password changed"
      panel_creds
    fi
    return 0
  fi

  local port
  ask "panel port" 8443 port
  case "$port" in ''|*[!0-9]*) die "not a port: $port";; esac

  mkdir -p "$CFGDIR"
  "$CTLBIN" init -c "$CTLCFG" --listen "0.0.0.0:$port" >"$TMPD/panel" 2>"$TMPD/err" \
    || { sed 's/^/      /' "$TMPD/err"; die "rakhsh-control init failed"; }
  ok "generated $CTLCFG with a random username and password"

  if [ -f "$CFG" ]; then
    wire_node rakhsh "$CFG"
    ok "wired the panel to this node's rakhsh.service"
  elif [ -f "$NODECFG" ]; then
    wire_node rakhsh-node "$NODECFG"
    ok "wired the panel to this node's rakhsh-node.service"
  else
    warn "no rakhsh config on this host yet — the panel will show an empty fleet until you create one"
  fi
  chmod 600 "$CTLCFG"

  step "installing systemd service (rakhsh-control.service)" \
    "$CTLBIN" install -c "$CTLCFG" --name rakhsh-control || die "could not install the service"

  panel_creds
  printf "\n"
  info "the certificate is self-signed, so the browser warns once — or set ${B}tls_cert${R}/${B}tls_key${R} in $CTLCFG"
  info "add more nodes by editing ${B}$CTLCFG${R}, then: ${B}systemctl restart rakhsh-control${R}"
}

update_list(){
  banner; printf "  ${B}Iranian IP list${R}  ${GRY}(for split routing: Iranian sites direct)${R}\n\n"
  build_iran_list
  local s
  for s in rakhsh rakhsh-node; do
    if svc_exists "$s" && systemctl is-active --quiet "$s"; then
      step "restarting $s to load the new list" systemctl restart "$s"
    fi
  done
}

do_optimize(){
  banner; printf "  ${B}Kernel network tuning${R}  ${GRY}(BBR + fq, buffers, backlog)${R}\n\n"
  step "applying sysctl tunables" "$BIN" optimize
  ok "persisted to /etc/sysctl.d/99-rakhsh.conf"
}

show_status(){
  banner; printf "  ${B}Status${R}\n\n"
  printf "  ${GRY}host${R}   %s ${GRY}·${R} %s ${GRY}·${R} %s CPUs ${GRY}·${R} public IP ${B}%s${R}\n" "$ARCH" "$OS" "$CPUS" "${PUBIP:-?}"
  printf "  ${GRY}binary${R} %s  %s\n" "$BIN" "$("$BIN" --version 2>/dev/null)"
  rule
  local s cfg any=0
  for s in rakhsh rakhsh-node; do
    svc_exists "$s" || continue
    any=1
    cfg=$CFG; [ "$s" = rakhsh-node ] && cfg=$NODECFG
    local act; act=$(systemctl is-active "$s" 2>/dev/null)
    if [ "$act" = active ]; then ok "$s.service ${GRN}active${R}"; else bad "$s.service ${RED}$act${R}"; fi
    [ -f "$cfg" ] && info "config $cfg — role $(grep -oP 'role *= *"\K[^"]+' "$cfg" 2>/dev/null), carrier $(grep -oP 'carrier *= *"\K[^"]+' "$cfg" 2>/dev/null || echo tcp)"
    printf "  ${GRY}recent log:${R}\n"
    journalctl -u "$s" --no-pager -n 5 2>/dev/null | sed 's/^/    /' | sed 's/\x1b\[[0-9;]*m//g' | cut -c1-150
    proxy_info "$cfg"
    printf "\n"
  done
  if svc_exists rakhsh-control; then
    any=1
    local pact; pact=$(systemctl is-active rakhsh-control 2>/dev/null)
    if [ "$pact" = active ]; then ok "rakhsh-control.service ${GRN}active${R}"; else bad "rakhsh-control.service ${RED}$pact${R}"; fi
    [ -f "$CTLCFG" ] && panel_creds
    printf "\n"
  fi
  [ $any = 0 ] && warn "nothing installed yet"
  [ -f "$IRLIST" ] && info "Iranian IP list: $(grep -c '^cidr:' "$IRLIST") blocks in $IRLIST"
}

do_uninstall(){
  banner; printf "  ${B}Uninstall${R}\n\n"
  local s any=0
  for s in rakhsh rakhsh-node; do
    svc_exists "$s" || continue
    any=1
    if yesno "remove $s.service and its config?" n; then
      "$BIN" uninstall --name "$s" >/dev/null 2>&1
      if [ "$s" = rakhsh ]; then rm -f "$CFG" "$CFG.bak"; else rm -f "$NODECFG" "$NODECFG.bak"; fi
      ok "$s removed"
    else
      info "$s kept"
    fi
  done
  if svc_exists rakhsh-control; then
    any=1
    if yesno "remove rakhsh-control.service and its config?" n; then
      if locate_ctl; then "$CTLBIN" uninstall --name rakhsh-control >/dev/null 2>&1; else
        systemctl disable --now rakhsh-control >/dev/null 2>&1
        rm -f /etc/systemd/system/rakhsh-control.service; systemctl daemon-reload
      fi
      rm -f "$CTLCFG"
      ok "rakhsh-control removed"
    else
      info "rakhsh-control kept"
    fi
  fi
  [ $any = 0 ] && info "no rakhsh services installed"
  info "binary left at /usr/local/bin/rakhsh"
}

# ─────────────────────────── one-shot arguments ──────────────────────
case "${1:-}" in
  -h|--help)
    banner
    printf "  ${B}usage${R}\n\n"
    printf "    sudo ./install.sh                  the menu\n"
    printf "    sudo ./install.sh --join <link>    join straight from a rakhsh:// link\n"
    printf "    sudo ./install.sh --panel          set up the web panel and print its login\n\n"
    printf "  ${B}environment${R}\n\n"
    printf "    RAKHSH_BIN= / RAKHSH_CONTROL_BIN=  use these binaries\n"
    printf "    RAKHSH_REPO=owner/repo             download from another repository\n"
    printf "    RAKHSH_VERSION=v0.1.0              pin a release (default: latest)\n\n"
    exit 0;;
  --join)
    ensure_bin
    join_link "${2:-}"
    exit $?;;
  --panel)
    ensure_bin
    create_panel
    exit $?;;
  "") ;;
  *) die "unknown argument ${1}. Try --help";;
esac

# ─────────────────────────────── menu ────────────────────────────────
ensure_bin
while :; do
  banner
  printf "  ${GRN}${NODE}${R} ${GRY}this node${R}  ${D}%s · %s · %s CPUs · %s${R}\n\n" "$ARCH" "$OS" "$CPUS" "${PUBIP:-?}"
  printf "   ${WIRE}┌─${R} ${CYN}${HUB}${R} ${B}1${R}  ${B}Create a new tunnel${R}     ${GRY}wizard, proxy core, setup link${R}\n"
  printf "   ${WIRE}├─${R} ${CYN}${HUB}${R} ${B}2${R}  ${B}Join with a setup link${R}  ${GRY}paste a link from the other node${R}\n"
  printf "   ${WIRE}├─${R} ${CYN}${HUB}${R} ${B}3${R}  ${B}Proxy node${R}              ${GRY}standalone SOCKS5/HTTP, no tunnel${R}\n"
  printf "   ${WIRE}├─${R} ${CYN}${HUB}${R} ${B}4${R}  ${B}Control panel${R}           ${GRY}web panel, with a generated login${R}\n"
  printf "   ${WIRE}├─${R} ${CYN}${HUB}${R} ${B}5${R}  ${B}Update Iranian IP list${R}  ${GRY}for direct routing of Iranian sites${R}\n"
  printf "   ${WIRE}├─${R} ${CYN}${HUB}${R} ${B}6${R}  ${B}Optimize kernel${R}         ${GRY}BBR + fq + buffers${R}\n"
  printf "   ${WIRE}├─${R} ${CYN}${HUB}${R} ${B}7${R}  ${B}Status${R}\n"
  printf "   ${WIRE}├─${R} ${CYN}${HUB}${R} ${B}8${R}  ${B}Uninstall${R}\n"
  printf "   ${WIRE}└─${R} ${GRY}${DOWN}${R} ${B}0${R}  ${GRY}Exit${R}\n\n"
  read -rp "  ${CYN}${EDGE}${R} select: " sel
  case "$sel" in
    1) create_tunnel;; 2) join_link;; 3) create_node;; 4) create_panel;;
    5) update_list;; 6) do_optimize;; 7) show_status;; 8) do_uninstall;;
    0|q|Q) printf "\n  ${GRY}bye.${R}\n\n"; exit 0;;
    *) continue;;
  esac
  printf "\n  ${GRY}press Enter to return to the menu…${R}"; read -r _
done
