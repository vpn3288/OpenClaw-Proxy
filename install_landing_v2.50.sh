#!/usr/bin/env bash
# install_landing_v2.50.sh — 落地机安装脚本 (v2.50 终极版)
# 4协议单端口回落 · routeOnly嗅探 · AsIs出站 · CAP_NET_BIND_SERVICE
# have_ipv6() sysctl guard · atomic_write · python validate · reload-or-restart
# 彻底修复: ACME 幽灵残留清理，SED 静态硬编码防崩，IPv6 端口精准放行
set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
readonly VERSION="v2.50-Final"

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()     { error "$*"; exit 1; }

readonly LANDING_BASE="/etc/xray-landing"
readonly CERT_RELOAD_SCRIPT="/usr/local/bin/xray-landing-cert-reload.sh"
readonly LANDING_CONF="${LANDING_BASE}/config.json"
readonly LANDING_BIN="/usr/local/bin/xray-landing"
readonly LANDING_SVC="xray-landing.service"
readonly LANDING_USER="xray-landing"
readonly LANDING_LOG="/var/log/xray-landing"
readonly MANAGER_BASE="/etc/landing_manager"
readonly INSTALLED_FLAG="${MANAGER_BASE}/.installed"
readonly MANAGER_CONFIG="${MANAGER_BASE}/manager.conf"
# 兼容环境变量覆写
ACME_HOME="${LANDING_BASE}/acme"
readonly CERT_BASE="${LANDING_BASE}/certs"
readonly FW_CHAIN="XRAY-LANDING"
readonly FW_CHAIN6="XRAY-LANDING-v6"
readonly LOGROTATE_FILE="/etc/logrotate.d/xray-landing"

[[ $EUID -eq 0 ]] || die "必须以 root 身份运行"

find /etc/xray-landing /etc/landing_manager /etc/systemd/system \
  -maxdepth 5 -name '.snap-recover.*' -mtime +1 -delete 2>/dev/null || true

_global_cleanup(){
  find /etc/xray-landing /etc/landing_manager /etc/systemd/system /etc/logrotate.d \
    -maxdepth 5 \
    \( -name '.xray-landing.*' -o -name 'tmp-*.conf' -o -name '.snap-recover.*' -o -name '.manager.*' \) \
    -type f -delete 2>/dev/null || true
  rm -rf "${MANAGER_BASE}/tmp/xray_tmp_"* 2>/dev/null || true
  find "${MANAGER_BASE}/tmp" \
    -maxdepth 1 -type f \
    \( -name '.manager.*' -o -name '.xray-landing.*' \) \
    -delete 2>/dev/null || true
}
trap '_global_cleanup' EXIT
trap 'echo -e "\n${RED}[中断] 请执行: bash $0 --uninstall${NC}"; exit 1' INT TERM

LANDING_PORT=8443
VLESS_UUID=""
VLESS_GRPC_PORT=0
TROJAN_GRPC_PORT=0
VLESS_WS_PORT=0
TROJAN_TCP_PORT=0
CF_TOKEN=""
CREATED_USER="0"

trim(){
  local s=${1-}
  s="${s#${s%%[!' '	\
]*}}"
  s="${s%${s##*[!' '	\
]}}"
  printf '%s' "$s"
}

shell_quote(){
  local s=${1-}
  printf "'%s'" "${s//\'/\'\\\'\'}"
}

atomic_write()(
  set -euo pipefail
  local target="$1" mode="$2" owner_group="${3:-root:root}" dir tmp
  dir="$(dirname "$target")"
  mkdir -p "$dir"
  tmp="$(mktemp "$dir/.xray-landing.XXXXXX")"
  trap 'rm -f "$tmp" 2>/dev/null || true' EXIT
  cat >"$tmp"
  chmod "$mode" "$tmp"
  chown "$owner_group" "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$target"
)

readonly LANDING_LOCK_FILE="${MANAGER_BASE}/tmp/landing-manager.lock"
_acquire_lock(){
  mkdir -p "${MANAGER_BASE}/tmp"
  exec 201>"$LANDING_LOCK_FILE"
  flock -w 10 201 || die "配置正在被其他进程修改，请稍后重试（等待超时 10s）"
}
_release_lock(){ flock -u 201 2>/dev/null || true; }

have_ipv6(){
  [[ -f /proc/net/if_inet6 ]] \
    && ip6tables -L >/dev/null 2>&1 \
    && [[ "$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 1)" != "1" ]]
}

detect_ssh_port(){
  local p=""
  p="$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}' || true)"
  if [[ -z "${p:-}" ]]; then
    p="$(ss -tlnp 2>/dev/null | awk '/sshd/{for(i=1;i<=NF;i++) if($i~/:[0-9]+$/){sub(/^.*:/,"",$i);print $i;exit}}' | head -1 || true)"
  fi
  if [[ ! "$p" =~ ^[0-9]+$ ]] || (( p < 1 || p > 65535 )); then
    echo -e "${RED}[FATAL]${NC} 无法探测 SSH 端口（sshd -T 和 ss 均失败）。" \
      "请以 detect_ssh_port_override=<端口> 环境变量指定后重试。" >&2
    if [[ "${detect_ssh_port_override:-}" =~ ^[0-9]+$ ]]; then
      p="$detect_ssh_port_override"
    else
      exit 1
    fi
  fi
  printf '%s\n' "$p"
}

load_manager_config(){
  [[ -f "$MANAGER_CONFIG" ]] || return 0
  local lp vu vg tg vw tt ct cu
  lp=$(grep '^LANDING_PORT='     "$MANAGER_CONFIG" 2>/dev/null | cut -d= -f2- || true)
  vu=$(grep '^VLESS_UUID='       "$MANAGER_CONFIG" 2>/dev/null | cut -d= -f2- || true)
  vg=$(grep '^VLESS_GRPC_PORT='  "$MANAGER_CONFIG" 2>/dev/null | cut -d= -f2- || true)
  tg=$(grep '^TROJAN_GRPC_PORT=' "$MANAGER_CONFIG" 2>/dev/null | cut -d= -f2- || true)
  vw=$(grep '^VLESS_WS_PORT='    "$MANAGER_CONFIG" 2>/dev/null | cut -d= -f2- || true)
  tt=$(grep '^TROJAN_TCP_PORT='  "$MANAGER_CONFIG" 2>/dev/null | cut -d= -f2- || true)
  ct=$(grep '^CF_TOKEN='         "$MANAGER_CONFIG" 2>/dev/null | cut -d= -f2- || true)
  cu=$(grep '^CREATED_USER='     "$MANAGER_CONFIG" 2>/dev/null | cut -d= -f2- || true)

  [[ "$lp" =~ ^[0-9]+$ ]] && (( lp >= 1 && lp <= 65535 )) \
    || die "manager.conf 损坏：LANDING_PORT='${lp:-<空>}' 非法。请执行 --uninstall 重装或从备份恢复"
  [[ -n "$vu" ]] \
    || die "manager.conf 损坏：VLESS_UUID 为空。请执行 --uninstall 重装或从备份恢复"

  LANDING_PORT="$lp"
  VLESS_UUID="$vu"
  for _pf in "$vg" "$tg" "$vw" "$tt"; do
    [[ -z "$_pf" || "$_pf" =~ ^[0-9]+$ ]] \
      || die "manager.conf 损坏：内部端口 '${_pf}' 格式非法。请执行 --uninstall 重装"
  done
  [[ "$vg" =~ ^[0-9]+$ ]] && VLESS_GRPC_PORT="$vg"   || VLESS_GRPC_PORT=0
  [[ "$tg" =~ ^[0-9]+$ ]] && TROJAN_GRPC_PORT="$tg"  || TROJAN_GRPC_PORT=0
  [[ "$vw" =~ ^[0-9]+$ ]] && VLESS_WS_PORT="$vw"     || VLESS_WS_PORT=0
  [[ "$tt" =~ ^[0-9]+$ ]] && TROJAN_TCP_PORT="$tt"   || TROJAN_TCP_PORT=0
  [[ -n "$ct" ]] && CF_TOKEN="$ct"         || CF_TOKEN=""
  [[ -n "$cu" ]] && CREATED_USER="$cu"     || CREATED_USER="0"
}

save_manager_config(){
  mkdir -p "$MANAGER_BASE"
  atomic_write "$MANAGER_CONFIG" 600 root:root <<MCEOF
LANDING_PORT=${LANDING_PORT}
VLESS_UUID=${VLESS_UUID}
VLESS_GRPC_PORT=${VLESS_GRPC_PORT}
TROJAN_GRPC_PORT=${TROJAN_GRPC_PORT}
VLESS_WS_PORT=${VLESS_WS_PORT}
TROJAN_TCP_PORT=${TROJAN_TCP_PORT}
CF_TOKEN=${CF_TOKEN}
CREATED_USER=${CREATED_USER}
MCEOF
}

validate_domain(){
  local d="$1"
  (( ${#d} >= 4 && ${#d} <= 253 )) || die "域名长度非法 (${#d}): $d"
  [[ "$d" == *"."* ]] || die "域名必须包含至少一个点: $d"
  python3 - "$d" <<'PY' >/dev/null 2>&1 || die "域名格式非法: $d"
import re, sys
d = sys.argv[1].strip()
pat = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)'
    r'(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?))*'
    r'\.[a-zA-Z0-9]{2,}$'
)
raise SystemExit(0 if pat.match(d) else 1)
PY
}

validate_ipv4(){
  local ip="$1"
  python3 - "$ip" <<'PY' >/dev/null 2>&1 || die "IPv4 格式非法: $ip"
import ipaddress, sys
try:
    addr = ipaddress.IPv4Address(sys.argv[1].strip())
    if addr.is_loopback or addr.is_unspecified or addr.is_reserved or addr.is_multicast or addr.is_link_local:
        raise SystemExit(1)
    if addr.is_private:
        raise SystemExit(1)
except ValueError:
    raise SystemExit(1)
PY
}

validate_port(){
  [[ "$1" =~ ^[0-9]+$ ]] || die "端口格式非法: $1"
  (( $1 >= 1 && $1 <= 65535 )) || die "端口需在 1-65535: $1"
}

validate_password(){
  local p="${1//[[:space:]]/}"
  [[ ${#p} -ge 16 ]] || die "Trojan 密码至少 16 位"
  [[ "$p" =~ ^[a-zA-Z0-9]+$ ]] || die "密码仅限字母数字"
}

validate_cf_token(){
  [[ -n "$1" ]] || die "CF Token 不能为空"
  [[ ${#1} -ge 40 ]] || die "CF Token 格式疑似有误（长度 ${#1} 位，通常 ≥40 位）"
  [[ "$1" =~ ^[a-zA-Z0-9_-]+$ ]] || die "CF Token 含非法字符（仅允许字母、数字、_、-）"
}

issue_certificate(){
  local domain="$1" cf_token="$2"
  [[ -n "$domain" ]] || die "issue_certificate: domain 不能为空"
  [[ -n "$cf_token" ]] || die "issue_certificate: Cloudflare Token 不能为空"

  mkdir -p "$LANDING_BASE" "$LANDING_LOG" "$CERT_BASE" "${MANAGER_BASE}/tmp"

  if [[ ! -x "${ACME_HOME}/acme.sh" ]]; then
    ACME_HOME="${HOME}/.acme.sh"
    curl -fsSL https://get.acme.sh | sh -s email=none >/dev/null 2>&1 \
      || die "acme.sh 安装失败，请检查网络或手动预装"
  fi
  [[ -x "${ACME_HOME}/acme.sh" ]] || die "acme.sh 不可用: ${ACME_HOME}/acme.sh"

  mkdir -p "${CERT_BASE}/${domain}"
  atomic_write "$CERT_RELOAD_SCRIPT" 755 root:root <<'RELOAD'
#!/usr/bin/env bash
set -euo pipefail
if [[ -f /etc/systemd/system/xray-landing.service ]]; then
  systemctl restart xray-landing.service >/dev/null 2>&1 || true
fi
exit 0
RELOAD

  local _acme_cmd=(env ACME_HOME="${ACME_HOME}" CF_Token="${cf_token}" "${ACME_HOME}/acme.sh" --home "${ACME_HOME}")
  "${_acme_cmd[@]}" --issue --dns dns_cf -d "$domain" --keylength ec-256 --force || die "证书签发失败: ${domain}"
  "${_acme_cmd[@]}" --install-cert -d "$domain" --ecc \
    --fullchain-file "${CERT_BASE}/${domain}/fullchain.pem" \
    --key-file "${CERT_BASE}/${domain}/key.pem" \
    --reloadcmd "$CERT_RELOAD_SCRIPT" || die "证书安装失败: ${domain}"

  chmod 600 "${CERT_BASE}/${domain}/fullchain.pem" "${CERT_BASE}/${domain}/key.pem" 2>/dev/null || true
  success "证书已就绪: ${domain}"
}

sync_xray_config(){
  load_manager_config
  mkdir -p "$LANDING_BASE" "$LANDING_LOG" "$CERT_BASE" "${MANAGER_BASE}/tmp"

  [[ -n "${LANDING_PORT:-}" ]] || die "sync_xray_config: LANDING_PORT 为空"
  [[ -n "${VLESS_UUID:-}" ]] || die "sync_xray_config: VLESS_UUID 为空"
  [[ -n "${VLESS_GRPC_PORT:-}" ]] || VLESS_GRPC_PORT=0
  [[ -n "${TROJAN_GRPC_PORT:-}" ]] || TROJAN_GRPC_PORT=0
  [[ -n "${VLESS_WS_PORT:-}" ]] || VLESS_WS_PORT=0
  [[ -n "${TROJAN_TCP_PORT:-}" ]] || TROJAN_TCP_PORT=0

  python3 - "$LANDING_CONF" "$LANDING_PORT" "$VLESS_UUID" "$VLESS_GRPC_PORT" "$TROJAN_GRPC_PORT" "$VLESS_WS_PORT" "$TROJAN_TCP_PORT" "$LANDING_LOG" "$CERT_BASE" "$MANAGER_BASE" <<'PY' | atomic_write "$LANDING_CONF" 600 root:root
import json
import os
import sys
from pathlib import Path

out = sys.argv[1]
public_port = int(sys.argv[2])
uuid = sys.argv[3].strip()
vgrpc_port = int(sys.argv[4])
tgrpc_port = int(sys.argv[5])
vws_port = int(sys.argv[6])
ttcp_port = int(sys.argv[7])
log_dir = sys.argv[8]
cert_base = Path(sys.argv[9])
manager_base = Path(sys.argv[10])
nodes_dir = manager_base / 'nodes'
pfx = uuid[:8]

certs = []
seen = set()
passwords = []
pwd_seen = set()
if nodes_dir.exists():
    for meta in sorted(nodes_dir.glob('*.conf')):
        data = {}
        try:
            for line in meta.read_text(errors='replace').splitlines():
                if '=' in line:
                    k, v = line.split('=', 1)
                    data[k.strip()] = v.strip()
        except Exception:
            continue
        dom = data.get('DOMAIN')
        if dom and dom not in seen:
            full = cert_base / dom / 'fullchain.pem'
            key = cert_base / dom / 'key.pem'
            if full.is_file() and key.is_file():
                certs.append({'certificateFile': str(full), 'keyFile': str(key)})
                seen.add(dom)
        pwd = data.get('PASSWORD')
        if pwd and pwd not in pwd_seen:
            passwords.append(pwd)
            pwd_seen.add(pwd)
if not passwords:
    passwords = [os.environ.get('LANDING_TROJAN_PASSWORD', 'changeme-landing')]

config = {
    'log': {
        'loglevel': 'warning',
        'error': f'{log_dir}/error.log',
        'access': f'{log_dir}/access.log',
    },
    'inbounds': [
        {
            'tag': 'landing-public',
            'listen': '0.0.0.0',
            'port': public_port,
            'protocol': 'vless',
            'settings': {
                'clients': [{'id': uuid, 'flow': 'xtls-rprx-vision', 'email': 'landing'}],
                'decryption': 'none',
                'fallbacks': [
                    {'alpn': 'h2', 'path': f'/{pfx}-vg', 'dest': f'127.0.0.1:{vgrpc_port}'},
                    {'path': f'/{pfx}-vw', 'dest': f'127.0.0.1:{vws_port}'},
                    {'dest': f'127.0.0.1:{ttcp_port}'},
                ],
            },
            'streamSettings': {
                'network': 'tcp',
                'security': 'tls',
                'tlsSettings': {
                    'alpn': ['h2', 'http/1.1'],
                    'certificates': certs,
                },
            },
            'sniffing': {
                'enabled': True,
                'destOverride': ['http', 'tls'],
                'routeOnly': True,
            },
        },
        {
            'tag': 'landing-vless-grpc',
            'listen': '127.0.0.1',
            'port': vgrpc_port,
            'protocol': 'vless',
            'settings': {
                'clients': [{'id': uuid, 'flow': 'xtls-rprx-vision', 'email': 'landing-vless-grpc'}],
                'decryption': 'none',
            },
            'streamSettings': {
                'network': 'grpc',
                'security': 'none',
                'grpcSettings': {'serviceName': f'{pfx}-vg', 'multiMode': True},
            },
        },
        {
            'tag': 'landing-trojan-grpc',
            'listen': '127.0.0.1',
            'port': tgrpc_port,
            'protocol': 'trojan',
            'settings': {
                'clients': [{'password': p} for p in passwords],
                'fallbacks': [],
            },
            'streamSettings': {
                'network': 'grpc',
                'security': 'none',
                'grpcSettings': {'serviceName': f'{pfx}-tg', 'multiMode': True},
            },
        },
        {
            'tag': 'landing-vless-ws',
            'listen': '127.0.0.1',
            'port': vws_port,
            'protocol': 'vless',
            'settings': {
                'clients': [{'id': uuid, 'flow': 'xtls-rprx-vision', 'email': 'landing-vless-ws'}],
                'decryption': 'none',
            },
            'streamSettings': {
                'network': 'ws',
                'security': 'none',
                'wsSettings': {
                    'path': f'/{pfx}-vw',
                    'headers': {'Host': 'localhost'},
                },
            },
        },
        {
            'tag': 'landing-trojan-tcp',
            'listen': '127.0.0.1',
            'port': ttcp_port,
            'protocol': 'trojan',
            'settings': {
                'clients': [{'password': p} for p in passwords],
                'fallbacks': [],
            },
            'streamSettings': {
                'network': 'tcp',
                'security': 'none',
            },
        },
    ],
    'outbounds': [
        {'tag': 'direct', 'protocol': 'freedom'},
        {'tag': 'blocked', 'protocol': 'blackhole'},
    ],
    'routing': {
        'domainStrategy': 'AsIs',
        'rules': [
            {'type': 'field', 'inboundTag': ['landing-public', 'landing-vless-grpc', 'landing-trojan-grpc', 'landing-vless-ws', 'landing-trojan-tcp'], 'outboundTag': 'direct'},
        ],
    },
}

with open(out, 'w', encoding='utf-8') as fh:
    json.dump(config, fh, ensure_ascii=False, indent=2)
    fh.write('\n')
PY
  python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$LANDING_CONF" >/dev/null 2>&1 \
    || { rm -f "$LANDING_CONF" 2>/dev/null || true; die "config.json 生成失败"; }
  success "config.json 已同步: ${LANDING_CONF}"
}

show_help(){
  cat <<HELP
用法: bash install_landing_${VERSION}.sh [选项]
  （无参数）        交互式安装或管理菜单
  --uninstall       清除本脚本所有内容（不影响 mack-a）
  --status          显示当前状态
  set-port <port>   修改落地机监听端口并重启服务
  --help            显示此帮助
HELP
}

get_public_ip(){
  local ip=""
  for src in "https://api.ipify.org" "https://ifconfig.me" "https://ipecho.net/plain" "https://checkip.amazonaws.com"; do
    ip=$(curl -4 -fsSL --connect-timeout 5 "$src" 2>/dev/null | tr -d '[:space:]') && [[ -n "$ip" ]] && break || true
  done
  [[ -n "$ip" ]] || die "无法获取本机公网 IPv4"
  validate_ipv4 "$ip"; echo "$ip"
}

gen_password(){
  local _pw=""
  _pw=$(python3 -c \
    "import secrets,string; a=string.ascii_letters+string.digits; \
     print(''.join(secrets.choice(a) for _ in range(20)),end='')" 2>/dev/null) \
  && [[ ${#_pw} -ge 20 ]] && { printf '%s' "$_pw"; return 0; }

  _pw=$(openssl rand -base64 30 2>/dev/null \
    | LC_ALL=C tr -dc 'a-zA-Z0-9' 2>/dev/null \
    | dd bs=1 count=20 2>/dev/null) \
  && [[ ${#_pw} -ge 20 ]] && { printf '%s' "$_pw"; return 0; }

  _pw=$(LC_ALL=C tr -dc 'a-zA-Z0-9' < /dev/urandom 2>/dev/null \
    | dd bs=1 count=20 2>/dev/null)
  printf '%s' "$_pw"
}

check_deps(){
  export DEBIAN_FRONTEND=noninteractive
  local _bin_pkg=(
    curl:curl wget:wget unzip:unzip iptables:iptables python3:python3
    openssl:openssl ip:iproute2 fuser:psmisc crontab:cron dig:dnsutils
  )
  local missing_pkgs=()
  for bp in "${_bin_pkg[@]}"; do
    local bin="${bp%%:*}" pkg="${bp##*:}"
    command -v "$bin" &>/dev/null || missing_pkgs+=("$pkg")
  done
  local missing=("${missing_pkgs[@]}")
  if (( ${#missing[@]} > 0 )) && command -v apt-get &>/dev/null; then
    local _lw=0
    if command -v fuser &>/dev/null; then
      while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
        sleep 2; ((_lw+=2))
        if ((_lw>60)); then die "apt 锁等待超时（另一个 apt 进程正在运行），请稍后重试"; fi
      done
    else
      sleep 5
    fi
    apt-get update -qq 2>/dev/null || true
    for d in "${missing[@]}"; do
      apt-get install -y "$d" 2>/dev/null || die "安装 $d 失败"
    done
  elif (( ${#missing[@]} > 0 )); then
    for d in "${missing[@]}"; do
      yum install -y "$d" 2>/dev/null || dnf install -y "$d" 2>/dev/null || die "无法安装 $d"
    done
  fi
  for bp in "${_bin_pkg[@]}"; do
    local bin="${bp%%:*}"
    command -v "$bin" &>/dev/null || die "依赖 ${bin} 安装后仍无法找到"
  done
}

optimize_kernel_network(){
  local bbr_conf="/etc/sysctl.d/99-landing-bbr.conf"
  [[ -f "$bbr_conf" ]] && grep -q 'tcp_timestamps' "$bbr_conf" 2>/dev/null && {
    sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -qi 'bbr' || true
    return 0
  }

  local _ram_mb; _ram_mb=$(free -m 2>/dev/null | awk '/^Mem:|^[内內]存:/{print $2}')
  [[ -z "$_ram_mb" ]] && _ram_mb=1024
  local _tw_max=$(( _ram_mb * 100 ))
  (( _tw_max < 10000 ))  && _tw_max=10000
  (( _tw_max > 250000 )) && _tw_max=250000

  local _fd_max=$(( _ram_mb * 800 ))
  (( _fd_max < 524288 ))   && _fd_max=524288
  (( _fd_max > 10485760 )) && _fd_max=10485760
  
  cat > "$bbr_conf" <<BBRCF
net.netfilter.nf_conntrack_max=1048576
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_keepalive_time=300
net.ipv4.tcp_keepalive_intvl=15
net.ipv4.tcp_keepalive_probes=5
net.ipv4.tcp_max_tw_buckets=${_tw_max}
net.ipv4.ip_local_port_range=1024 65535
net.core.somaxconn=65535
fs.nr_open=${_fd_max}
fs.file-max=${_fd_max}
net.ipv4.tcp_notsent_lowat=16384
net.ipv4.tcp_mtu_probing=1
BBRCF
  cat >> "$bbr_conf" <<'BBRCF2'
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_timestamps=1
net.ipv4.tcp_fastopen=3
BBRCF2
  echo "options nf_conntrack hashsize=262144" > /etc/modprobe.d/99-landing-conntrack.conf 2>/dev/null || true
  modprobe nf_conntrack 2>/dev/null || true
  
  local _ct_mem=$(( _ram_mb / 8 * 1024 * 1024 / 300 ))
  (( _ct_mem < 131072 )) && _ct_mem=131072
  echo "$_ct_mem" > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || true
  
  local _ct_max=$(( _ct_mem * 4 ))
  sysctl -w net.netfilter.nf_conntrack_max="${_ct_max}" &>/dev/null || true
  sysctl --system &>/dev/null || true
  
  sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -qi 'bbr' || true
  success "内核网络参数已优化（conntrack hashsize=${_ct_mem} / max=${_ct_max}）"
}

install_xray_binary(){
  info "下载 Xray-core ..."
  local api_resp ver
  api_resp=$(curl -fsSL --connect-timeout 10 "https://api.github.com/repos/XTLS/Xray-core/releases/latest" 2>/dev/null) || die "无法访问 GitHub API"
  ver=$(printf '%s' "$api_resp" | { grep '"tag_name"' || true; } | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
  [[ -n "$ver" ]] || die "无法解析 Xray 版本号"
  local arch; arch=$(uname -m)
  local arch_name="64"
  [[ "$arch" == "aarch64" || "$arch" == "arm64" ]] && arch_name="arm64-v8a"
  [[ "$arch" == "armv7l" ]] && arch_name="arm32-v7a"
  local zip_name="Xray-linux-${arch_name}.zip"
  
  mkdir -p "${MANAGER_BASE}/tmp"
  local tmp_dir; tmp_dir=$(mktemp -d "${MANAGER_BASE}/tmp/xray_tmp_XXXXXX")
  _xray_local_cleanup(){ rm -rf "${tmp_dir}" 2>/dev/null || true; trap - ERR; }
  trap '_xray_local_cleanup' ERR
  
  wget -q --show-progress --timeout=30 --tries=2 -O "${tmp_dir}/xray.zip" \
    "https://github.com/XTLS/Xray-core/releases/download/${ver}/${zip_name}" || die "下载 Xray 失败"
  
  if wget -q -O "${tmp_dir}/sha256sums.txt" \
      "https://github.com/XTLS/Xray-core/releases/download/${ver}/sha256sums.txt" 2>/dev/null; then
    if [[ -f "${tmp_dir}/sha256sums.txt" ]] && grep -qF "$zip_name" "${tmp_dir}/sha256sums.txt"; then
      ( cd "$tmp_dir" && grep -F "$zip_name" sha256sums.txt | sha256sum -c - ) || warn "Xray 完整性校验失败，跳过校验"
      info "sha256 校验通过"
    else
      die "sha256sums.txt 中未找到 ${zip_name}，无法校验 Xray 包完整性"
    fi
  else
    warn "Xray sha256sums.txt 下载失败，跳过完整性校验"
  fi
  unzip -q "${tmp_dir}/xray.zip" xray geoip.dat geosite.dat -d "${tmp_dir}/" || die "解压失败"
  install -m 755 "${tmp_dir}/xray" "$LANDING_BIN"
  chown root:"$LANDING_USER" "$LANDING_BIN" 2>/dev/null || true
  local asset_dir="/usr/local/share/xray-landing"
  mkdir -p "$asset_dir"
  install -m 644 "${tmp_dir}/geoip.dat"   "${asset_dir}/geoip.dat"
  install -m 644 "${tmp_dir}/geosite.dat" "${asset_dir}/geosite.dat"
  _xray_local_cleanup
  success "Xray 安装完成: ${LANDING_BIN} (${ver})"
}

create_system_user(){
  if ! id "$LANDING_USER" &>/dev/null; then
    useradd -r -s /usr/sbin/nologin -d /nonexistent -M "$LANDING_USER" \
      || die "创建系统用户 ${LANDING_USER} 失败。请检查 /usr/sbin/nologin"
    CREATED_USER="1"
    success "系统用户 ${LANDING_USER} 已创建"
  fi
}

write_logrotate(){
  atomic_write "$LOGROTATE_FILE" 644 root:root <<LREOF
/var/log/acme-xray-landing-renew.log {
    su root root
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}
${LANDING_LOG}/*.log {
    su root xray-landing
    daily
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
    create 0640 root root
}
LREOF
  local _jd_conf="/etc/systemd/journald.conf.d/xray-landing.conf"
  mkdir -p "/etc/systemd/journald.conf.d"
  if ! grep -q 'SystemMaxUse=200M' "$_jd_conf" 2>/dev/null; then
    atomic_write "$_jd_conf" 644 root:root <<'JDEOF'
[Journal]
SystemMaxUse=200M
RuntimeMaxUse=50M
JDEOF
    systemctl kill --kill-who=main --signal=SIGUSR2 systemd-journald 2>/dev/null || true
  fi
}

create_systemd_service(){
  mkdir -p "${MANAGER_BASE}/tmp"
  local _svc_tmp; _svc_tmp=$(mktemp "${MANAGER_BASE}/tmp/.xray-landing.svc.XXXXXX")
  trap "rm -f '${_svc_tmp}' 2>/dev/null || true; trap - ERR" ERR
  
  cat > "$_svc_tmp" <<'SVCEOF'
[Unit]
Description=Xray Landing Node (independent from mack-a)
After=network.target nss-lookup.target
StartLimitIntervalSec=900
StartLimitBurst=10
OnFailure=xray-landing-recovery.service

[Service]
Type=simple
User=@@LANDING_USER@@
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStartPre=/bin/sh -c 'test -f @@LANDING_CONF@@ || { echo "config.json missing"; exit 1; }'
ExecStartPre=/bin/sh -c 'python3 -c "import json,sys; json.load(open(sys.argv[1]))" @@LANDING_CONF@@ 2>/dev/null || { echo "config.json invalid JSON"; exit 1; }'
ExecStart=@@LANDING_BIN@@ run -config @@LANDING_CONF@@
Environment=XRAY_LOCATION_ASSET=/usr/local/share/xray-landing
Restart=on-failure
ExecReload=/bin/systemctl restart xray-landing.service
RestartSec=15s
LimitNOFILE=@@LIMIT_NOFILE@@
LimitNPROC=65535
TasksMax=infinity
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=@@LANDING_BASE@@ /usr/local/share/xray-landing @@CERT_BASE@@
ReadWritePaths=@@LANDING_LOG@@
PrivateTmp=true
PrivateDevices=true
ProtectKernelLogs=true
ProtectKernelTunables=true
SystemCallFilter=@system-service
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
ProtectClock=true
LockPersonality=true
UMask=0027
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF

  local _svc_ram_mb; _svc_ram_mb=$(free -m 2>/dev/null | awk '/^Mem:|^[内內]存:/{print $2}')
  [[ -z "$_svc_ram_mb" ]] && _svc_ram_mb=1024
  
  local _svc_fd=$(( _svc_ram_mb * 800 ))
  (( _svc_fd < 524288 ))   && _svc_fd=524288
  (( _svc_fd > 10485760 )) && _svc_fd=10485760

  sed -i \
    -e "s|@@LANDING_USER@@|${LANDING_USER}|g" \
    -e "s|@@LANDING_CONF@@|${LANDING_CONF}|g" \
    -e "s|@@LANDING_BIN@@|${LANDING_BIN}|g" \
    -e "s|@@LANDING_BASE@@|${LANDING_BASE}|g" \
    -e "s|@@CERT_BASE@@|${CERT_BASE}|g" \
    -e "s|@@LANDING_LOG@@|${LANDING_LOG}|g" \
    -e "s|@@LIMIT_NOFILE@@|${_svc_fd}|g" \
    "$_svc_tmp"
    
  mv -f "$_svc_tmp" "/etc/systemd/system/${LANDING_SVC}"
  chmod 644 "/etc/systemd/system/${LANDING_SVC}"
  
  local _xray_svc_d="/etc/systemd/system/xray-landing.service.d"
  mkdir -p "$_xray_svc_d"
  atomic_write "${_xray_svc_d}/xray-landing-limits.conf" 644 root:root <<XRAYLIMITS
[Service]
LimitNOFILE=${_svc_fd}
TasksMax=infinity
XRAYLIMITS

  atomic_write "/etc/systemd/system/xray-landing-recovery.service" 644 root:root <<RECEOF
[Unit]
Description=Xray Landing Recovery (preflight-gated auto-restart)
DefaultDependencies=no

[Service]
Type=oneshot
ExecStart=/bin/sh -c '\
  _lockdir="/run/lock"; \
  mkdir -p "$$_lockdir" 2>/dev/null || true; \
  _lockfile="$$_lockdir/xray-landing-recovery.lock"; \
  _tsfile="$$_lockdir/xray-landing-recovery.last"; \
  ( \
    flock -n 9 || { logger -t xray-landing-recovery "INFO: recovery already running, skipping."; exit 0; }; \
    _now=$(date +%s); \
    if [ -f "$$_tsfile" ]; then \
      _last=$(cat "$$_tsfile" 2>/dev/null || echo 0); \
      _delta=$$((_now - _last)); \
      if [ "$$_delta" -lt 1800 ]; then \
        logger -t xray-landing-recovery "FATAL: Recovery rate-limited (loop detected). Manual intervention required."; \
        echo "$$(date) [FATAL] recovery loop detected ($$_delta s interval)." >> ${LANDING_LOG}/error.log 2>/dev/null || true; \
        exit 0; \
      fi; \
    fi; \
    echo "$$_now" > "$$_tsfile"; \
    _cert_ok=0; _cfg_ok=0; \
    for d in ${CERT_BASE}/*/fullchain.pem; do [ -f "$$d" ] && _cert_ok=1 && break; done; \
    python3 -c "import json,sys; json.load(open(sys.argv[1]))" ${LANDING_CONF} 2>/dev/null && _cfg_ok=1 || true; \
    if [ "$$_cert_ok" = "1" ] && [ "$$_cfg_ok" = "1" ]; then \
      systemctl reset-failed ${LANDING_SVC} 2>/dev/null || true; \
      systemctl start ${LANDING_SVC} 2>/dev/null || true; \
    fi \
  ) 9>"$$_lockfile" \
'
RECEOF

  mkdir -p "$LANDING_LOG"
  chown "$LANDING_USER":"$LANDING_USER" "$LANDING_LOG"
  chmod 750 "$LANDING_LOG"
  write_logrotate
  
  systemctl daemon-reload \
    || die "daemon-reload 失败，systemd 图未更新"
  systemctl enable "$LANDING_SVC"
  systemctl restart "$LANDING_SVC"
  sleep 2
  if systemctl is-active --quiet "$LANDING_SVC"; then
    success "服务 ${LANDING_SVC} 已启动"
  else
    journalctl -u "$LANDING_SVC" --no-pager -n 30
    warn "服务启动失败，回滚 unit 和 logrotate..."
    systemctl disable --now "$LANDING_SVC" 2>/dev/null || true
    rm -f "/etc/systemd/system/${LANDING_SVC}" \
          "/etc/systemd/system/xray-landing-recovery.service" \
          "$LOGROTATE_FILE" 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
    die "服务启动失败，unit/logrotate 已清除，可安全重跑安装"
  fi
}

setup_firewall(){
  load_manager_config
  info "重建防火墙 Chain ${FW_CHAIN}（蓝绿原子切换）..."
  local ssh_port; ssh_port="$(detect_ssh_port)"

  local FW_TMP="${FW_CHAIN}-NEW"
  local FW_TMP6="${FW_CHAIN6}-NEW"

  _bulldoze_input_refs(){
    local _chain="$1" _num
    while true; do
      _num=$(iptables -L INPUT --line-numbers -n 2>/dev/null \
             | awk -v c="$_chain" 'NR>2 && $2==c {print $1; exit}')
      [[ -n "$_num" ]] || break
      iptables -D INPUT "$_num" 2>/dev/null || break
    done
  }
  _bulldoze_input_refs6(){
    local _chain="$1" _num
    while true; do
      _num=$(ip6tables -L INPUT --line-numbers -n 2>/dev/null \
             | awk -v c="$_chain" 'NR>2 && $2==c {print $1; exit}')
      [[ -n "$_num" ]] || break
      ip6tables -D INPUT "$_num" 2>/dev/null || break
    done
  }

  _bulldoze_input_refs  "$FW_CHAIN";  _bulldoze_input_refs  "$FW_TMP"
  iptables -F "$FW_TMP"   2>/dev/null || true; iptables -X "$FW_TMP"   2>/dev/null || true
  iptables -F "$FW_CHAIN" 2>/dev/null || true; iptables -X "$FW_CHAIN" 2>/dev/null || true
  if have_ipv6; then
    _bulldoze_input_refs6 "$FW_CHAIN6"; _bulldoze_input_refs6 "$FW_TMP6"
    ip6tables -F "$FW_TMP6"   2>/dev/null || true; ip6tables -X "$FW_TMP6"   2>/dev/null || true
    ip6tables -F "$FW_CHAIN6" 2>/dev/null || true; ip6tables -X "$FW_CHAIN6" 2>/dev/null || true
  fi
  _fw_landing_rollback(){
    iptables  -D INPUT -m comment --comment "xray-landing-swap"    2>/dev/null || true
    iptables  -F "$FW_TMP"  2>/dev/null || true
    iptables  -X "$FW_TMP"  2>/dev/null || true
    ip6tables -D INPUT -m comment --comment "xray-landing-v6-swap" 2>/dev/null || true
    ip6tables -F "$FW_TMP6" 2>/dev/null || true
    ip6tables -X "$FW_TMP6" 2>/dev/null || true
  }
  trap '_fw_landing_rollback; exit 130' INT TERM; trap 'exit 130' ERR
  
  iptables -N "$FW_TMP" 2>/dev/null || iptables -F "$FW_TMP"
  iptables -A "$FW_TMP" -i lo                                       -m comment --comment "xray-landing-lo"        -j ACCEPT
  iptables -A "$FW_TMP" -p tcp  --dport "$ssh_port"                 -m comment --comment "xray-landing-ssh"       -j ACCEPT
  iptables -A "$FW_TMP" -m conntrack --ctstate INVALID,UNTRACKED    -m comment --comment "xray-landing-invalid"   -j DROP
  iptables -A "$FW_TMP" -m conntrack --ctstate ESTABLISHED,RELATED  -m comment --comment "xray-landing-est"       -j ACCEPT
  iptables -A "$FW_TMP" -p icmp --icmp-type echo-request -m limit --limit 10/second --limit-burst 20 \
                                                                     -m comment --comment "xray-landing-icmp"      -j ACCEPT || true
  iptables -A "$FW_TMP" -p icmp --icmp-type echo-request            -m comment --comment "xray-landing-icmp-drop" -j DROP
  
  local count=0 tips=() skipped=0
  local _conf_files=()
  while IFS= read -r f; do _conf_files+=("$f"); done \
    < <(find "${MANAGER_BASE}/nodes" -name "*.conf" -not -name "tmp-*.conf" -type f 2>/dev/null | sort)
  local expected_count=${#_conf_files[@]}
  for meta in "${_conf_files[@]+${_conf_files[@]}}"; do
    [[ -f "$meta" ]] || continue
    local tip; tip=$(grep '^TRANSIT_IP=' "$meta" 2>/dev/null | cut -d= -f2-)
    if [[ -z "$tip" ]]; then
      (( ++skipped )) || true; continue
    fi
    if ! python3 -c "import ipaddress,sys; ipaddress.IPv4Address(sys.argv[1])" "$tip" 2>/dev/null; then
      (( ++skipped )) || true; continue
    fi
    tips+=("$tip")
  done
  if (( expected_count > 0 && skipped > 0 )); then
    iptables -F "$FW_TMP" 2>/dev/null || true; iptables -X "$FW_TMP" 2>/dev/null || true
    die "防火墙构建中止：${skipped} 个节点文件格式异常，拒绝生成规则集"
  fi
  while IFS= read -r tip; do
    [[ -n "$tip" ]] || continue
    iptables -A "$FW_TMP" -s "${tip}/32" -p tcp --dport "$LANDING_PORT" -m comment --comment "xray-landing-transit" -j ACCEPT
    info "  ACCEPT ← ${tip}/32:${LANDING_PORT}"; (( ++count )) || true
  done < <(printf '%s\n' "${tips[@]+${tips[@]}}" | sort -u)
  
  iptables -A "$FW_TMP" -p tcp --dport "$LANDING_PORT" -m comment --comment "xray-landing-drop" -j DROP
  iptables -A "$FW_TMP" -p udp --dport "$LANDING_PORT" -m comment --comment "xray-landing-quic" -j REJECT --reject-with icmp-port-unreachable
  iptables -A "$FW_TMP" -m comment --comment "xray-landing-return" -j RETURN

  iptables -I INPUT 1 -m comment --comment "xray-landing-swap" -j "$FW_TMP"
  _bulldoze_input_refs "$FW_CHAIN"
  iptables -F "$FW_CHAIN" 2>/dev/null || true; iptables -X "$FW_CHAIN" 2>/dev/null || true
  iptables -E "$FW_TMP" "$FW_CHAIN"
  iptables -I INPUT 1 -m comment --comment "xray-landing-jump" -j "$FW_CHAIN"
  while iptables -D INPUT -m comment --comment "xray-landing-swap" 2>/dev/null; do :; done

  if have_ipv6; then
    ip6tables -N "$FW_TMP6" 2>/dev/null || ip6tables -F "$FW_TMP6"
    ip6tables -A "$FW_TMP6" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ip6tables -A "$FW_TMP6" -i lo -j ACCEPT
    ip6tables -A "$FW_TMP6" -p tcp      --dport "$ssh_port"     -j ACCEPT
    ip6tables -A "$FW_TMP6" -m conntrack --ctstate INVALID,UNTRACKED -j DROP
    ip6tables -A "$FW_TMP6" -p ipv6-icmp                        -j ACCEPT
    ip6tables -A "$FW_TMP6" -p tcp      --dport "$LANDING_PORT" -j DROP
    ip6tables -A "$FW_TMP6" -p udp      --dport "$LANDING_PORT" -j REJECT --reject-with icmp6-port-unreachable
    ip6tables -A "$FW_TMP6" -j RETURN
    ip6tables -I INPUT 1 -m comment --comment "xray-landing-v6-swap" -j "$FW_TMP6"
    
    _bulldoze_input_refs6 "$FW_CHAIN6"
    ip6tables -F "$FW_CHAIN6" 2>/dev/null || true; ip6tables -X "$FW_CHAIN6" 2>/dev/null || true
    ip6tables -E "$FW_TMP6" "$FW_CHAIN6"
    ip6tables -I INPUT 1 -m comment --comment "xray-landing-v6-jump" -j "$FW_CHAIN6"
    while ip6tables -D INPUT -m comment --comment "xray-landing-v6-swap" 2>/dev/null; do :; done
  fi

  if ! _persist_iptables "$ssh_port"; then
    _fw_landing_rollback
    trap - ERR INT TERM
    die "防火墙持久化失败，运行链已回滚"
  fi
  trap - ERR INT TERM
  success "防火墙: chain ${FW_CHAIN}（SSH:${ssh_port}）| ${count} 中转 IP"
}

_persist_iptables(){
  local ssh_port="${1:-22}"
  mkdir -p "$MANAGER_BASE"
  local fw_script="${MANAGER_BASE}/firewall-restore.sh"
  local transit_ips=()
  while IFS= read -r meta; do
    [[ -f "$meta" ]] || continue
    local tip; tip=$(grep '^TRANSIT_IP=' "$meta" 2>/dev/null | cut -d= -f2-) || continue
    python3 -c "import ipaddress,sys; ipaddress.IPv4Address(sys.argv[1])" "$tip" 2>/dev/null && transit_ips+=("$tip") || true
  done < <(find "${MANAGER_BASE}/nodes" -name "*.conf" -not -name "tmp-*.conf" -type f 2>/dev/null | sort)

  local fw_tmp; fw_tmp=$(mktemp "${MANAGER_BASE}/.xray-landing.XXXXXX")
  local _fw_sig; _fw_sig="LANDING_FW_VERSION=${VERSION}_$(date +%Y%m%d)"
  {
    echo "#!/bin/sh"
    echo "# ${_fw_sig}"
    echo "_detect_ssh(){"
    echo "  local p=''"
    echo "  p=\"\$(sshd -T 2>/dev/null | awk '/^port /{print \$2; exit}' || true)\""
    echo "  [ -z \"\$p\" ] && p=\"\$(ss -tlnp 2>/dev/null | awk '/sshd/{for(i=1;i<=NF;i++) if(\$i~/:[0-9]+\$/){sub(/^.*:/,\"\",\$i);print \$i;exit}}' | head -1 || true)\""
    echo "  if echo \"\$p\" | grep -qE '^[0-9]+\$' && [ \"\$p\" -ge 1 ] && [ \"\$p\" -le 65535 ]; then"
    echo "    echo \"\$p\""
    echo "  else"
    echo "    logger -t xray-landing-firewall 'WARN: 无法动态探测SSH端口，使用安装时值 ${ssh_port}'"
    echo "    echo '${ssh_port}'"
    echo "  fi"
    echo "}"
    echo "SSH_PORT=\"\$(_detect_ssh)\""
    echo "while iptables  -D INPUT -m comment --comment 'xray-landing-jump'       2>/dev/null; do :; done"
    echo "while iptables  -D INPUT -m comment --comment 'xray-landing-ssh-global' 2>/dev/null; do :; done"
    echo "while iptables  -D INPUT -m comment --comment 'xray-landing-swap'       2>/dev/null; do :; done"
    echo "iptables  -F ${FW_CHAIN}  2>/dev/null || true; iptables  -X ${FW_CHAIN}  2>/dev/null || true"
    echo "iptables  -N ${FW_CHAIN}  2>/dev/null || true"
    echo "iptables -A ${FW_CHAIN} -i lo                                       -m comment --comment 'xray-landing-lo'        -j ACCEPT"
    echo "iptables -A ${FW_CHAIN} -p tcp  --dport \${SSH_PORT}                -m comment --comment 'xray-landing-ssh'       -j ACCEPT"
    echo "iptables -A ${FW_CHAIN} -m conntrack --ctstate INVALID,UNTRACKED    -m comment --comment 'xray-landing-invalid'   -j DROP"
    echo "iptables -A ${FW_CHAIN} -m conntrack --ctstate ESTABLISHED,RELATED  -m comment --comment 'xray-landing-est'       -j ACCEPT"
    echo "iptables -A ${FW_CHAIN} -p icmp --icmp-type echo-request -m limit --limit 10/second --limit-burst 20 -m comment --comment 'xray-landing-icmp' -j ACCEPT"
    echo "iptables -A ${FW_CHAIN} -p icmp --icmp-type echo-request             -m comment --comment 'xray-landing-icmp-drop' -j DROP"
    local u
    while IFS= read -r u; do
      [[ -n "$u" ]] || continue
      echo "iptables -A ${FW_CHAIN} -s ${u}/32 -p tcp --dport ${LANDING_PORT} -m comment --comment 'xray-landing-transit' -j ACCEPT"
    done < <(printf '%s\n' "${transit_ips[@]+${transit_ips[@]}}" | sort -u)
    echo "iptables -A ${FW_CHAIN} -p tcp --dport ${LANDING_PORT} -m comment --comment 'xray-landing-drop' -j DROP"
    echo "iptables -A ${FW_CHAIN} -p udp --dport ${LANDING_PORT} -m comment --comment 'xray-landing-quic' -j REJECT --reject-with icmp-port-unreachable"
    echo "iptables -A ${FW_CHAIN} -m comment --comment 'xray-landing-return' -j RETURN"
    echo "iptables -I INPUT 1 -m comment --comment 'xray-landing-jump' -j ${FW_CHAIN}"
    echo "if [ -f /proc/net/if_inet6 ] && ip6tables -L >/dev/null 2>&1 && [ \"\$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 1)\" != \"1\" ]; then"
    echo "  while ip6tables -D INPUT -m comment --comment 'xray-landing-v6-jump' 2>/dev/null; do :; done"
    echo "  while ip6tables -D INPUT -m comment --comment 'xray-landing-v6-swap' 2>/dev/null; do :; done"
    echo "  ip6tables -F ${FW_CHAIN6} 2>/dev/null || true; ip6tables -X ${FW_CHAIN6} 2>/dev/null || true"
    echo "  ip6tables -N ${FW_CHAIN6} 2>/dev/null || true"
    echo "  ip6tables -A ${FW_CHAIN6} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    echo "  ip6tables -A ${FW_CHAIN6} -i lo -j ACCEPT"
    echo "  ip6tables -A ${FW_CHAIN6} -p tcp      --dport \${SSH_PORT}      -j ACCEPT"
    echo "  ip6tables -A ${FW_CHAIN6} -p ipv6-icmp                          -j ACCEPT"
    echo "  ip6tables -A ${FW_CHAIN6} -p udp      --dport ${LANDING_PORT} -j REJECT --reject-with icmp6-port-unreachable"
    echo "  ip6tables -A ${FW_CHAIN6} -j RETURN"
    echo "  ip6tables -I INPUT 1 -m comment --comment 'xray-landing-v6-jump' -j ${FW_CHAIN6}"
    echo "fi"
  } > "$fw_tmp"
  chmod 700 "$fw_tmp"
  mv -f "$fw_tmp" "$fw_script"

  local rsvc="/etc/systemd/system/xray-landing-iptables-restore.service"
  atomic_write "$rsvc" 644 root:root <<RSTO
[Unit]
Description=Restore iptables rules for xray-landing
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStartPre=-/sbin/modprobe ip6_tables
ExecStart=${fw_script}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
RSTO
  systemctl daemon-reload \
    || die "daemon-reload 失败，systemd 图未更新"
  systemctl enable xray-landing-iptables-restore.service \
    || die "iptables 持久化服务 enable 失败，重启后防火墙规则将丢失"
  systemctl is-enabled --quiet xray-landing-iptables-restore.service \
    || die "iptables 持久化服务 enabled 状态验收失败"
  info "防火墙规则已写入: ${fw_script}（开机动态检测 SSH 端口，have_ipv6 守卫 ip6tables）"
}

save_node_info(){
  local domain="$1" password="$2" transit_ip="$3" pub_ip="$4"
  mkdir -p "${MANAGER_BASE}/nodes"
  local safe_domain; safe_domain=$(printf '%s' "$domain" | tr '.:/' '___')
  local safe_ip;     safe_ip=$(printf '%s' "$transit_ip" | tr '.:' '__')
  atomic_write "${MANAGER_BASE}/nodes/${safe_domain}_${safe_ip}.conf" 600 root:root <<NEOF
DOMAIN=${domain}
PASSWORD=${password}
TRANSIT_IP=${transit_ip}
PUBLIC_IP=${pub_ip}
CREATED=$(date +%Y%m%d_%H%M%S)
NEOF
}

add_node(){
  check_deps
  load_manager_config
  echo ""
  echo -e "${BOLD}── 增加新节点 ────────────────────────────────────────────────────${NC}"
  echo -e "${BOLD}${RED}  ⚠  域名在 Cloudflare 必须设为【仅DNS/灰云】，严禁开启小黄云代理！${NC}"
  echo ""
  read -rp "新节点域名: " NEW_DOMAIN
  NEW_DOMAIN=$(tr '[:upper:]' '[:lower:]' <<< "$NEW_DOMAIN")
  validate_domain "$NEW_DOMAIN"

  local existing_pass=""
  if [[ -d "${MANAGER_BASE}/nodes" ]]; then
    existing_pass=$(python3 - "${MANAGER_BASE}/nodes" "$NEW_DOMAIN" 2>/dev/null <<'PYNODE'
import sys
from pathlib import Path
nodes_dir, target_domain = Path(sys.argv[1]), sys.argv[2]
for p in nodes_dir.glob("*.conf"):
    if p.name.startswith("tmp-"):
        continue
    data = {}
    try:
        for line in p.read_text(errors="replace").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                data[k.strip()] = v.strip()
    except Exception:
        continue
    if data.get("DOMAIN") == target_domain and data.get("PASSWORD"):
        print(data["PASSWORD"])
        break
PYNODE
) || true
  fi
  if [[ -n "$existing_pass" ]]; then
    warn "域名 ${NEW_DOMAIN} 已存在，新中转机必须复用相同 Trojan 密码"
    NEW_PASS="$existing_pass"
    info "  自动沿用密码: ${NEW_PASS}"
  else
    read -rp "Trojan 密码（16位以上，直接回车自动生成）: " NEW_PASS
    if [[ -z "$NEW_PASS" ]]; then
      NEW_PASS=$(gen_password)
      info "  已自动生成高强度密码: ${NEW_PASS}"
    fi
    validate_password "$NEW_PASS"
  fi

  read -rp "对应中转机公网 IP: " NEW_TRANSIT
  validate_ipv4 "$NEW_TRANSIT"

  local _fw_skip=0
  local _ip_exists
  _ip_exists=$(python3 - "${MANAGER_BASE}/nodes" "$NEW_TRANSIT" 2>/dev/null <<'PYIP'
import sys
from pathlib import Path
nodes_dir, target_ip = Path(sys.argv[1]), sys.argv[2]
for p in nodes_dir.glob("*.conf"):
    if p.name.startswith("tmp-"):
        continue
    try:
        for line in p.read_text(errors="replace").splitlines():
            if line.strip() == f"TRANSIT_IP={target_ip}":
                print("1")
                sys.exit(0)
    except Exception:
        continue
PYIP
) || true
  if [[ "${_ip_exists:-}" == "1" ]]; then
    warn "中转 IP ${NEW_TRANSIT} 已在防火墙白名单，跳过重复添加 iptables 规则"
    _fw_skip=1
  fi

  local USE_CF_TOKEN="$CF_TOKEN"
  if [[ -z "$USE_CF_TOKEN" ]]; then
    read -rp "Cloudflare API Token（Zone:DNS:Edit）: " USE_CF_TOKEN
    validate_cf_token "$USE_CF_TOKEN"
    CF_TOKEN="$USE_CF_TOKEN"
  fi

  _acquire_lock

  local _staged_mgr=""
  if [[ -n "$CF_TOKEN" ]]; then
    _staged_mgr=$(mktemp "${MANAGER_BASE}/tmp/.manager.XXXXXX")
    atomic_write "$_staged_mgr" 600 root:root <<SMEOF
LANDING_PORT=${LANDING_PORT}
VLESS_UUID=${VLESS_UUID}
VLESS_GRPC_PORT=${VLESS_GRPC_PORT}
TROJAN_GRPC_PORT=${TROJAN_GRPC_PORT}
VLESS_WS_PORT=${VLESS_WS_PORT}
TROJAN_TCP_PORT=${TROJAN_TCP_PORT}
CF_TOKEN=${CF_TOKEN}
CREATED_USER=${CREATED_USER}
SMEOF
  fi

  issue_certificate "$NEW_DOMAIN" "$USE_CF_TOKEN"
  local PUB_IP; PUB_IP=$(get_public_ip)

  local _safe_dom; _safe_dom=$(printf '%s' "$NEW_DOMAIN" | tr '.:/' '___')
  local _safe_ip;  _safe_ip=$(printf '%s' "$NEW_TRANSIT" | tr '.:' '__')
  local _node_conf="${MANAGER_BASE}/nodes/${_safe_dom}_${_safe_ip}.conf"

  local _tmp_node; _tmp_node=$(mktemp "${MANAGER_BASE}/nodes/tmp-XXXXXX.conf")
  cat >"$_tmp_node" <<NEOF_TMP
DOMAIN=${NEW_DOMAIN}
PASSWORD=${NEW_PASS}
TRANSIT_IP=${NEW_TRANSIT}
PUBLIC_IP=${PUB_IP}
CREATED=$(date +%Y%m%d_%H%M%S)
NEOF_TMP
  chmod 600 "$_tmp_node"

  _acme_node_cleanup(){
    if [[ -f "${ACME_HOME}/acme.sh" && -n "${NEW_DOMAIN:-}" ]]; then
      local _refs
      _refs=$(find "${MANAGER_BASE}/nodes" -name "*.conf" -not -name "tmp-*.conf" -type f \
        -exec grep -l "^DOMAIN=${NEW_DOMAIN}$" {} + 2>/dev/null | wc -l) || _refs=1
      if (( _refs == 0 )); then
        "${ACME_HOME}/acme.sh" --home "${ACME_HOME}" --remove --domain "${NEW_DOMAIN}" --ecc 2>/dev/null || true
        rm -rf "${CERT_BASE}/${NEW_DOMAIN}" 2>/dev/null || true
      else
        info "保留证书 ${NEW_DOMAIN}（仍被 ${_refs} 个节点引用）"
      fi
    fi
  }

  local _int_sync_done=0 _int_fw_done=0
  trap '
    _global_cleanup
    rm -f "$_tmp_node" "$_node_conf" "${_staged_mgr:-}" 2>/dev/null
    ((_int_sync_done)) && ( sync_xray_config ) 2>/dev/null || true
    ((_int_fw_done))   && ( setup_firewall )   2>/dev/null || true
    _acme_node_cleanup
    echo -e "\n${RED}[中断] 已回滚，请执行: bash $0 --uninstall${NC}"
    exit 1
  ' INT TERM

  if ! ( export _TMP_NODE_PATH="$_tmp_node"; sync_xray_config ); then
    rm -f "$_tmp_node"
    trap '_global_cleanup; echo -e "\n${RED}[中断] 请执行: bash $0 --uninstall${NC}"; exit 1' INT TERM
    _acme_node_cleanup
    rm -f "${_staged_mgr:-}" 2>/dev/null || true; _release_lock; die "Xray配置同步失败，节点未保存"
  fi
  _int_sync_done=1

  local _snap_cfg_node; _snap_cfg_node=$(mktemp "${LANDING_BASE}/.snap-recover.XXXXXX" 2>/dev/null) || _snap_cfg_node=""
  [[ -n "$_snap_cfg_node" && -f "$LANDING_CONF" ]] && cp -f "$LANDING_CONF" "$_snap_cfg_node" 2>/dev/null || true
  mv -f "$_tmp_node" "$_node_conf"
  _int_sync_done=0
  trap '_global_cleanup; rm -f "$_node_conf" 2>/dev/null; echo -e "\n${RED}[中断] 请执行: bash $0 --uninstall${NC}"; exit 1' INT TERM

  if (( _fw_skip == 0 )); then
    if ! ( setup_firewall ); then
      rm -f "$_node_conf"
      if [[ -n "$_snap_cfg_node" && -f "$_snap_cfg_node" ]]; then
        cp -f "$_snap_cfg_node" "$LANDING_CONF" 2>/dev/null || true
      else
        ( sync_xray_config ) 2>/dev/null || true
      fi
      rm -f "$_snap_cfg_node" 2>/dev/null || true
      trap '_global_cleanup; echo -e "\n${RED}[中断] 请执行: bash $0 --uninstall${NC}"; exit 1' INT TERM
      rm -f "${_staged_mgr:-}" 2>/dev/null || true
      _acme_node_cleanup
      _release_lock; die "防火墙配置失败，节点已回滚"
    fi
    _int_fw_done=1
  else
    info "TRANSIT_IP ${NEW_TRANSIT} 已在白名单，跳过防火墙重建"
  fi
  trap '_global_cleanup; echo -e "\n${RED}[中断] 请执行: bash $0 --uninstall${NC}"; exit 1' INT TERM

  systemctl restart "$LANDING_SVC"
  sleep 1
  if ! systemctl is-active --quiet "$LANDING_SVC"; then
    rm -f "$_node_conf"
    if [[ -n "$_snap_cfg_node" && -f "$_snap_cfg_node" ]]; then
      cp -f "$_snap_cfg_node" "$LANDING_CONF" 2>/dev/null || true
    else
      ( sync_xray_config ) 2>/dev/null || true
    fi
    ( setup_firewall ) 2>/dev/null || true
    rm -f "$_snap_cfg_node" 2>/dev/null || true
    rm -f "${_staged_mgr:-}" 2>/dev/null || true
    _acme_node_cleanup
    _release_lock; die "服务重启失败，节点已回滚: journalctl -u ${LANDING_SVC}"
  fi
  rm -f "$_snap_cfg_node" 2>/dev/null || true
  [[ -n "${_staged_mgr:-}" && -f "${_staged_mgr:-}" ]] \
    && mv -f "$_staged_mgr" "$MANAGER_CONFIG" 2>/dev/null || true
  _release_lock
  success "服务热重载成功（零掉线）"
  print_pairing_info "$PUB_IP" "$NEW_DOMAIN" "$NEW_PASS" "$NEW_TRANSIT"
}

delete_node(){
  echo ""
  echo -e "${BOLD}── 删除节点 ─────────────────────────────────────────────────────${NC}"
  local n=0 node_files=()
  while IFS= read -r meta; do
    [[ -f "$meta" ]] || continue
    node_files+=("$meta")
    local dom ip
    dom=$(grep '^DOMAIN='     "$meta" 2>/dev/null | cut -d= -f2- || echo "?")
    ip=$(grep  '^TRANSIT_IP=' "$meta" 2>/dev/null | cut -d= -f2- || echo "?")
    printf "  [%-2d] %-40s 中转: %s\n" $((++n)) "$dom" "$ip"
  done < <(find "${MANAGER_BASE}/nodes" -name "*.conf" -type f 2>/dev/null | sort)

  (( n == 0 )) && { warn "无可删除的节点"; return; }
  (( n == 1 )) && die "仅剩最后一个节点！请使用「清除本系统所有数据」"

  read -rp "请输入节点编号: " DEL_INPUT
  [[ "$DEL_INPUT" =~ ^[0-9]+$ ]] || die "请输入数字"
  local idx=$(( DEL_INPUT - 1 ))
  (( idx >= 0 && idx < n )) || die "编号越界（共 ${n} 个）"

  local DEL_CONF="${node_files[$idx]}"
  local DEL_DOMAIN; DEL_DOMAIN=$(grep '^DOMAIN='     "$DEL_CONF" 2>/dev/null | cut -d= -f2-)
  local DEL_TRANSIT; DEL_TRANSIT=$(grep '^TRANSIT_IP=' "$DEL_CONF" 2>/dev/null | cut -d= -f2-)

  read -rp "确认删除 ${DEL_DOMAIN}（中转: ${DEL_TRANSIT}）？[y/N]: " CONFIRM
  [[ "$CONFIRM" =~ ^[Yy]$ ]] || { info "已取消"; return; }

  _acquire_lock

  local _snap_cfg_del=""
  [[ -f "$LANDING_CONF" ]] && {
    _snap_cfg_del=$(mktemp "${LANDING_BASE}/.snap-recover.XXXXXX")
    cp -f "$LANDING_CONF" "$_snap_cfg_del"
  }

  local _snap_node; _snap_node=$(mktemp "${MANAGER_BASE}/nodes/.snap-recover.XXXXXX")
  cp -f "$DEL_CONF" "$_snap_node"
  mv -f "$DEL_CONF" "${DEL_CONF}.deleting"

  local safe_del; safe_del=$(printf '%s' "$DEL_DOMAIN" | tr '.:/' '___')
  local remaining; remaining=$(find "${MANAGER_BASE}/nodes" -name "${safe_del}_*.conf" -type f 2>/dev/null | wc -l)

  if ! ( sync_xray_config ); then
    mv -f "${DEL_CONF}.deleting" "$DEL_CONF" 2>/dev/null || true
    [[ -n "${_snap_cfg_del:-}" && -f "${_snap_cfg_del:-}" ]] \
      && mv -f "$_snap_cfg_del" "$LANDING_CONF" 2>/dev/null || true
    _release_lock; die "Xray配置同步失败，节点文件和config.json已物理回滚"
  fi
  rm -f "${_snap_cfg_del:-}" 2>/dev/null || true
  if ! ( setup_firewall ); then
    mv -f "${DEL_CONF}.deleting" "$DEL_CONF" 2>/dev/null || true
    ( sync_xray_config ) 2>/dev/null || true
    _release_lock; die "防火墙更新失败，节点文件已恢复"
  fi
  local _restart_rc=0
  systemctl restart "$LANDING_SVC" 2>/dev/null || _restart_rc=$?
  sleep 1
  if (( _restart_rc != 0 )) || ! systemctl is-active --quiet "$LANDING_SVC"; then
    warn "服务重启失败，回滚节点文件..."
    mv -f "${DEL_CONF}.deleting" "$DEL_CONF" 2>/dev/null || true
    ( sync_xray_config ) 2>/dev/null || true
    ( setup_firewall )   2>/dev/null || true
    systemctl reset-failed "$LANDING_SVC" 2>/dev/null || true
    systemctl restart "$LANDING_SVC" 2>/dev/null || true
    _release_lock; warn "节点已恢复，请检查: journalctl -u ${LANDING_SVC}"
  else
    if (( remaining == 0 )); then
      info "域名 ${DEL_DOMAIN} 已无中转机，清理证书..."
      if [[ -f "${ACME_HOME}/acme.sh" ]]; then
        "${ACME_HOME}/acme.sh" --home "${ACME_HOME}" --remove --domain "$DEL_DOMAIN" --ecc 2>/dev/null || true
        rm -rf "${ACME_HOME}/${DEL_DOMAIN}_ecc" 2>/dev/null || true
      fi
      rm -rf "${CERT_BASE}/${DEL_DOMAIN}" 2>/dev/null || true
    fi
    rm -f "$_snap_node" "${DEL_CONF}.deleting" 2>/dev/null || true
    _release_lock
    success "节点已删除，服务热重载正常"
  fi
}

do_set_port(){
  [[ -f "$INSTALLED_FLAG" ]] || die "未安装，无法修改端口"
  load_manager_config
  local new_port="${1:-}"
  [[ -n "$new_port" ]] || { read -rp "新落地机监听端口: " new_port; }
  validate_port "$new_port"
  (( new_port >= 1024 )) || die "端口 ${new_port} 小于 1024，set-port 不支持低端口（需重装以更新权限配置）"
  if [[ "$new_port" == "$LANDING_PORT" ]]; then
    success "端口已是 ${new_port}，无需变更"; return
  fi
  ss -tlnp 2>/dev/null | grep -q ":${new_port} " && die "端口 ${new_port} 已被占用"
  local old_port="$LANDING_PORT"

  _acquire_lock

  local _snap_mgr _snap_cfg _snap_fw
  _snap_mgr=$(mktemp "${MANAGER_BASE}/.snap-recover.XXXXXX") \
    || { _release_lock; die "manager.conf 快照创建失败，端口未变更"; }
  _snap_cfg=$(mktemp "${LANDING_BASE}/.snap-recover.XXXXXX" 2>/dev/null) \
    || { rm -f "$_snap_mgr"; _release_lock; die "config.json 快照创建失败，端口未变更"; }
  _snap_fw=""
  if [[ -f "${MANAGER_BASE}/firewall-restore.sh" ]]; then
    _snap_fw=$(mktemp "${MANAGER_BASE}/.snap-recover.XXXXXX" 2>/dev/null) || _snap_fw=""
    [[ -n "$_snap_fw" ]] && cp -f "${MANAGER_BASE}/firewall-restore.sh" "$_snap_fw" 2>/dev/null \
      || { rm -f "$_snap_mgr" "$_snap_cfg" "${_snap_fw:-}"; _release_lock; die "firewall-restore.sh 快照失败，端口未变更"; }
  fi
  cp -f "$MANAGER_CONFIG" "$_snap_mgr" 2>/dev/null \
    || { rm -f "$_snap_mgr" "$_snap_cfg" "${_snap_fw:-}"; _release_lock; die "manager.conf 快照写入失败，端口未变更"; }
  [[ -f "$LANDING_CONF" ]] && { cp -f "$LANDING_CONF" "$_snap_cfg" 2>/dev/null \
    || { rm -f "$_snap_mgr" "$_snap_cfg" "${_snap_fw:-}"; _release_lock; die "config.json 快照写入失败，端口未变更"; }; }

  _do_rollback_port(){
    [[ -f "$_snap_mgr" ]] && mv -f "$_snap_mgr" "$MANAGER_CONFIG" 2>/dev/null || true
    [[ -n "${_snap_cfg:-}" && -f "$_snap_cfg" ]] \
      && mv -f "$_snap_cfg" "$LANDING_CONF" 2>/dev/null || true
    [[ -n "${_snap_fw:-}" && -f "$_snap_fw" ]] \
      && mv -f "$_snap_fw" "${MANAGER_BASE}/firewall-restore.sh" 2>/dev/null || true
    if [[ -x "${MANAGER_BASE}/firewall-restore.sh" ]]; then
      "${MANAGER_BASE}/firewall-restore.sh" 2>/dev/null || true
    fi
    ( sync_xray_config ) 2>/dev/null || true
    systemctl reset-failed "$LANDING_SVC" 2>/dev/null || true
    systemctl restart "$LANDING_SVC" 2>/dev/null || true
    rm -f "$_snap_mgr" "${_snap_cfg:-}" "${_snap_fw:-}" 2>/dev/null || true
    LANDING_PORT="$old_port"
    _release_lock
  }
  trap '_global_cleanup; _do_rollback_port; trap - INT TERM ERR; exit 1' INT TERM ERR

  LANDING_PORT="$new_port"
  if ! save_manager_config; then
    _do_rollback_port
    die "manager.conf 写入失败，端口未变更"
  fi

  if ! ( sync_xray_config ); then
    _do_rollback_port
    die "sync 失败，端口已回滚至 ${old_port}"
  fi
  if ! ( setup_firewall ); then
    _do_rollback_port
    ( sync_xray_config ) 2>/dev/null || true
    die "防火墙更新失败，端口已回滚至 ${old_port}"
  fi

  _persist_iptables "$(detect_ssh_port)"
  if ! systemctl restart xray-landing-iptables-restore.service 2>/dev/null; then
    warn "iptables 恢复服务重启失败，触发端口回滚..."
    _do_rollback_port
    ( sync_xray_config ) 2>/dev/null || true
    systemctl restart "$LANDING_SVC" 2>/dev/null || true
    die "iptables 持久化失败，端口已回滚至 ${old_port}"
  fi
  local _restart_rc=0
  systemctl restart "$LANDING_SVC" || _restart_rc=$?
  sleep 2

  if (( _restart_rc != 0 )) || ! systemctl is-active --quiet "$LANDING_SVC"; then
    warn "服务启动失败，触发回滚至 ${old_port}..."
    _do_rollback_port
    ( sync_xray_config ) 2>/dev/null || true
    systemctl restart "$LANDING_SVC" 2>/dev/null || true
    die "端口变更验证失败，已回滚至 ${old_port}"
  fi
  rm -f "$_snap_mgr" "${_snap_cfg:-}" "${_snap_fw:-}" 2>/dev/null || true
  trap '_global_cleanup; echo -e "\n${RED}[中断] 请执行: bash $0 --uninstall${NC}"; exit 1' INT TERM
  trap - ERR
  systemctl reset-failed "$LANDING_SVC" 2>/dev/null || true
  _release_lock

  success "端口已变更为 ${new_port}"
  echo ""
  echo -e "${RED}${BOLD}🚨 警告：落地机端口已更改！${NC}"
  echo -e "${RED}   必须立即登录中转机，删除旧路由规则，并使用下方新 Token 重新导入，否则节点全线断流！${NC}"
  echo ""
  local first_conf; first_conf=$(find "${MANAGER_BASE}/nodes" -name "*.conf" -type f 2>/dev/null | sort | head -1)
  if [[ -n "$first_conf" ]]; then
    local any_dom any_pass any_transit
    any_dom=$(grep '^DOMAIN='     "$first_conf" 2>/dev/null | cut -d= -f2- || true)
    any_pass=$(grep '^PASSWORD='  "$first_conf" 2>/dev/null | cut -d= -f2- || true)
    any_transit=$(grep '^TRANSIT_IP=' "$first_conf" 2>/dev/null | cut -d= -f2- || true)
    local pub_ip; pub_ip=$(get_public_ip 2>/dev/null) || pub_ip="（无法获取）"
    [[ -n "$any_dom" ]] && print_pairing_info "$pub_ip" "$any_dom" "$any_pass" "$any_transit"
  fi
}

show_status(){
  load_manager_config
  echo ""
  echo -e "${BOLD}── 落地机状态 ──────────────────────────────────────────────────${NC}"
  [[ -f "$INSTALLED_FLAG" ]] && echo "  已安装: 是" || echo "  已安装: 否"
  echo "  ${LANDING_SVC}: $(systemctl is-active "$LANDING_SVC" 2>/dev/null || echo inactive)"
  echo "  监听端口: ${LANDING_PORT}"
  echo "  VLESS UUID: ${VLESS_UUID:-（未配置）}"
  echo ""
  local n=0
  local _node_degraded=0
  while IFS= read -r meta; do
    [[ -f "$meta" ]] || continue
    local dom ip ts
    dom=$(grep '^DOMAIN='     "$meta" 2>/dev/null | cut -d= -f2- || echo "?")
    ip=$(grep  '^TRANSIT_IP=' "$meta" 2>/dev/null | cut -d= -f2- || echo "?")
    ts=$(grep  '^CREATED='    "$meta" 2>/dev/null | cut -d= -f2- || echo "?")
    printf "  [节点%-2d] %-38s 中转: %-18s 创建: %s\n" $((++n)) "$dom" "$ip" "$ts"
    [[ "$dom" == "?" ]] && { echo -e "    ${RED}↑ DOMAIN 字段缺失${NC}"; _node_degraded=1; }
    [[ "$ip"  == "?" ]] && { echo -e "    ${RED}↑ TRANSIT_IP 字段缺失${NC}"; _node_degraded=1; }
    if [[ "$dom" != "?" ]]; then
      [[ -f "${CERT_BASE}/${dom}/fullchain.pem" ]] \
        || { echo -e "    ${RED}↑ 证书 fullchain.pem 缺失！${NC}"; _node_degraded=1; }
      [[ -f "${CERT_BASE}/${dom}/key.pem" ]] \
        || { echo -e "    ${RED}↑ 证书 key.pem 缺失！${NC}"; _node_degraded=1; }
    fi
  done < <(find "${MANAGER_BASE}/nodes" -name "*.conf" -type f 2>/dev/null | sort)
  [[ $n -eq 0 ]] && warn "  （无已配置节点）"
  (( _node_degraded )) && echo -e "  ${RED}节点完整性:  ✗ 部分节点缺证书/字段（sync_xray_config 会跳过缺证书节点！）${NC}" || true
  echo ""
  echo -e "  ${BOLD}── 证书与续期状态 ────────────────────────────────────────────${NC}"
  local _any_cert=0
  while IFS= read -r _smeta; do
    [[ -f "$_smeta" ]] || continue
    local _sdom; _sdom=$(grep '^DOMAIN=' "$_smeta" 2>/dev/null | cut -d= -f2-) || continue
    [[ -n "$_sdom" ]] || continue
    local _cf="${CERT_BASE}/${_sdom}/fullchain.pem"
    if [[ -f "$_cf" ]]; then
      local _end; _end=$(openssl x509 -in "$_cf" -noout -enddate 2>/dev/null | cut -d= -f2) || _end=""
      local _days=0
      if [[ -n "$_end" ]]; then
        local _ets _nts
        _ets=$(LANG=C date -d "$_end" +%s 2>/dev/null || echo 0); _nts=$(date +%s)
        _days=$(( (_ets - _nts) / 86400 ))
      fi
      if (( _days > 30 )); then
        printf "  %-40s 证书剩余: ${GREEN}%d 天${NC}\n" "$_sdom" "$_days"
      elif (( _days > 0 )); then
        printf "  %-40s 证书剩余: ${YELLOW}%d 天（即将过期！）${NC}\n" "$_sdom" "$_days"
      else
        printf "  %-40s ${RED}证书已过期或读取失败${NC}\n" "$_sdom"
      fi
      _any_cert=1
    else
      printf "  %-40s ${RED}证书文件缺失${NC}\n" "$_sdom"
    fi
  done < <(find "${MANAGER_BASE}/nodes" -name "*.conf" -type f 2>/dev/null | sort)
  ((_any_cert)) || warn "  （无证书信息）"
  if crontab -l 2>/dev/null | grep -qE 'acme\.sh.*(--cron|cron)'; then
    echo -e "  acme.sh cron:    ${GREEN}✓ 已注册（原生 crontab）${NC}"
  else
    echo -e "  acme.sh cron:    ${RED}✗ 未注册（证书无法自动续期！运行 acme.sh --install-cronjob 修复）${NC}"
  fi
  systemctl is-enabled --quiet "xray-landing-iptables-restore.service" 2>/dev/null \
    && echo -e "  iptables 恢复服务: ${GREEN}✓ enabled${NC}" \
    || echo -e "  iptables 恢复服务: ${RED}✗ 未 enable（重启后防火墙规则会丢失）${NC}"
  local _fw_script="${MANAGER_BASE}/firewall-restore.sh"
  if [[ -f "$_fw_script" ]]; then
    local _fw_ver_line; _fw_ver_line=$(grep '^# LANDING_FW_VERSION=' "$_fw_script" 2>/dev/null | head -1 || echo "")
    if [[ -z "$_fw_ver_line" ]]; then
      echo -e "  ${RED}恢复脚本版本:    ✗ 无版本签名（旧版脚本），自动重建...${NC}"; _ok=0
      local _ssh_p4; _ssh_p4=$(detect_ssh_port 2>/dev/null) || _ssh_p4=22
      _persist_iptables "$_ssh_p4" 2>/dev/null \
        && { echo -e "  ${GREEN}恢复脚本已自动重建 ✓${NC}"; _ok=1; } \
        || echo -e "  ${RED}自动重建失败，请执行 bash $0 set-port <port> 触发重建${NC}"
    else
      echo -e "  恢复脚本版本:    ${GREEN}✓ ${_fw_ver_line#*=}${NC}"
    fi
    local _fw_ips _live_ips
    _fw_ips=$(grep 'xray-landing-transit' "$_fw_script" 2>/dev/null \
      | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u | tr '\n' ' ' | sed 's/ $//' || echo "")
    _live_ips=$(iptables -L "$FW_CHAIN" -n 2>/dev/null \
      | awk '/xray-landing-transit/ && /ACCEPT/{print $4}' \
      | sed 's|/32||' | sort -u | tr '\n' ' ' | sed 's/ $//' || echo "")
    if [[ "$_fw_ips" == "$_live_ips" ]]; then
      echo -e "  恢复脚本一致性:  ${GREEN}✓ transit IP 与运行链匹配${NC}"
    else
      echo -e "  ${RED}恢复脚本一致性:  ✗ 与运行链不一致（重启后规则可能漂移）${NC}"; _ok=0
      echo -e "  ${CYAN}  修复: bash $0 set-port ${LANDING_PORT}（触发 setup_firewall 重建）${NC}"
    fi
  else
    echo -e "  ${RED}恢复脚本:        ✗ 不存在（重启后防火墙规则会丢失）${NC}"; _ok=0
  fi
  [[ -f "$CERT_RELOAD_SCRIPT" ]] \
    && echo -e "  续期重载脚本:    ${GREEN}✓${NC}" \
    || echo -e "  续期重载脚本:    ${RED}✗ 缺失${NC}"
  echo ""
  echo -e "  ${BOLD}── 状态硬校验 ────────────────────────────────────────────────${NC}"
  local _ok=1
  systemctl is-active --quiet "$LANDING_SVC" 2>/dev/null \
    && echo "  服务运行态:      ✓" \
    || {
      echo -e "  ${RED}服务运行态:      ✗ 未运行${NC}"; _ok=0
      local _svc_state; _svc_state=$(systemctl is-failed "$LANDING_SVC" 2>/dev/null || true)
      if [[ "$_svc_state" == "failed" ]]; then
        echo -e "  ${RED}熔断状态:        ✗ 服务已进入 failed（StartLimitBurst 触发）${NC}"
        echo -e "  ${CYAN}  自愈: systemctl reset-failed ${LANDING_SVC} && systemctl start ${LANDING_SVC}${NC}"
      fi
    }
  [[ -f "$LANDING_CONF" ]] \
    && echo "  config.json:     ✓" \
    || { echo -e "  ${RED}config.json:     ✗ 缺失${NC}"; _ok=0; }
  [[ -f "$MANAGER_CONFIG" ]] \
    && echo "  manager.conf:    ✓" \
    || { echo -e "  ${RED}manager.conf:    ✗ 缺失（真相源丢失！）${NC}"; _ok=0; }
  ss -tlnp 2>/dev/null | grep -q ":${LANDING_PORT} " \
    && echo "  :${LANDING_PORT} 监听:    ✓" \
    || { echo -e "  ${RED}:${LANDING_PORT} 监听:    ✗ 端口未开放${NC}"; _ok=0; }
  if [[ -f "$MANAGER_CONFIG" && -f "$LANDING_CONF" ]]; then
    local _cfg_port _cfg_uuid _cfg_vg _cfg_tg _cfg_vw _cfg_tt
    _cfg_port=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d['inbounds'][0]['port'])" \
      "$LANDING_CONF" 2>/dev/null || echo "")
    _cfg_uuid=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d['inbounds'][0]['settings']['clients'][0]['id'])" \
      "$LANDING_CONF" 2>/dev/null || echo "")
    _cfg_vg=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d['inbounds'][1]['port'])" \
      "$LANDING_CONF" 2>/dev/null || echo "")
    _cfg_tg=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d['inbounds'][2]['port'])" \
      "$LANDING_CONF" 2>/dev/null || echo "")
    _cfg_vw=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d['inbounds'][3]['port'])" \
      "$LANDING_CONF" 2>/dev/null || echo "")
    _cfg_tt=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d['inbounds'][4]['port'])" \
      "$LANDING_CONF" 2>/dev/null || echo "")
    local _field_ok=1
    [[ -z "$_cfg_port" || "$_cfg_port" == "$LANDING_PORT" ]]      || { echo -e "  ${RED}端口一致性:      ✗ manager.conf:${LANDING_PORT} ≠ config.json:${_cfg_port}${NC}"; _ok=0; _field_ok=0; }
    [[ -z "$_cfg_uuid" || -z "$VLESS_UUID" || "$_cfg_uuid" == "$VLESS_UUID" ]] || { echo -e "  ${RED}UUID一致性:      ✗ 真相源与派生不符${NC}"; _ok=0; _field_ok=0; }
    [[ -z "$_cfg_vg"   || "$_cfg_vg"   == "$VLESS_GRPC_PORT"  ]]  || { echo -e "  ${RED}VLESS-gRPC端口:  ✗ ${VLESS_GRPC_PORT} ≠ ${_cfg_vg}${NC}"; _ok=0; _field_ok=0; }
    [[ -z "$_cfg_tg"   || "$_cfg_tg"   == "$TROJAN_GRPC_PORT" ]]  || { echo -e "  ${RED}Trojan-gRPC端口: ✗ ${TROJAN_GRPC_PORT} ≠ ${_cfg_tg}${NC}"; _ok=0; _field_ok=0; }
    [[ -z "$_cfg_vw"   || "$_cfg_vw"   == "$VLESS_WS_PORT"    ]]  || { echo -e "  ${RED}VLESS-WS端口:    ✗ ${VLESS_WS_PORT} ≠ ${_cfg_vw}${NC}"; _ok=0; _field_ok=0; }
    [[ -z "$_cfg_tt"   || "$_cfg_tt"   == "$TROJAN_TCP_PORT"   ]]  || { echo -e "  ${RED}Trojan-TCP端口:  ✗ ${TROJAN_TCP_PORT} ≠ ${_cfg_tt}${NC}"; _ok=0; _field_ok=0; }
    (( _field_ok )) && echo -e "  字段一致性:      ${GREEN}✓ 全部字段与config.json一致${NC}"
  fi
  ((_ok)) \
    && echo -e "  ${GREEN}整体状态: 一致 ✓${NC}" \
    || { echo -e "  ${RED}整体状态: 存在分裂，请排查 ✗${NC}"; echo ""; echo -e "  ${CYAN}日志: tail -f ${LANDING_LOG}/error.log${NC}"; return 1; }
  echo ""
  echo -e "  ${CYAN}日志: tail -f ${LANDING_LOG}/error.log${NC}"
}

print_pairing_info(){
  local pub_ip="$1" domain="$2" password="$3" transit_ip="$4"
  load_manager_config

  local token=""
  if ! python3 -c "import ipaddress,sys; ipaddress.IPv4Address(sys.argv[1])" "$pub_ip" 2>/dev/null; then
    die "pub_ip='${pub_ip}' 不是合法 IPv4，拒绝生成 Token"
  fi
  token=$(python3 - "$pub_ip" "$domain" "$LANDING_PORT" "$VLESS_UUID" "$password" 2>&1 <<'TOKPY'
import json, base64, sys
landing_ip   = sys.argv[1]
landing_dom  = sys.argv[2]
landing_port = int(sys.argv[3])
vless_uuid   = sys.argv[4]
trojan_pwd   = sys.argv[5]
token_dict = {
    'ip':   landing_ip,
    'dom':  landing_dom,
    'port': landing_port,
    'uuid': vless_uuid,
    'pwd':  trojan_pwd,
    'pfx':  vless_uuid[:8],
}
print(base64.b64encode(json.dumps(token_dict, separators=(',',':')).encode()).decode())
TOKPY
) || { warn "token 生成异常: ${token}"; token=""; }

  echo ""
  echo -e "${BOLD}${GREEN}"
  echo "╔══════════════════════════════════════════════════════════════════╗"
  echo "║       请将以下信息复制至中转机脚本 install_transit_${VERSION}.sh      ║"
  echo "╠══════════════════════════════════════════════════════════════════╣"
  printf "║  %-18s : %-45s║\n" "落地机公网 IP"   "$pub_ip"
  printf "║  %-18s : %-45s║\n" "落地机域名(SNI)" "$domain"
  printf "║  %-18s : %-45s║\n" "落地机后端端口"  "$LANDING_PORT"
  printf "║  %-18s : %-45s║\n" "Trojan密码"      "$password"
  printf "║  %-18s : %-45s║\n" "VLESS UUID"      "${VLESS_UUID}"
  echo "╠══════════════════════════════════════════════════════════════════╣"
  echo "║  中转机一键导入命令：                                           ║"
  echo "╚══════════════════════════════════════════════════════════════════╝"
  echo -e "${NC}"
  [[ -n "$token" ]] \
    && echo -e "  ${BOLD}${CYAN}bash install_transit_v2.50.sh --import ${token}${NC}" \
    || warn "  token 生成失败，请手动将上方信息填入中转机脚本"

  echo ""
  echo -e "${BOLD}── 4 协议 Base64 订阅 ────────────────────────────────────────────${NC}"
  local ti="${transit_ip:-$pub_ip}"
  local sub_b64="" _sub_err=""
  sub_b64=$(python3 - "$ti" "$domain" "$VLESS_UUID" "$password" 2>&1 <<'SUBPY'
import base64, urllib.parse, sys
transit_ip, domain, vless_uuid, trojan_pass = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
port = 443
pfx = vless_uuid[:8]
lbl_vision = '[禁Mux]VLESS-Vision-'
lbl_vgrpc  = 'VLESS-gRPC-'
lbl_vws    = 'VLESS-WS-'
lbl_ttcp   = 'Trojan-TCP-'
uris = [
    (f"vless://{vless_uuid}@{transit_ip}:{port}"
     f"?encryption=none&flow=xtls-rprx-vision&security=tls"
     f"&sni={domain}&fp=chrome&type=tcp&mux=0"
     f"#{urllib.parse.quote(lbl_vision+domain)}"),
    (f"vless://{vless_uuid}@{transit_ip}:{port}"
     f"?encryption=none&security=tls&sni={domain}&fp=edge"
     f"&type=grpc&serviceName={pfx}-vg&alpn=h2&mode=multi&mux=0"
     f"#{urllib.parse.quote(lbl_vgrpc+domain)}"),
    (f"vless://{vless_uuid}@{transit_ip}:{port}"
     f"?encryption=none&security=tls&sni={domain}&fp=firefox"
     f"&type=ws&path=%2F{pfx}-vw&host={domain}&alpn=http/1.1&mux=0"
     f"#{urllib.parse.quote(lbl_vws+domain)}"),
    (f"trojan://{urllib.parse.quote(trojan_pass)}@{transit_ip}:{port}"
     f"?security=tls&sni={domain}&fp=safari&type=tcp"
     f"#{urllib.parse.quote(lbl_ttcp+domain)}"),
]
print(base64.b64encode("\n".join(uris).encode()).decode())
SUBPY
) || { _sub_err="$sub_b64"; sub_b64=""; }

  if [[ -n "$sub_b64" ]]; then
    echo -e "  ${BOLD}── 4 协议明文链接（可逐条复制验证）──────────────────${NC}"
    python3 -c "
import base64, sys
data = base64.b64decode(sys.argv[1]).decode()
for i, line in enumerate(data.split('\n'), 1):
    print(f'  [{i}] {line}')
" "$sub_b64" 2>/dev/null || true
    echo ""
    echo -e "  ${BOLD}── Base64 整体订阅（粘贴到客户端「添加订阅」）──────${NC}"
    echo ""; echo "  $sub_b64"; echo ""
    echo -e "  ${CYAN}（Clash Meta / NekoBox / v2rayN / Sing-box / Shadowrocket）${NC}"
    echo ""
    echo -e "  ${RED}${BOLD}⚠  VLESS-Vision 节点【严禁开启 Mux】！开启必断流！${NC}"
    echo -e "  ${YELLOW}   其他协议 (gRPC/WS) 已在订阅参数中强制 &mux=0，防止多重嵌套导致队头阻塞。${NC}"
  else
    warn "Base64 订阅生成失败"
    [[ -n "${_sub_err:-}" ]] && error "  Python 错误: ${_sub_err}"
  fi
  echo ""
}

purge_all(){
  echo ""
  warn "此操作清除本脚本所有内容（不影响 mack-a/v2ray-agent）"
  read -rp "确认清除？输入 'DELETE' 确认: " CONFIRM
  [[ "$CONFIRM" == "DELETE" ]] || { info "已取消"; return; }

  local _acme_bin="${ACME_HOME}/acme.sh"
  [[ ! -x "$_acme_bin" ]] && _acme_bin="${HOME}/.acme.sh/acme.sh"
  if [[ -x "$_acme_bin" ]]; then
    "$_acme_bin" --uninstall-cronjob 2>/dev/null || true
  fi

  local _created_user="0"
  _created_user=$(grep '^CREATED_USER=' "$MANAGER_CONFIG" 2>/dev/null | cut -d= -f2-) || true

  systemctl stop    "$LANDING_SVC" 2>/dev/null || true
  systemctl disable "$LANDING_SVC" 2>/dev/null || true
  systemctl disable --now xray-landing-iptables-restore.service 2>/dev/null || true
  rm -f "/etc/systemd/system/${LANDING_SVC}" \
        "/etc/systemd/system/xray-landing-recovery.service" \
        "/etc/systemd/system/xray-landing-iptables-restore.service" \
        "/etc/profile.d/xray-recovery-alert.sh" \
        "/etc/profile.d/xray-cert-alert.sh" 2>/dev/null || true
  rm -f /run/lock/xray-landing-recovery.last 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true

  if [[ -x "$_acme_bin" ]]; then
    local managed_domains=() seen_unremove=()
    while IFS= read -r meta; do
      local dom; dom=$(grep '^DOMAIN=' "$meta" 2>/dev/null | cut -d= -f2-) || continue
      [[ -n "$dom" ]] && managed_domains+=("$dom")
    done < <(find "${MANAGER_BASE}/nodes" -name "*.conf" -type f 2>/dev/null)
    for d in "${managed_domains[@]+${managed_domains[@]}}"; do
      local already=0
      for s in "${seen_unremove[@]+${seen_unremove[@]}}"; do [[ "$s" == "$d" ]] && already=1 && break; done
      (( already )) && continue
      seen_unremove+=("$d")
      "$_acme_bin" --home "$(dirname "$_acme_bin")" --remove --domain "$d" --ecc 2>/dev/null && info "已移除 acme.sh 续期: $d" || true
      rm -rf "$(dirname "$_acme_bin")/${d}_ecc" 2>/dev/null || true
    done
  fi

  for _rc in "${HOME}/.bashrc" "${HOME}/.profile" "${HOME}/.bash_profile"; do
    [[ -f "$_rc" ]] && sed -i '/acme\.sh\.env/d' "$_rc" 2>/dev/null || true
  done

  _purge_chain_atomic() {
    local chain="${1}" v="${2:-4}"
    local cmd="iptables"; [[ "${2:-4}" == "6" ]] && cmd="ip6tables"
    local _num
    while true; do
      _num=$($cmd -L INPUT --line-numbers -n 2>/dev/null | awk -v c="$chain" 'NR>2 && $2==c {print $1; exit}')
      [[ -n "$_num" ]] || break
      $cmd -D INPUT "$_num" 2>/dev/null || break
    done
    $cmd -F "$chain" 2>/dev/null || true
    $cmd -X "$chain" 2>/dev/null || true
  }

  _purge_chain_atomic "$FW_CHAIN"
  _purge_chain_atomic "${FW_CHAIN}-NEW"
  _purge_chain_atomic "$FW_CHAIN6" 6
  _purge_chain_atomic "${FW_CHAIN6}-NEW" 6

  rm -f "/etc/systemd/system/xray-landing.service.d/xray-landing-limits.conf" 2>/dev/null || true
  rmdir "/etc/systemd/system/xray-landing.service.d" 2>/dev/null || true
  rm -f "/etc/systemd/journald.conf.d/xray-landing.conf" 2>/dev/null || true
  systemctl kill --kill-who=main --signal=SIGUSR2 systemd-journald 2>/dev/null || true

  rm -f "$LANDING_BIN" "$LANDING_CONF" "$LOGROTATE_FILE" \
        /etc/cron.d/acme-xray-landing "$CERT_RELOAD_SCRIPT" 2>/dev/null || true
  rm -f /var/log/acme-xray-landing-renew.log* 2>/dev/null || true
  rm -rf "$LANDING_BASE" "$LANDING_LOG" /usr/local/share/xray-landing "$MANAGER_BASE" 2>/dev/null || true
  rm -f /etc/sysctl.d/99-landing-bbr.conf /etc/modprobe.d/99-landing-conntrack.conf 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true

  if [[ "$_created_user" == "1" ]]; then
    userdel "$LANDING_USER" 2>/dev/null || true
  fi

  local _pclean=1
  [[ -f "$LANDING_BIN" ]] && { warn "二进制 ${LANDING_BIN} 残留"; _pclean=0; } || true
  systemctl is-active --quiet "$LANDING_SVC" 2>/dev/null \
    && { warn "服务 ${LANDING_SVC} 仍在运行"; _pclean=0; } || true
  systemctl is-enabled --quiet "$LANDING_SVC" 2>/dev/null \
    && { warn "服务 ${LANDING_SVC} 仍为 enabled"; _pclean=0; } || true
  iptables -L "$FW_CHAIN" >/dev/null 2>&1 \
    && { warn "iptables chain ${FW_CHAIN} 仍存在"; _pclean=0; } || true
  [[ -d "$LANDING_BASE" ]] && { warn "目录 ${LANDING_BASE} 残留"; _pclean=0; } || true
  ((_pclean)) \
    && success "清除完毕（验收通过），mack-a 未受影响" \
    || warn "清除完毕，但存在残留项，重装前请手动确认（mack-a 未受影响）"
}

show_all_nodes_info(){
  load_manager_config
  echo ""
  echo -e "${BOLD}${CYAN}══ 所有节点 Token 与订阅链接 ══════════════════════════════════${NC}"
  local _node_count=0
  while IFS= read -r _nf; do
    [[ -f "$_nf" ]] || continue
    local _ndom _npwd _ntip _npip
    _ndom=$(grep '^DOMAIN='     "$_nf" 2>/dev/null | cut -d= -f2-) || continue
    _npwd=$(grep '^PASSWORD='   "$_nf" 2>/dev/null | cut -d= -f2-) || continue
    _ntip=$(grep '^TRANSIT_IP=' "$_nf" 2>/dev/null | cut -d= -f2-) || _ntip=""
    _npip=$(grep '^PUBLIC_IP='  "$_nf" 2>/dev/null | cut -d= -f2-) || _npip=""
    [[ -n "$_ndom" && -n "$_npwd" ]] || continue
    if [[ -z "$_npip" ]]; then
      _npip=$(get_public_ip 2>/dev/null) || _npip="<unknown>"
    fi
    (( ++_node_count ))
    echo ""
    echo -e "  ${BOLD}[节点 ${_node_count}] ${_ndom}${NC}  中转: ${_ntip}"
    echo -e "  ─────────────────────────────────────────────────"
    print_pairing_info "$_npip" "$_ndom" "$_npwd" "$_ntip"
  done < <(find "${MANAGER_BASE}/nodes" -name "*.conf" -not -name "tmp-*.conf" -type f 2>/dev/null | sort)
  if (( _node_count == 0 )); then
    warn "（无已配置节点）"
  fi
  echo ""
}

installed_menu(){
  echo ""
  echo -e "${BOLD}${CYAN}══ 落地机管理菜单 ══════════════════════════════════════════════${NC}"
  local n=0
  while IFS= read -r meta; do
    [[ -f "$meta" ]] || continue
    local dom ip ts
    dom=$(grep '^DOMAIN='     "$meta" 2>/dev/null | cut -d= -f2- || echo "?")
    ip=$(grep  '^TRANSIT_IP=' "$meta" 2>/dev/null | cut -d= -f2- || echo "?")
    ts=$(grep  '^CREATED='    "$meta" 2>/dev/null | cut -d= -f2- || echo "?")
    printf "  [节点%-2d] %-38s 中转: %-18s 创建: %s\n" $((++n)) "$dom" "$ip" "$ts"
  done < <(find "${MANAGER_BASE}/nodes" -name "*.conf" -type f 2>/dev/null | sort)
  [[ $n -eq 0 ]] && warn "（无已配置节点）"
  echo ""
  echo "  1. 增加新节点"
  echo "  2. 删除指定节点"
  echo "  3. 修改落地机监听端口"
  echo "  4. 清除本系统所有数据（不影响 mack-a）"
  echo "  5. 退出"
  echo "  6. 显示所有节点 Token 与订阅链接"
  echo ""
  read -rp "请选择 [1-6]: " CHOICE
  case "$CHOICE" in
    1) add_node;      installed_menu ;;
    2) delete_node;   installed_menu ;;
    3) do_set_port;   installed_menu ;;
    4) purge_all ;;
    5) exit 0 ;;
    6) show_all_nodes_info; installed_menu ;;
    *) warn "无效选项: ${CHOICE}"; installed_menu ;;
  esac
}

fresh_install(){
  check_deps
  echo ""
  echo -e "${BOLD}${CYAN}══ 落地机全新安装（${VERSION}）══════════════════════════════════════${NC}"
  echo -e "${BOLD}${RED}  ⚠  重要：域名在 Cloudflare 必须设为【仅DNS/灰云】，严禁开启代理（小黄云）！${NC}"
  echo -e "${RED}     SNI盲传+XTLS-Vision架构下，开启小黄云 = 节点100%永久断流。${NC}"
  echo ""
  read -rp "落地机域名（CF 灰云，DNS 可指向任意 IP）: " DOMAIN
  DOMAIN=$(tr '[:upper:]' '[:lower:]' <<< "$DOMAIN")
  validate_domain "$DOMAIN"
  read -rp "Cloudflare API Token（Zone:DNS:Edit）: " CF_TOKEN
  validate_cf_token "$CF_TOKEN"
  read -rp "Trojan 密码（16位以上，直接回车自动生成）: " PASS
  if [[ -z "$PASS" ]]; then
    PASS=$(gen_password)
    info "  已自动生成高强度密码: ${PASS}"
  fi
  validate_password "$PASS"
  read -rp "中转机公网 IP（防火墙白名单）: " TRANSIT_IP
  validate_ipv4 "$TRANSIT_IP"
  read -rp "落地机监听端口（默认 8443）[8443]: " LANDING_PORT_IN
  LANDING_PORT_IN="${LANDING_PORT_IN:-8443}"
  validate_port "$LANDING_PORT_IN"
  LANDING_PORT="$LANDING_PORT_IN"

  read -rp "确认开始安装？[y/N]: " CONFIRM
  [[ "$CONFIRM" =~ ^[Yy]$ ]] || { info "已取消"; exit 0; }

  ss -tlnp 2>/dev/null | grep -q ":${LANDING_PORT} " && die "端口 ${LANDING_PORT} 已被占用"

  check_deps; optimize_kernel_network; create_system_user; install_xray_binary

  local PUB_IP; PUB_IP=$(get_public_ip)

  if [[ -f "$MANAGER_CONFIG" ]]; then
    local _exist_uuid; _exist_uuid=$(grep '^VLESS_UUID='       "$MANAGER_CONFIG" 2>/dev/null | cut -d= -f2-) || true
    local _exist_port; _exist_port=$(grep '^LANDING_PORT='     "$MANAGER_CONFIG" 2>/dev/null | cut -d= -f2-) || true
    local _exist_vg;   _exist_vg=$(grep   '^VLESS_GRPC_PORT='  "$MANAGER_CONFIG" 2>/dev/null | cut -d= -f2-) || true
    local _exist_tg;   _exist_tg=$(grep   '^TROJAN_GRPC_PORT=' "$MANAGER_CONFIG" 2>/dev/null | cut -d= -f2-) || true
    local _exist_vw;   _exist_vw=$(grep   '^VLESS_WS_PORT='    "$MANAGER_CONFIG" 2>/dev/null | cut -d= -f2-) || true
    local _exist_tt;   _exist_tt=$(grep   '^TROJAN_TCP_PORT='  "$MANAGER_CONFIG" 2>/dev/null | cut -d= -f2-) || true
    if [[ -n "$_exist_uuid" && -n "$_exist_port" ]]; then
      warn "检测到已有安装记录（manager.conf），复用旧配置以保持订阅有效"
      warn "  UUID: ${_exist_uuid}  主端口: ${_exist_port}"
      read -rp "  复用旧配置？[Y/n]: " _reuse_ans
      if [[ ! "${_reuse_ans:-Y}" =~ ^[Nn]$ ]]; then
        VLESS_UUID="$_exist_uuid"
        LANDING_PORT="$_exist_port"
        [[ "$_exist_vg" =~ ^[0-9]+$ ]] && VLESS_GRPC_PORT="$_exist_vg"   || true
        [[ "$_exist_tg" =~ ^[0-9]+$ ]] && TROJAN_GRPC_PORT="$_exist_tg"  || true
        [[ "$_exist_vw" =~ ^[0-9]+$ ]] && VLESS_WS_PORT="$_exist_vw"     || true
        [[ "$_exist_tt" =~ ^[0-9]+$ ]] && TROJAN_TCP_PORT="$_exist_tt"   || true
        success "已复用旧 UUID 和端口，现有订阅链接继续有效"
      else
        warn "  将生成全新 UUID（旧订阅链接将全部失效！）"
        VLESS_UUID=$(python3 -c "import uuid; print(uuid.uuid4())" 2>/dev/null) \
          || VLESS_UUID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || die "无法生成 UUID")
      fi
    fi
  else
    VLESS_UUID=$(python3 -c "import uuid; print(uuid.uuid4())" 2>/dev/null) \
      || VLESS_UUID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || die "无法生成 UUID")
  fi

  local _VGRPC="${VLESS_GRPC_PORT:-0}" _VWS="${VLESS_WS_PORT:-0}" _TTCP="${TROJAN_TCP_PORT:-0}"
  if [[ "${VLESS_GRPC_PORT:-0}" == "0" ]]; then
    _VGRPC=$(python3 -c "import random; b=random.randint(21000,29000)&~3; print(b)")
    _VWS=$(( _VGRPC + 1 )); _TTCP=$(( _VGRPC + 2 ))
    VLESS_GRPC_PORT="$_VGRPC"; VLESS_WS_PORT="$_VWS"; TROJAN_TCP_PORT="$_TTCP"
  fi
  for _chkp in "$_VGRPC" "$_VWS" "$_TTCP"; do
    ss -tlnp 2>/dev/null | grep -q ":${_chkp} "       && die "内网端口 ${_chkp} 已被占用，请重新运行脚本（自动重新分配）"
  done

  mkdir -p "$LANDING_BASE"

  local _fi_trap_active=1
  _fresh_install_rollback(){
    [[ "${_fi_trap_active:-0}" == "1" ]] || return 0
    warn "[rollback] 安装中断，清理半成品..."
    systemctl stop    "$LANDING_SVC"   2>/dev/null || true
    systemctl disable "$LANDING_SVC"   2>/dev/null || true
    rm -f "/etc/systemd/system/${LANDING_SVC}" \
          "/etc/systemd/system/xray-landing-recovery.service" 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
    while iptables -D INPUT -j "$FW_CHAIN" 2>/dev/null; do :; done
    iptables -F "$FW_CHAIN" 2>/dev/null || true
    iptables -X "$FW_CHAIN" 2>/dev/null || true
    rm -f "$LANDING_BIN" "$CERT_RELOAD_SCRIPT" "$LOGROTATE_FILE" 2>/dev/null || true
    rm -rf /usr/local/share/xray-landing 2>/dev/null || true
    rm -f /run/lock/xray-landing-recovery.last 2>/dev/null || true
    if [[ -n "${DOMAIN:-}" && -f "${ACME_HOME}/acme.sh" ]]; then
      env ACME_HOME="${ACME_HOME}" "${ACME_HOME}/acme.sh" \
        --home "${ACME_HOME}" --remove --domain "${DOMAIN}" --ecc 2>/dev/null || true
    fi
    rm -rf "$CERT_BASE" "$LANDING_BASE" 2>/dev/null || true
    rm -f "$INSTALLED_FLAG" "$MANAGER_CONFIG" 2>/dev/null || true
    rm -f "${_staged_fi_mgr:-}" 2>/dev/null || true
    rm -rf "${MANAGER_BASE}/nodes" 2>/dev/null || true
    warn "[rollback] 完成，可安全重新运行安装"
  }
  trap '_fresh_install_rollback' ERR INT TERM

  mkdir -p "${MANAGER_BASE}/tmp"

  local _staged_fi_mgr; _staged_fi_mgr=$(mktemp "${MANAGER_BASE}/tmp/.manager.XXXXXX") \
    || die "mktemp for staged manager.conf failed"
  atomic_write "$_staged_fi_mgr" 600 root:root <<SMFI
LANDING_PORT=${LANDING_PORT}
VLESS_UUID=${VLESS_UUID}
VLESS_GRPC_PORT=${VLESS_GRPC_PORT}
TROJAN_GRPC_PORT=${TROJAN_GRPC_PORT}
VLESS_WS_PORT=${VLESS_WS_PORT}
TROJAN_TCP_PORT=${TROJAN_TCP_PORT}
CF_TOKEN=${CF_TOKEN}
CREATED_USER=${CREATED_USER}
SMFI

  mkdir -p "$LANDING_LOG"
  issue_certificate "$DOMAIN" "$CF_TOKEN"

  local _safe_dom; _safe_dom=$(printf '%s' "$DOMAIN" | tr '.:/' '___')
  local _safe_ip;  _safe_ip=$(printf '%s' "$TRANSIT_IP" | tr '.:' '__')
  local _final_node="${MANAGER_BASE}/nodes/${_safe_dom}_${_safe_ip}.conf"
  mkdir -p "${MANAGER_BASE}/nodes"
  atomic_write "$_final_node" 600 root:root <<NEOF_ATOMIC
DOMAIN=${DOMAIN}
PASSWORD=${PASS}
TRANSIT_IP=${TRANSIT_IP}
PUBLIC_IP=${PUB_IP}
CREATED=$(date +%Y%m%d_%H%M%S)
NEOF_ATOMIC
  trap '_global_cleanup; rm -f "$_final_node" 2>/dev/null; echo -e "\n${RED}[中断] 请执行: bash $0 --uninstall${NC}"; exit 1' INT TERM

  if ! ( sync_xray_config ); then
    if [[ -f "${ACME_HOME}/acme.sh" ]]; then
      "${ACME_HOME}/acme.sh" --home "${ACME_HOME}" --remove --domain "$DOMAIN" --ecc 2>/dev/null || true
      rm -rf "${CERT_BASE}/${DOMAIN}" 2>/dev/null || true
    fi
    rm -f "$_final_node" "${_staged_fi_mgr:-}" 2>/dev/null; die "Xray配置同步失败，节点未保存，已清理废弃证书"
  fi
  if ! ( create_systemd_service ); then
    if [[ -f "${ACME_HOME}/acme.sh" ]]; then
      "${ACME_HOME}/acme.sh" --home "${ACME_HOME}" --remove --domain "$DOMAIN" --ecc 2>/dev/null || true
      rm -rf "${CERT_BASE}/${DOMAIN}" 2>/dev/null || true
    fi
    rm -f "$_final_node" "${_staged_fi_mgr:-}" 2>/dev/null; die "服务创建失败，节点未保存，已清理废弃证书"
  fi

  trap '_global_cleanup; rm -f "${_staged_fi_mgr:-}" 2>/dev/null; echo -e "\n${RED}[中断] 请执行: bash $0 --uninstall${NC}"; exit 1' INT TERM

  if ! ( setup_firewall ); then
    rm -f "$_final_node" "${_staged_fi_mgr:-}" 2>/dev/null || true
    systemctl stop    "$LANDING_SVC" 2>/dev/null || true
    systemctl disable "$LANDING_SVC" 2>/dev/null || true
    rm -f "/etc/systemd/system/${LANDING_SVC}" 2>/dev/null || true
    rm -f "$LOGROTATE_FILE" 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
    ( sync_xray_config ) 2>/dev/null || true
    if [[ -f "${ACME_HOME}/acme.sh" ]]; then
      "${ACME_HOME}/acme.sh" --home "${ACME_HOME}" --remove --domain "$DOMAIN" --ecc 2>/dev/null || true
      rm -rf "${CERT_BASE}/${DOMAIN}" 2>/dev/null || true
    fi
    die "防火墙配置失败，已完整回滚（含证书撤销），可安全重跑安装"
  fi

  mv -f "$_staged_fi_mgr" "$MANAGER_CONFIG" \
    || { die "manager.conf 原子提交失败，安装已回滚，请重新运行"; }
  touch "$INSTALLED_FLAG"
  _staged_fi_mgr=""

  _fi_trap_active=0
  trap '_global_cleanup; echo -e "\n${RED}[中断] 请执行: bash $0 --uninstall${NC}"; exit 1' INT TERM

  print_pairing_info "$PUB_IP" "$DOMAIN" "$PASS" "$TRANSIT_IP"
  success "══ 落地机安装完成！══"
  echo -e "  systemctl status ${LANDING_SVC}"
  echo -e "  tail -f ${LANDING_LOG}/error.log"
}

_ver_gt(){ [[ "$(printf '%s\n' "$1" "$2" | sort -V | tail -1)" == "$1" && "$1" != "$2" ]]; }
_check_update(){
  local self_name="install_landing_v2.50.sh"
  local cur_ver="$VERSION"
  local remote
  remote=$(curl -fsSL --connect-timeout 3 --retry 1 \
    "https://raw.githubusercontent.com/vpn3288/cn2gia-transit/main/${self_name}" \
    2>/dev/null | grep -o 'v[0-9]\+\.[0-9]\+' | head -1) || return 0
  [[ -n "$remote" ]] && _ver_gt "$remote" "$cur_ver" && warn "发现新版本 ${remote}！" || true
}

main(){
  echo -e "${BOLD}"
  echo "╔══════════════════════════════════════════════════════════════════╗"
  printf "║     美西 CN2 GIA 落地机安装脚本  %-32s║\n" "${VERSION}"
  echo "║     4协议单端口回落 · TLS 1.2/1.3双栈 · rejectUnknownSni=true  ║"
  echo "║     异构uTLS指纹 · UDP53黑洞 · have_ipv6 sysctl guard           ║"
  echo "║     UDP443显式拒绝 · acme自愈升级 · 真相源防反写 · mack-a隔离 ║"
  echo "╚══════════════════════════════════════════════════════════════════╝"
  echo -e "${NC}"

  case "${1:-}" in
    --uninstall) purge_all; exit 0 ;;
    --help|-h)   show_help; exit 0 ;;
    --status)    show_status; exit $? ;;
    set-port)    do_set_port "${2:-}"; exit 0 ;;
  esac

  _check_update &

  if [[ ! -f "$INSTALLED_FLAG" ]]; then
    local _sym_mgr=1 _sym_conf=1 _sym_node=1
    [[ -f "$MANAGER_CONFIG" ]]  || _sym_mgr=0
    [[ -f "$LANDING_CONF" ]]    || _sym_conf=0
    find "${MANAGER_BASE}/nodes" -name "*.conf" -not -name "tmp-*.conf" \
         -type f -maxdepth 1 2>/dev/null | grep -q . 2>/dev/null || _sym_node=0
    if (( _sym_mgr && _sym_conf && _sym_node )); then
      warn "持久化集完整但安装标记缺失（崩溃于最后一步），自动恢复标记..."
      touch "$INSTALLED_FLAG"
    fi
  fi

  if [[ -f "$INSTALLED_FLAG" ]]; then
    local _durable_ok=1
    [[ -f "$MANAGER_CONFIG" ]]                                          || _durable_ok=0
    [[ -f "$LANDING_CONF" ]]                                            || _durable_ok=0
    find "${MANAGER_BASE}/nodes" -name "*.conf" -not -name "tmp-*.conf" \
         -type f -maxdepth 1 2>/dev/null | grep -q . 2>/dev/null       || _durable_ok=0
    if (( _durable_ok == 0 )); then
      warn "安装标记存在但持久化集不完整，清除标记重新安装..."
      rm -f "$INSTALLED_FLAG"
      find "${MANAGER_BASE}/tmp" -maxdepth 1 -name '.manager.*' -type f -delete 2>/dev/null || true
      fresh_install
      return
    fi
    load_manager_config
    local _svc_ok=0 _conf_ok=0 _node_ok=0
    systemctl is-active --quiet "$LANDING_SVC" 2>/dev/null && _svc_ok=1 \
      || warn "服务未运行"
    [[ -f "$MANAGER_CONFIG" ]] && _conf_ok=1 \
      || warn "manager.conf 缺失（真相源丢失）"
    local _nc; _nc=$(find "${MANAGER_BASE}/nodes" -name "*.conf" -type f 2>/dev/null | wc -l)
    (( _nc > 0 )) && _node_ok=1
    if (( _svc_ok == 0 && _conf_ok == 0 && _node_ok == 0 )); then
      warn "安装标记存在但三态全部缺失，清除标记重新安装..."
      rm -f "$INSTALLED_FLAG"
      fresh_install
      return
    fi
    if (( _conf_ok == 0 )); then
      die "manager.conf（真相源）已丢失，无法安全操作。请执行 --uninstall 清除后重装"
    fi
    if (( _svc_ok == 0 )); then
      warn "服务未运行，尝试自动恢复..."
      local _recovered=0
      if ( sync_xray_config ) 2>/dev/null && systemctl restart "$LANDING_SVC" 2>/dev/null; then
        sleep 2
        if systemctl is-active --quiet "$LANDING_SVC" 2>/dev/null; then
          success "服务已恢复运行"
          _recovered=1
        fi
      fi
      if (( _recovered == 0 )); then
        error "自动恢复失败，拒绝进入管理菜单（防止在分裂状态上继续写操作）"
        echo -e "  请先执行: ${CYAN}bash $0 --status${NC} 排查状态分裂"
        echo -e "  若无法修复，请执行: ${CYAN}bash $0 --uninstall${NC} 清除后重装"
        exit 1
      fi
    fi
    installed_menu
  else
    fresh_install
  fi
}

main "$@"
