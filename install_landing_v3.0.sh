#!/usr/bin/env bash
# install_landing_v3.0.sh — 落地机安装脚本 v3.0
# 5协议单端口回落 · routeOnly嗅探 · AsIs出站 · CAP_NET_BIND_SERVICE
# v3.0: 修复 EXIT trap 被覆盖 bug、find -delete 语法错误、mktemp 超时保护
set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1;1m'; NC='\033[0m'
readonly VERSION="v3.0"

info()    { echo -e "${CYAN}[INFO]${NC}    $*"; }
success() { echo -e "${GREEN}[OK]${NC}     $*"; }
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
readonly ACME_HOME="${LANDING_BASE}/acme"
readonly CERT_BASE="${LANDING_BASE}/certs"
readonly FW_CHAIN="XRAY-LANDING"
readonly FW_CHAIN6="XRAY-LANDING-v6"
readonly LOGROTATE_FILE="/etc/logrotate.d/xray-landing"
readonly TEMP_DIR="${MANAGER_BASE}/tmp"

[[ $EUID -eq 0 ]] || die "必须以 root 身份运行"

# v3.0: [BUGFIX-1] 正确的清理函数，find -delete 必须单独一行
_landing_cleanup(){
  # 清理本脚本的临时文件（前缀隔离）
  find "${MANAGER_BASE}" /etc/xray-landing /etc/nginx \
    /etc/systemd/system /etc/logrotate.d \
    -maxdepth 5 -type f \
    \( -name '.xray-landing.*' -o -name '.landing-mgr.*' -o -name '.snap-recover.*' \) \
    -delete 2>/dev/null
  
  # 清理 staging 文件
  find "${MANAGER_BASE}/nodes" -maxdepth 1 -type f -name 'tmp-*.conf' -delete 2>/dev/null
  
  # 清理 xray tmp dirs
  rm -rf "${MANAGER_BASE}/tmp/xray_tmp_"* 2>/dev/null
  
  # 清理 tmp 目录中的残留
  find "${TEMP_DIR}" -maxdepth 1 -type f \
    \( -name '.landing-mgr.*' -o -name '.xray-landing.*' -o -name '.nginx-conf-snap.*' \) \
    -delete 2>/dev/null
}

# v3.0: [BUGFIX-1] 信号处理器，确保清理总是执行
_landing_signal_handler(){
  local sig="$1"
  echo -e "\n${RED}[${sig}] 安装已中断，清理临时文件..." >&2
  _landing_cleanup
  echo -e "${RED}[中断] 请执行: bash $0 --uninstall${NC}" >&2
  exit 130
}

# v3.0: 先注册 EXIT 清理
trap '_landing_cleanup' EXIT
# v3.0: 再注册 INT/TERM，覆盖时保留清理逻辑
trap '_landing_signal_handler INT' INT
trap '_landing_signal_handler TERM' TERM

# v3.0: [BUGFIX-3] mktemp 带超时和 fallback
_mktemp(){
  local prefix="${1:-tmp}"
  local timeout_secs="${2:-5}"
  local dir="${3:-${TEMP_DIR}}"
  mkdir -p "$dir"
  
  # 生成唯一后缀
  local suffix
  suffix=$(LC_ALL=C tr -dc 'a-zA-Z0-9' </dev/urandom 2>/dev/null | head -c 8)
  [[ -z "$suffix" ]] && suffix="$$_$(date +%N)"
  
  local tmp_file="${dir}/.landing-mgr.${prefix}.${suffix}"
  
  # 尝试创建
  if touch "$tmp_file" 2>/dev/null; then
    printf '%s' "$tmp_file"
    return 0
  fi
  
  # fallback: 使用带超时的 mktemp
  local oldopts="$-"
  set +e
  local result
  result=$(timeout "$timeout_secs" mktemp "${dir}/.landing-mgr.${prefix}.XXXXXX" 2>/dev/null)
  local mkt_status=$?
  set -"$oldopts"
  
  if (( mkt_status == 0 )) && [[ -n "$result" && -f "$result" ]]; then
    printf '%s' "$result"
    return 0
  fi
  
  # 最终 fallback: date+pid+random
  printf '%s/.landing-mgr.%s.%d.%s' "$dir" "$prefix" "$$" "$(date +%s%N)"
  return 0
}

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

# v3.0: [架构优化] atomic_write 纯 bash 实现
atomic_write(){
  local target="$1" mode="${2:-644}" owner_group="${3:-root:root}"
  local dir tmp
  
  [[ -z "$target" ]] && { echo "atomic_write: target 为空" >&2; return 1; }
  dir="$(dirname "$target")"
  mkdir -p "$dir"
  
  tmp="$(_mktemp "atomic" 3 "$dir")"
  [[ -z "$tmp" ]] && { echo "atomic_write: mktemp 失败" >&2; return 1; }
  
  # stdin → 临时文件
  if ! cat >"$tmp" 2>/dev/null; then
    rm -f "$tmp" 2>/dev/null
    echo "atomic_write: 无法写入 $tmp" >&2
    return 1
  fi
  
  chmod "$mode" "$tmp" 2>/dev/null || true
  chown "$owner_group" "$tmp" 2>/dev/null || true
  
  # 原子 mv
  if ! mv -f "$tmp" "$target" 2>/dev/null; then
    rm -f "$tmp" 2>/dev/null
    echo "atomic_write: mv 失败 $tmp → $target" >&2
    return 1
  fi
  return 0
}

# v3.0: 全局写锁
_acquire_lock(){
  mkdir -p "$TEMP_DIR"
  exec 200>"${TEMP_DIR}/landing-manager.lock" 2>/dev/null || return 1
  if ! flock -w 10 200; then
    die "配置正在被其他进程修改，请稍后重试（等待超时 10s）"
  fi
}
_release_lock(){
  flock -u 200 2>/dev/null || true
  exec 200>&- 2>/dev/null || true
  exec 200>/dev/null 2>/dev/null || true
}

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
    echo -e "${RED}[FATAL]${NC} 无法探测 SSH 端口。" >&2
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
    || die "manager.conf 损坏：LANDING_PORT='${lp:-<空>}' 非法"
  [[ -n "$vu" ]] || die "manager.conf 损坏：VLESS_UUID 为空"

  LANDING_PORT="$lp"
  VLESS_UUID="$vu"
  for _pf in "$vg" "$tg" "$vw" "$tt"; do
    [[ -z "$_pf" || "$_pf" =~ ^[0-9]+$ ]] || die "manager.conf 损坏：内部端口 '${_pf}' 非法"
  done
  [[ "$vg" =~ ^[0-9]+$ ]] && VLESS_GRPC_PORT="$vg"   || VLESS_GRPC_PORT=0
  [[ "$tg" =~ ^[0-9]+$ ]] && TROJAN_GRPC_PORT="$tg"  || TROJAN_GRPC_PORT=0
  [[ "$vw" =~ ^[0-9]+$ ]] && VLESS_WS_PORT="$vw"     || VLESS_WS_PORT=0
  [[ "$tt" =~ ^[0-9]+$ ]] && TROJAN_TCP_PORT="$tt"   || TROJAN_TCP_PORT=0
  [[ -n "$ct" ]] && CF_TOKEN="$ct" || CF_TOKEN=""
  [[ -n "$cu" ]] && CREATED_USER="$cu" || CREATED_USER="0"
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
    if addr.is_loopback or addr.is_unspecified or addr.is_reserved or addr.is_multicast or addr.is_link_local or addr.is_private:
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
  [[ "$1" =~ ^[a-zA-Z0-9_-]+$ ]] || die "CF Token 含非法字符"
}

show_help(){
  cat <<HELP
用法: bash install_landing_v3.0.sh [选项]
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
    ip=$(curl -4 -fsSL --connect-timeout 5 --max-time 10 "$src" 2>/dev/null | tr -d '[:space:]') \
      && [[ -n "$ip" ]] && break || true
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
    openssl:openssl nginx:nginx ip:iproute2 fuser:psmisc crontab:cron
  )
  local missing_pkgs=()
  for bp in "${_bin_pkg[@]}"; do
    local bin="${bp%%:*}" pkg="${bp##*:}"
    command -v "$bin" &>/dev/null || missing_pkgs+=("$pkg")
  done
  
  if (( ${#missing_pkgs[@]} > 0 )) && command -v apt-get &>/dev/null; then
    local _lw=0
    if command -v fuser &>/dev/null; then
      while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
        sleep 2; ((_lw+=2))
        ((_lw>60)) && die "apt 锁等待超时"
      done
    else
      sleep 5
    fi
    apt-get update -qq 2>/dev/null || true
    for d in "${missing_pkgs[@]}"; do
      apt-get install -y "$d" 2>/dev/null || die "安装 $d 失败"
    done
  elif (( ${#missing_pkgs[@]} > 0 )); then
    for d in "${missing_pkgs[@]}"; do
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
    sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -qi 'bbr' \
      || warn "BBRPlus 未检测到"
    return 0
  }

  local _ram_mb; _ram_mb=$(free -m 2>/dev/null | awk '/Mem:/{print $2}') || _ram_mb=1024
  local _tw_max=$(( _ram_mb * 100 ))
  (( _tw_max < 10000 ))  && _tw_max=10000
  (( _tw_max > 250000 )) && _tw_max=250000

  local _fd_max=$(( _ram_mb * 800 ))
  (( _fd_max < 524288 ))   && _fd_max=524288
  (( _fd_max > 10485760 )) && _fd_max=10485760

  atomic_write "$bbr_conf" 644 root:root <<BBRCF
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
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_timestamps=1
net.ipv4.tcp_fastopen=3
BBRCF

  echo "options nf_conntrack hashsize=262144" > /etc/modprobe.d/99-landing-conntrack.conf 2>/dev/null || true
  modprobe nf_conntrack 2>/dev/null || true
  sysctl --system &>/dev/null || true
  success "内核网络参数已优化"
}

install_xray_binary(){
  info "下载 Xray-core ..."
  local api_resp ver
  api_resp=$(curl -fsSL --connect-timeout 10 --max-time 30 "https://api.github.com/repos/XTLS/Xray-core/releases/latest" 2>/dev/null) \
    || die "无法访问 GitHub API"
  ver=$(printf '%s' "$api_resp" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
  [[ -n "$ver" ]] || die "无法解析 Xray 版本号"

  local arch_name="64"
  case "$(uname -m)" in
    aarch64|arm64) arch_name="arm64-v8a" ;;
    armv7l) arch_name="arm32-v7a" ;;
  esac

  local zip_name="Xray-linux-${arch_name}.zip"
  local tmp_dir; tmp_dir="$(_mktemp "xray-dl" 60)"
  mkdir -p "$tmp_dir"

  wget -q --timeout=30 --tries=2 -O "${tmp_dir}/xray.zip" \
    "https://github.com/XTLS/Xray-core/releases/download/${ver}/${zip_name}" \
    || die "下载 Xray 失败"

  if wget -q -O "${tmp_dir}/sha256sums.txt" \
      "https://github.com/XTLS/Xray-core/releases/download/${ver}/sha256sums.txt" 2>/dev/null \
      && grep -qF "$zip_name" "${tmp_dir}/sha256sums.txt"; then
    ( cd "$tmp_dir" && grep -F "$zip_name" sha256sums.txt | sha256sum -c - ) \
      || warn "Xray 完整性校验失败，跳过"
  fi

  unzip -q "${tmp_dir}/xray.zip" xray geoip.dat geosite.dat -d "${tmp_dir}/" || die "解压失败"
  install -m 755 "${tmp_dir}/xray" "$LANDING_BIN"
  chown root:"$LANDING_USER" "$LANDING_BIN" 2>/dev/null || true
  
  mkdir -p /usr/local/share/xray-landing
  install -m 644 "${tmp_dir}/geoip.dat"   /usr/local/share/xray-landing/geoip.dat
  install -m 644 "${tmp_dir}/geosite.dat" /usr/local/share/xray-landing/geosite.dat

  rm -rf "$tmp_dir"
  success "Xray 安装完成: ${LANDING_BIN} (${ver})"
}

create_system_user(){
  if ! id "$LANDING_USER" &>/dev/null; then
    useradd -r -s /usr/sbin/nologin -d /nonexistent -M "$LANDING_USER" \
      || die "创建系统用户 ${LANDING_USER} 失败"
    CREATED_USER="1"
    success "系统用户 ${LANDING_USER} 已创建"
  fi
}

_tune_nginx_worker_connections(){
  local mc="/etc/nginx/nginx.conf"
  local _mc_bak; _mc_bak="$(_mktemp "nginx-conf-snap" 3)"
  cp -a "$mc" "$_mc_bak" 2>/dev/null || { warn "nginx.conf snapshot failed"; return 0; }

  local _tmc_ram_mb; _tmc_ram_mb=$(free -m 2>/dev/null | awk '/Mem:/{print $2}') || _tmc_ram_mb=1024
  local _tmc_fd=$(( _tmc_ram_mb * 800 ))
  (( _tmc_fd < 524288 ))   && _tmc_fd=524288
  (( _tmc_fd > 10485760 )) && _tmc_fd=10485760

  if ! grep -qE '^\s*worker_connections\s+100000\s*;' "$mc" 2>/dev/null; then
    if grep -qE '^\s*worker_connections' "$mc" 2>/dev/null; then
      sed -i 's/^\s*worker_connections\s\+[0-9]\+;/    worker_connections 100000;/' "$mc"
    else
      sed -i '/^events\s*{/a\    worker_connections 100000;' "$mc"
    fi
  fi

  if ! grep -qE "^worker_rlimit_nofile\s+${_tmc_fd}\s*;" "$mc" 2>/dev/null; then
    if grep -qE '^\s*worker_rlimit_nofile' "$mc" 2>/dev/null; then
      sed -i "s/^.*worker_rlimit_nofile.*/worker_rlimit_nofile ${_tmc_fd};/" "$mc"
    else
      sed -i "/^events\s*{/i\\worker_rlimit_nofile ${_tmc_fd};" "$mc"
    fi
  fi

  if ! nginx -t 2>/dev/null; then
    cp -f "$_mc_bak" "$mc" 2>/dev/null || die "nginx.conf restore FAILED"
    die "nginx.conf tuning failed"
  fi
  rm -f "$_mc_bak" 2>/dev/null || true

  local od="/etc/systemd/system/nginx.service.d"
  mkdir -p "$od"
  atomic_write "${od}/landing-override.conf" 644 root:root <<SVCOV
[Service]
LimitNOFILE=${_tmc_fd}
TasksMax=infinity
StandardOutput=null
StandardError=null
SVCOV
  systemctl daemon-reload 2>/dev/null || true
}

setup_fallback_decoy(){
  local fallback_conf="/etc/nginx/conf.d/xray-landing-fallback.conf"

  if fuser -n tcp 45231 2>/dev/null; then
    die "端口 45231 已被占用"
  fi

  if ! command -v nginx &>/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq 2>/dev/null || true
    apt-get install -y nginx 2>/dev/null || die "Nginx 安装失败"
  fi

  _tune_nginx_worker_connections

  local need_ipv6=0; have_ipv6 && need_ipv6=1
  atomic_write "$fallback_conf" 644 root:root <<FDEOF
limit_conn_zone \$binary_remote_addr zone=fallback_conn:10m;
limit_req_zone  \$binary_remote_addr zone=fallback_req:10m rate=10r/s;
server {
    listen 127.0.0.1:45231 http2;
    server_name _;
    server_tokens off;
    limit_conn fallback_conn 4;
    limit_req  zone=fallback_req burst=50 nodelay;
    error_page 400 503 = @silent_close;
    location @silent_close { return 444; }
    location / { return 444; }
    access_log off;
    error_log /dev/null;
}
FDEOF

  (( need_ipv6 )) && sed -i 's|listen 127.0.0.1:45231 http2;|listen 127.0.0.1:45231 http2;\n    listen [::1]:45231 http2;|' "$fallback_conf"

  nginx -t 2>&1 || die "Nginx fallback 配置验证失败"

  if systemctl is-active --quiet nginx 2>/dev/null; then
    systemctl reload nginx
  else
    systemctl enable nginx || die "nginx enable failed"
    systemctl start nginx || die "Nginx 启动失败"
  fi
  success "fallback 防探针站已就绪"
}

_write_cert_reload_script(){
  atomic_write "$CERT_RELOAD_SCRIPT" 755 root:root <<'RELOAD_EOF'
#!/bin/sh
set -eu
CERT_DIR="${1:-}"
[ -n "$CERT_DIR" ] || exit 0
chown -R root:xray-landing "$CERT_DIR" 2>/dev/null || true
chmod 750 "$CERT_DIR" 2>/dev/null || true
chmod 644 "$CERT_DIR/cert.pem" "$CERT_DIR/fullchain.pem" 2>/dev/null || true
chmod 640 "$CERT_DIR/key.pem" 2>/dev/null || true

if ! /bin/systemctl is-active --quiet xray-landing.service 2>/dev/null; then
  exit 0
fi

if openssl x509 -checkend 86400 -noout -in "$CERT_DIR/fullchain.pem" 2>/dev/null; then
  if ! /bin/systemctl reload xray-landing.service 2>/dev/null; then
    /bin/systemctl restart xray-landing.service 2>/dev/null || true
  fi
else
  echo "$(date '+%Y-%m-%d %H:%M:%S') WARN: 证书续期后校验失败，保留旧进程态" >> /var/log/acme-xray-landing-renew.log 2>/dev/null || true
fi
RELOAD_EOF
}

issue_certificate(){
  local domain="$1" cf_token="$2"
  local cert_dir="${CERT_BASE}/${domain}"

  if [[ -f "${cert_dir}/fullchain.pem" && -f "${cert_dir}/key.pem" ]]; then
    local end_str expiry_days=0
    end_str=$(openssl x509 -in "${cert_dir}/fullchain.pem" -noout -enddate 2>/dev/null | cut -d= -f2) || true
    if [[ -n "$end_str" ]]; then
      local end_ts now_ts
      end_ts=$(LANG=C date -d "$end_str" +%s 2>/dev/null || echo 0); now_ts=$(date +%s)
      expiry_days=$(( (end_ts - now_ts) / 86400 ))
      (( expiry_days < 0 )) && expiry_days=0
    fi
    if (( expiry_days > 30 )); then
      success "证书有效（剩余 ${expiry_days} 天），跳过申请"
      return 0
    fi
    info "证书即将到期（${expiry_days} 天），重新申请"
  fi

  mkdir -p "$cert_dir" "$ACME_HOME"

  if [[ ! -f "${ACME_HOME}/acme.sh" ]]; then
    mkdir -p "$ACME_HOME"
    env ACME_HOME="$ACME_HOME" curl -fsSL https://get.acme.sh \
      | env ACME_HOME="$ACME_HOME" sh -s email="admin@${domain}" --nocron \
      || die "acme.sh 安装失败"
    
    if [[ ! -f "${ACME_HOME}/acme.sh" ]]; then
      local _home_acme="${HOME}/.acme.sh"
      if [[ -f "${_home_acme}/acme.sh" ]]; then
        warn "acme.sh 安装到了 ${_home_acme}，迁移..."
        mkdir -p "$ACME_HOME"
        cp -rp "${_home_acme}/." "$ACME_HOME}/"
        rm -rf "${_home_acme}"
      fi
    fi
    
    [[ -f "${ACME_HOME}/dnsapi/dns_cf.sh" ]] \
      || die "acme.sh 缺少 dns_cf.sh 插件"
    
    env ACME_HOME="$ACME_HOME" "${ACME_HOME}/acme.sh" \
      --set-default-ca --server letsencrypt 2>/dev/null || true
    "${ACME_HOME}/acme.sh" --upgrade --auto-upgrade 2>/dev/null || true
  fi
  
  export PATH="${ACME_HOME}:${PATH}"

  info "申请证书（DNS-01/Cloudflare）: ${domain} ..."

  local issued=0
  for try in 1 2; do
    CF_Token="$cf_token" env ACME_HOME="$ACME_HOME" "${ACME_HOME}/acme.sh" \
      --issue --dns dns_cf --domain "$domain" --keylength ec-256 \
      --server letsencrypt --dnssleep 40 --force \
      && issued=1 && break || true
    (( try < 2 )) && { warn "第 ${try} 次申请失败，等待后重试..."; sleep 30; }
  done
  (( issued )) || die "证书申请失败"

  _write_cert_reload_script

  env ACME_HOME="$ACME_HOME" "${ACME_HOME}/acme.sh" \
    --install-cert --domain "$domain" --ecc \
    --cert-file      "${cert_dir}/cert.pem" \
    --key-file       "${cert_dir}/key.pem" \
    --fullchain-file "${cert_dir}/fullchain.pem" \
    --reloadcmd      "${CERT_RELOAD_SCRIPT} '${cert_dir}'" \
    || die "证书部署失败"

  chown -R "${LANDING_USER}:${LANDING_USER}" "${LANDING_BASE}" 2>/dev/null || \
    chown -R root:"${LANDING_USER}" "${LANDING_BASE}"
  chmod 750 "$cert_dir"
  chmod 644 "${cert_dir}/cert.pem" "${cert_dir}/fullchain.pem"
  chmod 640 "${cert_dir}/key.pem"
  [[ -f "$LANDING_CONF" ]] && chmod 640 "$LANDING_CONF" 2>/dev/null || true
  success "证书部署完成"

  info "配置证书自动续期 cron ..."
  rm -f /etc/cron.d/acme-xray-landing 2>/dev/null || true
  env ACME_HOME="$ACME_HOME" "${ACME_HOME}/acme.sh" --uninstall-cronjob 2>/dev/null || true
  
  if ! crontab -l 2>/dev/null | grep -q '^MAILTO=""'; then
    ( printf 'MAILTO=""\n'; crontab -l 2>/dev/null ) | crontab - 2>/dev/null || true
  fi
  
  env ACME_HOME="$ACME_HOME" "${ACME_HOME}/acme.sh" --install-cronjob \
    || die "acme.sh --install-cronjob 失败"
  
  crontab -l 2>/dev/null \
    | sed "s|${HOME}/.acme.sh/acme.sh|${ACME_HOME}/acme.sh|g" \
    | crontab - 2>/dev/null || true

  success "证书自动续期已配置"
}

sync_xray_config(){
  info "同步 Xray 配置..."
  load_manager_config

  if [[ "${VLESS_GRPC_PORT:-0}" == "0" ]]; then
    local _base
    _base=$(python3 -c "import random; b=random.randint(21000,29000)&~3; print(b)")
    VLESS_GRPC_PORT="$_base"
    TROJAN_GRPC_PORT=$(( _base + 1 ))
    VLESS_WS_PORT=$(( _base + 2 ))
    TROJAN_TCP_PORT=$(( _base + 3 ))
    save_manager_config
  fi

  mkdir -p "$LANDING_BASE"
  local py_exit=0
  (
    export _NODES_DIR="${MANAGER_BASE}/nodes"
    export _CERT_BASE="$CERT_BASE"
    export _LOG_DIR="$LANDING_LOG"
    export _CFG_OUT="$LANDING_CONF"
    export _LANDING_PORT="$LANDING_PORT"
    export _VLESS_UUID="$VLESS_UUID"
    export _VLESS_GRPC_PORT="$VLESS_GRPC_PORT"
    export _TROJAN_GRPC_PORT="$TROJAN_GRPC_PORT"
    export _VLESS_WS_PORT="$VLESS_WS_PORT"
    export _TROJAN_TCP_PORT="$TROJAN_TCP_PORT"
    
    python3 - <<'PYEOF'
import json, os, glob, uuid as _uuid, random as _rand

def safe_int(val, fallback=0):
    try:
        return int(val) if val and val.strip() else fallback
    except (ValueError, TypeError):
        return fallback

landing_port = safe_int(os.environ.get('_LANDING_PORT', '8443'), 8443)
vless_uuid  = os.environ.get('_VLESS_UUID', '') or str(_uuid.uuid4())
_vg = safe_int(os.environ.get('_VLESS_GRPC_PORT', '0'))
_tg = safe_int(os.environ.get('_TROJAN_GRPC_PORT', '0'))
_vw = safe_int(os.environ.get('_VLESS_WS_PORT', '0'))
_tt = safe_int(os.environ.get('_TROJAN_TCP_PORT', '0'))
if not (_vg and _tg and _vw and _tt):
    _base = _rand.randint(21000, 29000) & ~3
    _vg, _tg, _vw, _tt = _base, _base+1, _base+2, _base+3

nodes_dir = os.environ['_NODES_DIR']
cert_base = os.environ['_CERT_BASE']

trojan_clients = []
certs_dict = {}
seen_domains = set()

for path in sorted(glob.glob(os.path.join(nodes_dir, '*.conf'))):
    if os.path.getsize(path) == 0:
        raise ValueError(f"Zero-byte node file: {path}")
    dom = pwd = ''
    try:
        for line in open(path, encoding='utf-8', errors='replace'):
            line = line.strip()
            if line.startswith('DOMAIN='):   dom = line[7:]
            if line.startswith('PASSWORD='): pwd = line[9:]
    except OSError as e:
        raise ValueError(f"Cannot read {path}: {e}")
    if not dom or not pwd:
        raise ValueError(f"Corrupted node: {path}")
    cert_fullchain = f"{cert_base}/{dom}/fullchain.pem"
    cert_key = f"{cert_base}/{dom}/key.pem"
    if not os.path.exists(cert_fullchain) or not os.path.exists(cert_key):
        print(f"  [WARN] {dom} 证书文件不存在，跳过")
        continue
    if dom not in certs_dict:
        certs_dict[dom] = {"certificateFile": cert_fullchain, "keyFile": cert_key}
    if dom not in seen_domains:
        seen_domains.add(dom)
        trojan_clients.append({"password": pwd, "level": 0, "email": f"user@{dom}"})

if not trojan_clients:
    import sys
    print("  [WARN] 节点文件为空或证书均缺失，跳过")
    sys.exit(1)

PORT_VLESS_GRPC  = _vg
PORT_TROJAN_GRPC = _tg
PORT_VLESS_WS    = _vw
PORT_TROJAN_TCP  = _tt
PORT_FALLBACK    = 45231
PFX = vless_uuid[:8]

tls_settings = {
    "minVersion": "1.2",
    "alpn": ["h2", "http/1.1", "http/1.0"],
    "rejectUnknownSni": True,
    "fingerprint": "random",
    "certificates": list(certs_dict.values())
}

cfg = {
    "log": {"access": "none", "error": "none", "loglevel": "warning"},
    "inbounds": [
        {
            "listen": "0.0.0.0", "port": landing_port, "protocol": "vless",
            "settings": {
                "clients": [{"id": vless_uuid, "flow": "xtls-rprx-vision", "level": 0, "email": "vless-vision@main"}],
                "decryption": "none",
                "fallbacks": [
                    {"alpn": "h2", "dest": PORT_VLESS_GRPC,  "xver": 0},
                    {"alpn": "h2", "dest": PORT_TROJAN_GRPC, "xver": 0},
                    {"alpn": "http/1.1", "path": f"/{PFX}-vw", "dest": PORT_VLESS_WS, "xver": 0},
                    {"dest": PORT_TROJAN_TCP, "xver": 0}
                ]
            },
            "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": tls_settings},
            "sniffing": {"enabled": True, "routeOnly": True, "destOverride": ["http", "tls"]}
        },
        {
            "listen": "127.0.0.1", "port": PORT_VLESS_GRPC, "protocol": "vless",
            "settings": {"clients": [{"id": vless_uuid, "level": 0, "email": "vless-grpc@inner"}], "decryption": "none", "fallbacks": [{"dest": 45232, "xver": 0}]},
            "streamSettings": {"network": "grpc", "grpcSettings": {"serviceName": f"{PFX}-vg"}},
            "sniffing": {"enabled": False}
        },
        {
            "listen": "127.0.0.1", "port": PORT_TROJAN_GRPC, "protocol": "trojan",
            "settings": {"clients": trojan_clients, "fallbacks": [{"dest": PORT_FALLBACK, "xver": 0}]},
            "streamSettings": {"network": "grpc", "grpcSettings": {"serviceName": f"{PFX}-tg"}},
            "sniffing": {"enabled": False}
        },
        {
            "listen": "127.0.0.1", "port": PORT_VLESS_WS, "protocol": "vless",
            "settings": {"clients": [{"id": vless_uuid, "level": 0, "email": "vless-ws@inner"}], "decryption": "none"},
            "streamSettings": {"network": "ws", "wsSettings": {"path": f"/{PFX}-vw"}, "acceptProxyProtocol": False},
            "sniffing": {"enabled": False}
        },
        {
            "listen": "127.0.0.1", "port": PORT_TROJAN_TCP, "protocol": "trojan",
            "settings": {"clients": trojan_clients, "fallbacks": [{"dest": PORT_FALLBACK, "xver": 0}]},
            "streamSettings": {"network": "tcp", "acceptProxyProtocol": False},
            "sniffing": {"enabled": False}
        }
    ],
    "dns": {
        "servers": ["https+local://1.1.1.1/dns-query", "https+local://8.8.8.8/dns-query", "localhost"],
        "queryStrategy": "UseIP"
    },
    "outbounds": [
        {"protocol": "dns", "tag": "dns-out", "settings": {"address": "1.1.1.1", "port": 53}},
        {"protocol": "freedom", "tag": "direct", "settings": {"domainStrategy": "AsIs"}, "multiplex": {"enabled": True, "concurrency": 8}},
        {"protocol": "blackhole", "tag": "blocked", "settings": {"response": {"type": "none"}}}
    ],
    "routing": {
        "domainStrategy": "IPIfNonMatch",
        "rules": [
            {"type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked"},
            {"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"},
            {"type": "field", "port": "25", "outboundTag": "blocked"},
            {"type": "field", "port": "53", "network": "udp,tcp", "outboundTag": "dns-out"}
        ]
    },
    "policy": {
        "levels": {"0": {"handshakeTimeout": 4, "connIdle": 300, "uplinkOnly": 2, "downlinkOnly": 5, "bufferSize": 256}},
        "system": {"statsInboundUplink": False, "statsInboundDownlink": False}
    }
}

tmp = os.path.join(os.environ['_CFG_OUT'] + '.tmp')
with open(tmp, 'w', encoding='utf-8') as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False)
os.replace(tmp, os.environ['_CFG_OUT'])
print(f"  [OK] {len(trojan_clients)} Trojan 客户端, {len(certs_dict)} 证书")
PYEOF
  ) || py_exit=$?
  [[ $py_exit -eq 0 ]] || die "sync_xray_config 失败"
  
  chown -R root:"$LANDING_USER" "$LANDING_BASE" \
    || die "chown LANDING_BASE failed"
  chmod 750 "$LANDING_BASE"
  chmod 640 "$LANDING_CONF"
  success "Xray 配置同步完成"
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
  atomic_write "$_jd_conf" 644 root:root <<'JDEOF'
[Journal]
SystemMaxUse=200M
RuntimeMaxUse=50M
JDEOF
  success "logrotate 已配置"
}

create_systemd_service(){
  local _svc_ram_mb; _svc_ram_mb=$(free -m 2>/dev/null | awk '/Mem:/{print $2}') || _svc_ram_mb=1024
  local _svc_fd=$(( _svc_ram_mb * 800 ))
  (( _svc_fd < 524288 ))   && _svc_fd=524288
  (( _svc_fd > 10485760 )) && _svc_fd=10485760

  local _svc_tmp; _svc_tmp="$(_mktemp "svc" 3)"
  
  cat > "$_svc_tmp" <<SVCEOF
[Unit]
Description=Xray Landing Node (independent from mack-a)
After=network.target nss-lookup.target
StartLimitIntervalSec=900
StartLimitBurst=10
OnFailure=xray-landing-recovery.service

[Service]
Type=simple
User=${LANDING_USER}
NoNewPrivileges=true
ExecStartPre=/bin/sh -c 'test -f ${LANDING_CONF} || { echo "config.json missing"; exit 1; }'
ExecStartPre=/bin/sh -c 'python3 -c "import json,sys; json.load(open(sys.argv[1]))" ${LANDING_CONF} 2>/dev/null || { echo "config.json invalid"; exit 1; }'
ExecStart=${LANDING_BIN} run -config ${LANDING_CONF}
Environment=XRAY_LOCATION_ASSET=/usr/local/share/xray-landing
Restart=on-failure
RestartSec=15s
LimitNOFILE=${_svc_fd}
LimitNPROC=65535
TasksMax=infinity
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=${LANDING_BASE} /usr/local/share/xray-landing ${CERT_BASE}
ReadWritePaths=${LANDING_LOG}
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

  mv -f "$_svc_tmp" "/etc/systemd/system/${LANDING_SVC}" || die "service unit 写入失败"
  chmod 644 "/etc/systemd/system/${LANDING_SVC}"

  mkdir -p /etc/systemd/system/xray-landing.service.d
  atomic_write /etc/systemd/system/xray-landing.service.d/limits.conf 644 root:root <<XRAYLIMITS
[Service]
LimitNOFILE=${_svc_fd}
TasksMax=infinity
XRAYLIMITS

  atomic_write /etc/systemd/system/xray-landing-recovery.service 644 root:root <<'RECEOF'
[Unit]
Description=Xray Landing Recovery
DefaultDependencies=no

[Service]
Type=oneshot
ExecStart=/bin/sh -c '\
  mkdir -p /run/lock 2>/dev/null; \
  lockfile="/run/lock/xray-landing-recovery.lock"; \
  tsfile="/run/lock/xray-landing-recovery.last"; \
  ( flock -n 9 || exit 0; \
    now=$(date +%s); \
    if [ -f "$tsfile" ]; then \
      last=$(cat "$tsfile" 2>/dev/null || echo 0); \
      delta=$((now - last)); \
      if [ "$delta" -lt 1800 ]; then \
        logger -t xray-landing-recovery "Recovery rate-limited"; exit 0; \
      fi; \
    fi; \
    echo "$now" > "$tsfile"; \
    cert_ok=0; cfg_ok=0; \
    for d in ${CERT_BASE}/*/fullchain.pem; do [ -f "$d" ] && cert_ok=1 && break; done; \
    python3 -c "import json,sys; json.load(open(sys.argv[1]))" ${LANDING_CONF} 2>/dev/null && cfg_ok=1 || true; \
    if [ "$cert_ok" = "1" ] && [ "$cfg_ok" = "1" ]; then \
      systemctl reset-failed ${LANDING_SVC} 2>/dev/null || true; \
      systemctl start ${LANDING_SVC} 2>/dev/null || true; \
    fi \
  ) 9>"$lockfile" \
'
RECEOF

  mkdir -p "$LANDING_LOG"
  chown "$LANDING_USER:$LANDING_USER" "$LANDING_LOG"
  chmod 750 "$LANDING_LOG"
  write_logrotate

  systemctl daemon-reload \
    || die "daemon-reload 失败"
  systemctl enable "$LANDING_SVC"
  systemctl restart "$LANDING_SVC"
  sleep 2

  if systemctl is-active --quiet "$LANDING_SVC"; then
    success "服务 ${LANDING_SVC} 已启动"
  else
    journalctl -u "$LANDING_SVC" --no-pager -n 30
    die "服务启动失败"
  fi
}

setup_firewall(){
  load_manager_config
  info "重建防火墙 Chain ${FW_CHAIN}..."
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

  iptables -N "$FW_TMP" 2>/dev/null || iptables -F "$FW_TMP"
  iptables -A "$FW_TMP" -i lo                                       -j ACCEPT
  iptables -A "$FW_TMP" -p tcp  --dport "$ssh_port"                 -j ACCEPT
  iptables -A "$FW_TMP" -m conntrack --ctstate INVALID,UNTRACKED    -j DROP
  iptables -A "$FW_TMP" -m conntrack --ctstate ESTABLISHED,RELATED  -j ACCEPT
  iptables -A "$FW_TMP" -p icmp --icmp-type echo-request -m limit --limit 10/second --limit-burst 20 -j ACCEPT || true
  iptables -A "$FW_TMP" -p icmp --icmp-type echo-request            -j DROP

  local count=0 tips=()
  local _conf_files=()
  while IFS= read -r f; do _conf_files+=("$f"); done \
    < <(find "${MANAGER_BASE}/nodes" -name "*.conf" -not -name "tmp-*.conf" -type f 2>/dev/null | sort)

  for meta in "${_conf_files[@]+${_conf_files[@]}}"; do
    [[ -f "$meta" ]] || continue
    local tip; tip=$(grep '^TRANSIT_IP=' "$meta" 2>/dev/null | cut -d= -f2-)
    if [[ -z "$tip" ]] || ! python3 -c "import ipaddress,sys; ipaddress.IPv4Address(sys.argv[1])" "$tip" 2>/dev/null; then
      warn "跳过 ${meta}（无效 TRANSIT_IP）"
      continue
    fi
    tips+=("$tip")
  done

  while IFS= read -r tip; do
    [[ -n "$tip" ]] || continue
    iptables -A "$FW_TMP" -s "${tip}/32" -p tcp --dport "$LANDING_PORT" -j ACCEPT
    info "  ACCEPT ← ${tip}/32:${LANDING_PORT}"; (( ++count )) || true
  done < <(printf '%s\n' "${tips[@]+${tips[@]}}" | sort -u)

  iptables -A "$FW_TMP" -j DROP
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
    ip6tables -A "$FW_TMP6" -p tcp --dport "$ssh_port" -j ACCEPT
    ip6tables -A "$FW_TMP6" -m conntrack --ctstate INVALID,UNTRACKED -j DROP
    ip6tables -A "$FW_TMP6" -p ipv6-icmp -j ACCEPT
    ip6tables -A "$FW_TMP6" -p tcp --dport "$LANDING_PORT" -j DROP
    ip6tables -A "$FW_TMP6" -j DROP
    ip6tables -I INPUT 1 -m comment --comment "xray-landing-v6-swap" -j "$FW_TMP6"
    _bulldoze_input_refs6 "$FW_CHAIN6"
    ip6tables -F "$FW_CHAIN6" 2>/dev/null || true; ip6tables -X "$FW_CHAIN6" 2>/dev/null || true
    ip6tables -E "$FW_TMP6" "$FW_CHAIN6"
    ip6tables -I INPUT 1 -m comment --comment "xray-landing-v6-jump" -j "$FW_CHAIN6"
    while ip6tables -D INPUT -m comment --comment "xray-landing-v6-swap" 2>/dev/null; do :; done
  fi

  _persist_iptables "$ssh_port"
  success "防火墙已配置：${count} 中转 IP"
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

  atomic_write "$fw_script" 700 root:root <<FWEOF
#!/bin/sh
# LANDING_FW_VERSION=${VERSION}_\$(date +%Y%m%d)
_detect_ssh(){
  local p="\$(sshd -T 2>/dev/null | awk '/^port /{print \$2; exit}' || true)"
  [ -z "\$p" ] && p="\$(ss -tlnp 2>/dev/null | awk '/sshd/{for(i=1;i<=NF;i++) if(\$i~/:[0-9]+\$/){sub(/^.*:/,\"\",\$i);print \$i;exit}}' | head -1 || true)"
  if echo "\$p" | grep -qE '^[0-9]+\$' && [ "\$p" -ge 1 ] && [ "\$p" -le 65535 ]; then echo "\$p"; else echo "${ssh_port}"; fi
}
SSH_PORT="\$( _detect_ssh )"
while iptables  -D INPUT -m comment --comment 'xray-landing-jump' 2>/dev/null; do :; done
while iptables  -D INPUT -m comment --comment 'xray-landing-swap' 2>/dev/null; do :; done
iptables  -F ${FW_CHAIN}  2>/dev/null || true; iptables  -X ${FW_CHAIN}  2>/dev/null || true
iptables  -N ${FW_CHAIN}  2>/dev/null || true
iptables -A ${FW_CHAIN} -i lo                                       -j ACCEPT
iptables -A ${FW_CHAIN} -p tcp  --dport \${SSH_PORT}                -j ACCEPT
iptables -A ${FW_CHAIN} -m conntrack --ctstate INVALID,UNTRACKED    -j DROP
iptables -A ${FW_CHAIN} -m conntrack --ctstate ESTABLISHED,RELATED  -j ACCEPT
iptables -A ${FW_CHAIN} -p icmp --icmp-type echo-request -m limit --limit 10/second --limit-burst 20 -j ACCEPT
iptables -A ${FW_CHAIN} -p icmp --icmp-type echo-request             -j DROP
$(while IFS= read -r u; do
  [[ -n "$u" ]] && echo "iptables -A ${FW_CHAIN} -s ${u}/32 -p tcp --dport ${LANDING_PORT} -j ACCEPT"
done < <(printf '%s\n' "${transit_ips[@]+${transit_ips[@]}}" | sort -u))
iptables -A ${FW_CHAIN} -j DROP
iptables -I INPUT 1 -m comment --comment 'xray-landing-jump' -j ${FW_CHAIN}
if [ -f /proc/net/if_inet6 ] && ip6tables -L >/dev/null 2>&1 && [ "\$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 1)" != "1" ]; then
  while ip6tables -D INPUT -m comment --comment 'xray-landing-v6-jump' 2>/dev/null; do :; done
  while ip6tables -D INPUT -m comment --comment 'xray-landing-v6-swap' 2>/dev/null; do :; done
  ip6tables -F ${FW_CHAIN6} 2>/dev/null || true; ip6tables -X ${FW_CHAIN6} 2>/dev/null || true
  ip6tables -N ${FW_CHAIN6} 2>/dev/null || true
  ip6tables -A ${FW_CHAIN6} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ip6tables -A ${FW_CHAIN6} -i lo -j ACCEPT
  ip6tables -A ${FW_CHAIN6} -p tcp      --dport \${SSH_PORT}     -j ACCEPT
  ip6tables -A ${FW_CHAIN6} -p ipv6-icmp                          -j ACCEPT
  ip6tables -A ${FW_CHAIN6} -j DROP
  ip6tables -I INPUT 1 -m comment --comment 'xray-landing-v6-jump' -j ${FW_CHAIN6}
fi
FWEOF

  local rsvc="/etc/systemd/system/xray-landing-iptables-restore.service"
  atomic_write "$rsvc" 644 root:root <<RSTO
[Unit]
Description=Restore iptables rules for xray-landing
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=${fw_script}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
RSTO

  systemctl daemon-reload || die "daemon-reload 失败"
  systemctl enable xray-landing-iptables-restore.service \
    || die "iptables 持久化服务 enable 失败"
  info "防火墙规则已写入: ${fw_script}"
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
  load_manager_config
  echo ""
  echo -e "${BOLD}── 增加新节点 ────────────────────────────────────────────────────${NC}"
  echo -e "${BOLD}${RED}  ⚠  域名必须设为【仅DNS/灰云】，严禁开启小黄云代理！${NC}"
  echo ""
  read -rp "新节点域名: " NEW_DOMAIN
  NEW_DOMAIN=$(tr '[:upper:]' '[:lower:]' <<< "$NEW_DOMAIN")
  validate_domain "$NEW_DOMAIN"

  local existing_pass=""
  if [[ -d "${MANAGER_BASE}/nodes" ]]; then
    existing_pass=$(python3 - "${MANAGER_BASE}/nodes" "$NEW_DOMAIN" 2>/dev/null <<'PYNODE'
import sys
from pathlib import Path
nodes_dir, target = Path(sys.argv[1]), sys.argv[2]
for p in sorted(nodes_dir.glob("*.conf")):
    if p.name.startswith("tmp-"): continue
    data = {}
    try:
        for line in p.read_text(errors="replace").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                data[k.strip()] = v.strip()
    except: continue
    if data.get("DOMAIN") == target and data.get("PASSWORD"):
        print(data["PASSWORD"]); break
PYNODE
) || true
  fi

  if [[ -n "$existing_pass" ]]; then
    warn "域名 ${NEW_DOMAIN} 已存在，复用密码: ${existing_pass}"
    NEW_PASS="$existing_pass"
  else
    read -rp "Trojan 密码（16位以上，直接回车自动生成）: " NEW_PASS
    if [[ -z "$NEW_PASS" ]]; then
      NEW_PASS=$(gen_password)
      info "已生成密码: ${NEW_PASS}"
    fi
    validate_password "$NEW_PASS"
  fi

  read -rp "对应中转机公网 IP: " NEW_TRANSIT
  validate_ipv4 "$NEW_TRANSIT"

  local USE_CF_TOKEN="$CF_TOKEN"
  [[ -z "$USE_CF_TOKEN" ]] && {
    read -rp "Cloudflare API Token: " USE_CF_TOKEN
    validate_cf_token "$USE_CF_TOKEN"
    CF_TOKEN="$USE_CF_TOKEN"
  }

  _acquire_lock

  local _staged_mgr=""
  if [[ -n "$CF_TOKEN" ]]; then
    _staged_mgr="$(_mktemp "mgr" 3)"
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

  setup_fallback_decoy
  issue_certificate "$NEW_DOMAIN" "$USE_CF_TOKEN"
  local PUB_IP; PUB_IP=$(get_public_ip)

  local _safe_dom; _safe_dom=$(printf '%s' "$NEW_DOMAIN" | tr '.:/' '___')
  local _safe_ip;  _safe_ip=$(printf '%s' "$NEW_TRANSIT" | tr '.:' '__')
  local _node_conf="${MANAGER_BASE}/nodes/${_safe_dom}_${_safe_ip}.conf"
  local _tmp_node; _tmp_node="$(_mktemp "node" 3 "${MANAGER_BASE}/nodes")"
  cat >"$_tmp_node" <<NEOF_TMP
DOMAIN=${NEW_DOMAIN}
PASSWORD=${NEW_PASS}
TRANSIT_IP=${NEW_TRANSIT}
PUBLIC_IP=${PUB_IP}
CREATED=$(date +%Y%m%d_%H%M%S)
NEOF_TMP
  chmod 600 "$_tmp_node"

  if ! ( sync_xray_config ); then
    rm -f "$_tmp_node" "${_staged_mgr:-}" 2>/dev/null
    _release_lock; die "Xray配置同步失败"
  fi

  mv -f "$_tmp_node" "$_node_conf"

  if ! ( setup_firewall ); then
    rm -f "$_node_conf"
    ( sync_xray_config ) 2>/dev/null || true
    _release_lock; die "防火墙配置失败"
  fi

  trap - INT TERM
  systemctl restart "$LANDING_SVC"
  sleep 1

  if ! systemctl is-active --quiet "$LANDING_SVC"; then
    rm -f "$_node_conf"
    ( sync_xray_config ) 2>/dev/null || true
    ( setup_firewall ) 2>/dev/null || true
    _release_lock; die "服务重启失败"
  fi

  [[ -n "${_staged_mgr:-}" && -f "${_staged_mgr:-}" ]] \
    && mv -f "$_staged_mgr" "$MANAGER_CONFIG" 2>/dev/null || true

  _release_lock
  success "节点添加成功"
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
    printf "  [%2d] %-40s 中转: %s\n" $((++n)) "$dom" "$ip"
  done < <(find "${MANAGER_BASE}/nodes" -name "*.conf" -type f 2>/dev/null | sort)

  (( n == 0 )) && { warn "无可删除的节点"; return; }
  (( n == 1 )) && die "仅剩最后一个节点！请使用清除本系统所有数据"

  read -rp "请输入编号: " DEL_INPUT
  [[ "$DEL_INPUT" =~ ^[0-9]+$ ]] || die "请输入数字"
  local idx=$(( DEL_INPUT - 1 ))
  (( idx >= 0 && idx < n )) || die "编号越界（共 ${n} 个）"

  local DEL_CONF="${node_files[$idx]}"
  local DEL_DOMAIN; DEL_DOMAIN=$(grep '^DOMAIN=' "$DEL_CONF" 2>/dev/null | cut -d= -f2-)

  read -rp "确认删除 ${DEL_DOMAIN}？[y/N]: " CONFIRM
  [[ "$CONFIRM" =~ ^[Yy]$ ]] || { info "已取消"; return; }

  _acquire_lock

  mv -f "$DEL_CONF" "${DEL_CONF}.deleting" 2>/dev/null || true

  if ! ( sync_xray_config ); then
    mv -f "${DEL_CONF}.deleting" "$DEL_CONF" 2>/dev/null || true
    _release_lock; die "Xray配置同步失败"
  fi

  if ! ( setup_firewall ); then
    mv -f "${DEL_CONF}.deleting" "$DEL_CONF" 2>/dev/null || true
    ( sync_xray_config ) 2>/dev/null || true
    _release_lock; die "防火墙更新失败"
  fi

  systemctl restart "$LANDING_SVC"
  sleep 1

  rm -f "${DEL_CONF}.deleting" 2>/dev/null || true
  _release_lock
  success "节点已删除"
}

do_set_port(){
  [[ -f "$INSTALLED_FLAG" ]] || die "未安装"
  load_manager_config
  local new_port="${1:-}"
  [[ -n "$new_port" ]] || { read -rp "新落地机监听端口: " new_port; }
  validate_port "$new_port"
  (( new_port >= 1024 )) || die "端口必须 >= 1024"
  [[ "$new_port" == "$LANDING_PORT" ]] && { success "端口相同，无需变更"; return; }
  ss -tlnp 2>/dev/null | grep -q ":${new_port} " && die "端口 ${new_port} 已被占用"

  local old_port="$LANDING_PORT"
  _acquire_lock

  LANDING_PORT="$new_port"
  save_manager_config

  if ! ( sync_xray_config ); then
    LANDING_PORT="$old_port"; save_manager_config
    ( sync_xray_config ) 2>/dev/null || true
    _release_lock; die "sync 失败"
  fi

  if ! ( setup_firewall ); then
    LANDING_PORT="$old_port"; save_manager_config
    ( sync_xray_config ) 2>/dev/null || true
    _release_lock; die "防火墙更新失败"
  fi

  _persist_iptables "$(detect_ssh_port)"
  systemctl restart "$LANDING_SVC"
  sleep 2

  if ! systemctl is-active --quiet "$LANDING_SVC"; then
    LANDING_PORT="$old_port"; save_manager_config
    ( sync_xray_config ) 2>/dev/null || true
    ( setup_firewall ) 2>/dev/null || true
    systemctl restart "$LANDING_SVC" 2>/dev/null || true
    _release_lock; die "服务启动失败"
  fi

  _release_lock
  success "端口已变更为 ${new_port}"
  warn "必须登录中转机删除旧路由并用新 Token 重新导入！"
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
  while IFS= read -r meta; do
    [[ -f "$meta" ]] || continue
    local dom ip ts
    dom=$(grep '^DOMAIN='     "$meta" 2>/dev/null | cut -d= -f2- || echo "?")
    ip=$(grep  '^TRANSIT_IP=' "$meta" 2>/dev/null | cut -d= -f2- || echo "?")
    ts=$(grep  '^CREATED='    "$meta" 2>/dev/null | cut -d= -f2- || echo "?")
    printf "  [节点%2d] %-38s 中转: %-18s 创建: %s\n" $((++n)) "$dom" "$ip" "$ts"
  done < <(find "${MANAGER_BASE}/nodes" -name "*.conf" -type f 2>/dev/null | sort)
  [[ $n -eq 0 ]] && warn "  （无节点）"
  echo ""

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
        printf "  %-40s 证书剩余: ${YELLOW}%d 天${NC}\n" "$_sdom" "$_days"
      else
        printf "  %-40s ${RED}证书已过期${NC}\n" "$_sdom"
      fi
      _any_cert=1
    else
      printf "  %-40s ${RED}证书缺失${NC}\n" "$_sdom"
    fi
  done < <(find "${MANAGER_BASE}/nodes" -name "*.conf" -type f 2>/dev/null | sort)
  [[ $_any_cert -eq 0 ]] && warn "  （无证书）"

  crontab -l 2>/dev/null | grep -qE 'acme\.sh.*(--cron|cron)' \
    && echo -e "  acme.sh cron:    ${GREEN}✓${NC}" \
    || echo -e "  acme.sh cron:    ${RED}✗${NC}"

  systemctl is-enabled --quiet xray-landing-iptables-restore.service 2>/dev/null \
    && echo -e "  iptables 服务:   ${GREEN}✓ enabled${NC}" \
    || echo -e "  iptables 服务:   ${RED}✗${NC}"

  echo ""
  systemctl is-active --quiet "$LANDING_SVC" 2>/dev/null \
    && echo -e "  ${GREEN}整体状态: 正常${NC}" \
    || echo -e "  ${RED}整体状态: 异常${NC}"
}

print_pairing_info(){
  local pub_ip="$1" domain="$2" password="$3" transit_ip="$4"
  load_manager_config

  local token=""
  token=$(python3 - "$pub_ip" "$domain" "$LANDING_PORT" "$VLESS_UUID" "$password" 2>&1 <<'TOKPY'
import json, base64, sys
ip, dom, port, uuid, pwd = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5]
d = {'ip': ip, 'dom': dom, 'port': port, 'uuid': uuid, 'pwd': pwd, 'pfx': uuid[:8]}
print(base64.b64encode(json.dumps(d, separators=(',',':')).decode())
TOKPY
) || { warn "token 生成异常"; token=""; }

  echo ""
  echo -e "${BOLD}${GREEN}"
  echo "╔══════════════════════════════════════════════════════════════════╗"
  printf "║  落地机公网 IP  : %-45s║\n" "$pub_ip"
  printf "║  落地机域名(SNI): %-45s║\n" "$domain"
  printf "║  落地机后端端口: %-45s║\n" "$LANDING_PORT"
  printf "║  Trojan密码     : %-45s║\n" "$password"
  printf "║  VLESS UUID    : %-45s║\n" "${VLESS_UUID}"
  echo "╚══════════════════════════════════════════════════════════════════╝"
  echo -e "${NC}"
  [[ -n "$token" ]] \
    && echo -e "  ${BOLD}${CYAN}bash install_transit_v3.0.sh --import ${token}${NC}" \
    || warn "  token 生成失败"
}

purge_all(){
  echo ""
  warn "此操作清除本脚本所有内容（不影响 mack-a）"
  read -rp "确认清除？输入 'DELETE': " CONFIRM
  [[ "$CONFIRM" == "DELETE" ]] || { info "已取消"; return; }

  if [[ -f "${ACME_HOME}/acme.sh" ]]; then
    env ACME_HOME="$ACME_HOME" "${ACME_HOME}/acme.sh" --uninstall-cronjob 2>/dev/null || true
  fi

  systemctl stop    "$LANDING_SVC" 2>/dev/null || true
  systemctl disable "$LANDING_SVC" 2>/dev/null || true
  systemctl disable --now xray-landing-iptables-restore.service 2>/dev/null || true
  rm -f "/etc/systemd/system/${LANDING_SVC}" \
        "/etc/systemd/system/xray-landing-recovery.service" \
        "/etc/systemd/system/xray-landing-iptables-restore.service" 2>/dev/null || true
  rm -f /run/lock/xray-landing-recovery.last 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true

  if [[ -f "${ACME_HOME}/acme.sh" ]]; then
    while IFS= read -r meta; do
      local dom; dom=$(grep '^DOMAIN=' "$meta" 2>/dev/null | cut -d= -f2-) || continue
      [[ -n "$dom" ]] && {
        env ACME_HOME="$ACME_HOME" "${ACME_HOME}/acme.sh" --home "$ACME_HOME" --remove --domain "$dom" --ecc 2>/dev/null || true
      }
    done < <(find "${MANAGER_BASE}/nodes" -name "*.conf" -type f 2>/dev/null | sort)
  fi

  rm -rf "$LANDING_BASE" "$MANAGER_BASE"
  rm -f /etc/logrotate.d/xray-landing \
        /etc/profile.d/xray-recovery-alert.sh \
        /etc/profile.d/xray-cert-alert.sh 2>/dev/null || true
  rm -rf /etc/systemd/journald.conf.d/xray-landing.conf 2>/dev/null || true

  _landing_cleanup
  success "清除完毕，mack-a 未受影响"
}

installed_menu(){
  echo ""
  echo -e "${BOLD}${CYAN}══ 落地机管理菜单 ══════════════════════════════════════════════${NC}"
  echo "  1. 增加新节点"
  echo "  2. 删除节点"
  echo "  3. 修改监听端口"
  echo "  4. 清除本系统所有数据"
  echo "  5. 显示状态"
  echo "  6. 退出"
  echo ""
  read -rp "请选择 [1-6]: " CHOICE
  case "$CHOICE" in
    1) add_node;      installed_menu ;;
    2) delete_node;   installed_menu ;;
    3) do_set_port;   installed_menu ;;
    4) purge_all;      installed_menu ;;
    5) show_status;    installed_menu ;;
    6) info "退出"; exit 0 ;;
    *) warn "无效选项"; installed_menu ;;
  esac
}

main(){
  echo -e "${BOLD}"
  echo "╔══════════════════════════════════════════════════════════════════╗"
  printf "║     落地机安装脚本  %-46s║\n" "${VERSION}"
  echo "║     5协议单端口回落 · routeOnly嗅探 · AsIs出站 · 完全隔离    ║"
  echo "╚══════════════════════════════════════════════════════════════════╝"
  echo -e "${NC}"

  if [[ "${1:-}" == "--uninstall" ]]; then purge_all; exit 0; fi
  if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then show_help; exit 0; fi
  if [[ "${1:-}" == "set-port" ]]; then do_set_port "${2:-}"; exit $?; fi
  if [[ "${1:-}" == "--status" ]]; then show_status; exit $?; fi

  if [[ -f "$INSTALLED_FLAG" ]]; then
    installed_menu
  else
    echo ""
    echo -e "${BOLD}${CYAN}══ 落地机全新安装 ${VERSION} ══════════════════════════════════════════${NC}"
    check_deps
    optimize_kernel_network
    install_xray_binary
    create_system_user
    create_systemd_service
    touch "$INSTALLED_FLAG"
    echo ""
    success "══ 落地机安装完成！══"
    add_node
  fi
}

main "$@"
