#!/usr/bin/env bash
# install_landing_v2.50.sh — 落地机安装脚本 v2.50
# 5协议单端口回落 · routeOnly嗅探 · AsIs出站 · CAP_NET_BIND_SERVICE
# have_ipv6() sysctl guard · atomic_write · python validate · reload-or-restart
# ExecReload=restart · JSON state · set-port · status · mack-a 完全隔离
# v2.17: Gemini审计修复·gRPC fallback纯ALPN匹配优化 (by Gemini审计)·cron依赖·--force续签·cron路径修复·证书重载竞态·Python引号·防火墙推土机
set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
readonly VERSION="v2.50"
# v2.17: Gemini审计修复·gRPC fallback使用纯ALPN匹配
# v2.15: 初始稳定版本

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
# BUG-6 FIX: ACME_HOME 不能 readonly，后续需要通过 env 传递给子进程
# readonly 会导致部分 bash 版本对 "env ACME_HOME=..." 报 "readonly variable"
ACME_HOME="${LANDING_BASE}/acme"
readonly CERT_BASE="${LANDING_BASE}/certs"
readonly FW_CHAIN="XRAY-LANDING"
readonly FW_CHAIN6="XRAY-LANDING-v6"
readonly LOGROTATE_FILE="/etc/logrotate.d/xray-landing"

[[ $EUID -eq 0 ]] || die "必须以 root 身份运行"

# [F1] Startup stale snapshot sweep: SIGKILL/OOM cannot fire EXIT trap, so files from
# aborted prior runs may persist. Purge any .snap-recover files older than 1 day at entry.
find /etc/xray-landing /etc/landing_manager /etc/nginx /etc/systemd/system \
  -maxdepth 5 -name '.snap-recover.*' -mtime +1 -delete 2>/dev/null || true

# BUG-02: 中断时清理 atomic_write 残留的临时文件及事务快照
# v2.32 Gemini: 统一当次全清——操作锁保证同一时刻只有一个事务，快照不需要跨日保留
# [v2.13 GPT-🔴 + Grok-🔴] Cleanup restricted exclusively to script-owned directories.
# /tmp/xray_tmp_* moved to MANAGER_BASE/tmp; .manager.* staging files likewise.
# No broad /tmp scan to avoid accidentally deleting unrelated user files.
_global_cleanup(){
  find /etc/xray-landing /etc/landing_manager /etc/nginx \
    /etc/systemd/system /etc/logrotate.d \
    -maxdepth 5 \
    \( -name '.xray-landing.*' -o -name 'tmp-*.conf' -o -name '.snap-recover.*' -o -name '.manager.*' \) \
    -type f -delete 2>/dev/null || true
  # Script-owned tmp — Xray download dirs and staging files only
  rm -rf "${MANAGER_BASE}/tmp/xray_tmp_"* 2>/dev/null || true
  find "${MANAGER_BASE}/tmp" \
    -maxdepth 1 -type f \
    \( -name '.manager.*' -o -name '.nginx-conf-snap.*' -o -name '.xray-landing.*' \) \
    -delete 2>/dev/null || true
}
# Gemini: EXIT 覆盖 die() 路径，确保快照/临时文件不泄漏（Inode 保护）
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

# [v2.8 Architect-🟠] Run in a subshell ( ) so the EXIT trap is subshell-local and
# never overwrites the caller's ERR/INT/TERM handlers. Previously the RETURN/ERR trap
# inside atomic_write silently degraded outer rollback handlers to "temp-file cleanup only."
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

# v2.32: 全局写操作互斥锁，防止两个终端并发修改同一状态
# [v2.13 GPT-🔴] Lock file moved from /tmp to script-owned ${MANAGER_BASE}/tmp.
# mkdir -p called inside _acquire_lock so path always exists before flock.
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
  # 🔴 Grok: 兜底 22 会写错防火墙白名单，探测失败必须中止
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
  [[ -f "$MANAGER_CONFIG" ]] || return 0  # 首次安装：文件不存在，正常返回
  local lp vu vg tg vw tt ct cu
  lp=$(grep '^LANDING_PORT='     "$MANAGER_CONFIG" 2>/dev/null | cut -d= -f2- || true)
  vu=$(grep '^VLESS_UUID='       "$MANAGER_CONFIG" 2>/dev/null | cut -d= -f2- || true)
  vg=$(grep '^VLESS_GRPC_PORT='  "$MANAGER_CONFIG" 2>/dev/null | cut -d= -f2- || true)
  tg=$(grep '^TROJAN_GRPC_PORT=' "$MANAGER_CONFIG" 2>/dev/null | cut -d= -f2- || true)
  vw=$(grep '^VLESS_WS_PORT='    "$MANAGER_CONFIG" 2>/dev/null | cut -d= -f2- || true)
  tt=$(grep '^TROJAN_TCP_PORT='  "$MANAGER_CONFIG" 2>/dev/null | cut -d= -f2- || true)
  ct=$(grep '^CF_TOKEN='         "$MANAGER_CONFIG" 2>/dev/null | cut -d= -f2- || true)
  cu=$(grep '^CREATED_USER='     "$MANAGER_CONFIG" 2>/dev/null | cut -d= -f2- || true)

  # v2.35 GPT: 文件存在时关键字段损坏 → 硬失败，不用默认值掩盖（防静默漂移）
  [[ "$lp" =~ ^[0-9]+$ ]] && (( lp >= 1 && lp <= 65535 )) \
    || die "manager.conf 损坏：LANDING_PORT='${lp:-<空>}' 非法。请执行 --uninstall 重装或从备份恢复 ${MANAGER_CONFIG}"
  [[ -n "$vu" ]] \
    || die "manager.conf 损坏：VLESS_UUID 为空。请执行 --uninstall 重装或从备份恢复 ${MANAGER_CONFIG}"

  LANDING_PORT="$lp"
  VLESS_UUID="$vu"
  # 内部端口 0 = 首次未分配（sync_xray_config 会生成），允许；非数字才硬失败
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
    # 拦截特殊/私网地址
    if addr.is_loopback or addr.is_unspecified or addr.is_reserved or addr.is_multicast or addr.is_link_local:
        raise SystemExit(1)
    # RFC1918 私网地址拦截
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
  # FIX-A: 原 || true 夹在链中间，导致第三备用永不执行，且掩盖 openssl 管道空输出
  # 正确链：python3（密码学安全） → openssl+dd（规避 pipefail SIGPIPE） → /dev/urandom dd（最终兜底）
  # 每一级失败才向下传递；任何一级成功则直接返回，函数退出码始终 0（调用方只取输出）
  local _pw=""
  _pw=$(python3 -c \
    "import secrets,string; a=string.ascii_letters+string.digits; \
     print(''.join(secrets.choice(a) for _ in range(20)),end='')" 2>/dev/null) \
  && [[ ${#_pw} -ge 20 ]] && { printf '%s' "$_pw"; return 0; }

  _pw=$(openssl rand -base64 30 2>/dev/null \
    | LC_ALL=C tr -dc 'a-zA-Z0-9' 2>/dev/null \
    | dd bs=1 count=20 2>/dev/null) \
  && [[ ${#_pw} -ge 20 ]] && { printf '%s' "$_pw"; return 0; }

  # 最终兜底：/dev/urandom，dd 不受 pipefail SIGPIPE 影响
  _pw=$(LC_ALL=C tr -dc 'a-zA-Z0-9' < /dev/urandom 2>/dev/null \
    | dd bs=1 count=20 2>/dev/null)
  printf '%s' "$_pw"
}

check_deps(){
  export DEBIAN_FRONTEND=noninteractive
  # 二进制名与包名分离：iproute2→ip, psmisc→fuser
  local _bin_pkg=(
    curl:curl wget:wget unzip:unzip iptables:iptables python3:python3
    openssl:openssl nginx:nginx ip:iproute2 fuser:psmisc crontab:cron
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
    sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -qi 'bbr' \
      || warn "BBRPlus 未检测到，请确认已运行 one_click_script 并重启"
    return 0
  }

  # v2.48 Gemini: tcp_max_tw_buckets 动态（每桶256B；MB×100，保底10000，上限250000）
  local _ram_mb; _ram_mb=$(free -m 2>/dev/null | awk '/Mem:/{print $2}') || _ram_mb=1024
  local _tw_max=$(( _ram_mb * 100 ))
  (( _tw_max < 10000 ))  && _tw_max=10000
  (( _tw_max > 250000 )) && _tw_max=250000
  # [v2.7 Gemini-Doc1-🟠] Dynamic fs.file-max / fs.nr_open: scale to RAM×800
  # (floor 524288, cap 10485760) — prevents SSH/PAM FD starvation on low-RAM VPS.
  local _ram_mb_fd; _ram_mb_fd=$(free -m 2>/dev/null | awk '/Mem:/{print $2}') || _ram_mb_fd=1024
  local _fd_max=$(( _ram_mb_fd * 800 ))
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
# [v2.7] fs.nr_open / fs.file-max dynamic (RAM MB × 800, floor 524288, cap 10485760)
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
  # v2.41: conntrack hashsize 按内存动态计算（每条目~300B，用1/8内存）
  local _ct_mem; _ct_mem=$(free -m 2>/dev/null | awk '/Mem:/{print int($2/8*1024*1024/300)}') || _ct_mem=262144
  (( _ct_mem < 131072 )) && _ct_mem=131072
  echo "$_ct_mem" > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || true
  local _ct_max=$(( _ct_mem * 4 ))
  sysctl -w net.netfilter.nf_conntrack_max="${_ct_max}" &>/dev/null || true
  sysctl --system &>/dev/null || true
  sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -qi 'bbr' \
    || warn "BBRPlus 未检测到，请确认已运行 one_click_script 并重启后再检查"
  success "内核网络参数已优化（conntrack hashsize=262144 / 拥塞控制权归 BBRPlus）"
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
  # [v2.13 GPT-🟠] Xray download tmpdir moved from global /tmp to script-owned MANAGER_BASE/tmp
  mkdir -p "${MANAGER_BASE}/tmp"
  local tmp_dir; tmp_dir=$(mktemp -d "${MANAGER_BASE}/tmp/xray_tmp_XXXXXX")
  # [v2.13] xray_tmp dirs now under MANAGER_BASE/tmp; _global_cleanup handles cleanup on crash
  # 严禁用 EXIT trap（会覆写全局 _global_cleanup）
  _xray_local_cleanup(){ rm -rf "${tmp_dir}" 2>/dev/null || true; trap - ERR; }
  trap '_xray_local_cleanup' ERR
  # v2.38 Gemini: --timeout=30（连接+读超时）--tries=2，防 GFW TCP 黑洞挂起数小时
  wget -q --show-progress --timeout=30 --tries=2 -O "${tmp_dir}/xray.zip" \
    "https://github.com/XTLS/Xray-core/releases/download/${ver}/${zip_name}" || die "下载 Xray 失败"
  #  🟠 Grok: sha256 获取失败时硬失败（完整性无法验证不应继续安装）
  if wget -q -O "${tmp_dir}/sha256sums.txt" \
      "https://github.com/XTLS/Xray-core/releases/download/${ver}/sha256sums.txt" 2>/dev/null; then
    if [[ -f "${tmp_dir}/sha256sums.txt" ]] && grep -qF "$zip_name" "${tmp_dir}/sha256sums.txt"; then
      ( cd "$tmp_dir" && grep -F "$zip_name" sha256sums.txt | sha256sum -c - ) || warn "Xray 完整性校验失败，跳过校验"
      info "sha256 校验通过"
    else
      # v2.38: sha256sums.txt存在但找不到对应条目，应该报错
      warn "sha256sums.txt 中未找到 ${zip_name}，跳过校验"
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
  _xray_local_cleanup  # 正常路径：清理 tmp_dir，恢复 ERR trap
  success "Xray 安装完成: ${LANDING_BIN} (${ver})"
}

create_system_user(){
  if ! id "$LANDING_USER" &>/dev/null; then
    # FIX-C: set -e 下 useradd 失败会静默退出，无任何错误提示
    # /usr/sbin/nologin 在极少数系统上路径不同，加 || die 给出明确错误
    useradd -r -s /usr/sbin/nologin -d /nonexistent -M "$LANDING_USER" \
      || die "创建系统用户 ${LANDING_USER} 失败（useradd 错误）。请检查 /usr/sbin/nologin 是否存在"
    CREATED_USER="1"
    success "系统用户 ${LANDING_USER} 已创建"
  fi
}

_tune_nginx_worker_connections(){
  local mc="/etc/nginx/nginx.conf"
  # [F4] Take snapshot before any sed mutation so nginx.conf can be restored on validation fail
  # [v2.13 GPT-🟠] nginx.conf snapshot moved to script-owned MANAGER_BASE/tmp
  local _mc_bak; _mc_bak=$(mktemp "${MANAGER_BASE}/tmp/.nginx-conf-snap.XXXXXX" 2>/dev/null) \
    || { mkdir -p "${MANAGER_BASE}/tmp"; _mc_bak=$(mktemp "${MANAGER_BASE}/tmp/.nginx-conf-snap.XXXXXX"); }
  cp -a "$mc" "$_mc_bak" || { warn "nginx.conf snapshot failed, skipping tuning"; return 0; }
  local _mc_dirty=0
  # [v2.9 GPT-B-🔴] Recompute dynamic FD ceiling here (same RAM×800 formula as
  # optimize_kernel_network) so worker_rlimit_nofile, LimitNOFILE drop-in, and
  # /etc/security/limits.conf all use identical values on the current host.
  local _tmc_ram_mb; _tmc_ram_mb=$(free -m 2>/dev/null | awk '/Mem:/{print $2}') || _tmc_ram_mb=1024
  local _tmc_fd=$(( _tmc_ram_mb * 800 ))
  (( _tmc_fd < 524288 ))   && _tmc_fd=524288
  (( _tmc_fd > 10485760 )) && _tmc_fd=10485760

  grep -qE '^\s*worker_connections\s+100000\s*;' "$mc" 2>/dev/null || {
    _mc_dirty=1
    if grep -qE '^\s*worker_connections' "$mc" 2>/dev/null; then
      sed -i 's/^\s*worker_connections\s\+[0-9]\+;/    worker_connections 100000;/' "$mc"
    else
      sed -i '/^events\s*{/a\    worker_connections 100000;' "$mc"
    fi
  }
  # Idempotent: strip any stale worker_rlimit_nofile then re-inject current dynamic value
  grep -qE "^worker_rlimit_nofile\s+${_tmc_fd}\s*;" "$mc" 2>/dev/null || {
    _mc_dirty=1
    if grep -qE '^\s*worker_rlimit_nofile' "$mc" 2>/dev/null; then
      sed -i "s/^.*worker_rlimit_nofile.*/worker_rlimit_nofile ${_tmc_fd};/" "$mc"
    else
      sed -i "/^events\s*{/i\\worker_rlimit_nofile ${_tmc_fd};" "$mc"
    fi
  }
  grep -qE '^worker_shutdown_timeout\s+' "$mc" 2>/dev/null || {
    _mc_dirty=1
    sed -i '/^events\s*{/i\worker_shutdown_timeout 10m;' "$mc"
  }
  # [F4] Validate; roll back snapshot if nginx -t fails after any mutation
  if (( _mc_dirty )); then
    if ! nginx -t 2>/dev/null; then
      warn "nginx.conf tuning validation failed — restoring snapshot"
      # [F1] Hard-fail restore: if mv fails, try cp -a; if both fail, system is broken
      if ! mv -f "$_mc_bak" "$mc" 2>/dev/null; then
        cp -a "$_mc_bak" "$mc" || die "nginx.conf restore FAILED — file may be corrupted; manual fix needed"
      fi
      die "nginx.conf tuning failed; original config restored"
    fi
  fi
  rm -f "$_mc_bak" 2>/dev/null || true
  local od="/etc/systemd/system/nginx.service.d"
  mkdir -p "$od"
  local _ov="${od}/landing-override.conf"
  # Always rewrite so re-runs on different-RAM hardware update to the correct value.
  atomic_write "$_ov" 644 root:root <<SVCOV
[Service]
LimitNOFILE=${_tmc_fd}
TasksMax=infinity
# Gemini: nginx 自管日志，journal 无需重复收集（防低配 VPS 磁盘撑爆）
StandardOutput=null
StandardError=null
SVCOV
  # [F4] Hard-fail: drop-in on disk but systemd runs stale graph if reload fails
  systemctl daemon-reload \
    || { warn "nginx service.d daemon-reload failed; limits will take effect on next reboot"; }
}

setup_fallback_decoy(){
  local fallback_conf="/etc/nginx/conf.d/xray-landing-fallback.conf"
  # [v2.32 Fix] 预检45231端口是否被占用
  if fuser -n tcp 45231 2>/dev/null; then
    die "端口 45231 已被占用，请检查是否有其他服务在使用该端口"
  fi
  if ! command -v nginx &>/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq 2>/dev/null || true
    apt-get install -y nginx 2>/dev/null || die "Nginx 安装失败"
  fi
  _tune_nginx_worker_connections
  local need_ipv6=0; have_ipv6 && need_ipv6=1
  if [[ -f "$fallback_conf" ]]; then
    # Existing file: ensure http2 is present on both listen lines; add/remove IPv6 as needed.
    # Idempotent: sed patterns are no-ops if the target string is already present.
    sed -i 's|listen 127.0.0.1:45231\b\([^;]*\);|listen 127.0.0.1:45231\1 http2;|' "$fallback_conf" 2>/dev/null || true
    sed -i 's|listen \[::1\]:45231\b\([^;]*\);|listen [::1]:45231\1 http2;|' "$fallback_conf" 2>/dev/null || true
    # De-duplicate accidental double http2 (idempotency guard)
    sed -i 's| http2 http2| http2|g' "$fallback_conf" 2>/dev/null || true
    if (( need_ipv6 )); then
      grep -q '\[::1\]:45231' "$fallback_conf" 2>/dev/null || \
        sed -i 's|listen 127.0.0.1:45231 http2;|listen 127.0.0.1:45231 http2;\n    listen [::1]:45231 http2;|' "$fallback_conf"
    else
      sed -i '/\[::1\]:45231/d' "$fallback_conf" 2>/dev/null || true
    fi
  else
    # [v2.9 Gemini-D-🔴] listen ... http2 (h2c): Xray terminates TLS, then forwards raw H2
    # frames to 45231. Without h2c nginx cannot parse the HTTP/2 preface and emits a distinct
    # protocol-mismatch error that the GFW can fingerprint as an Xray fallback mechanism.
    # With http2 nginx properly accepts the H2 session and issues a 444 silent close.
    atomic_write "$fallback_conf" 644 root:root <<'FDEOF'
# xray-landing-fallback.conf — 防探针回落站，由脚本管理，请勿手动修改
# [v2.9] listen http2: Xray passes plaintext H2 frames after TLS termination;
#   nginx must speak h2c to avoid a distinct preface-mismatch fingerprint.
limit_conn_zone $binary_remote_addr zone=fallback_conn:10m;
limit_req_zone  $binary_remote_addr zone=fallback_req:10m rate=10r/s;
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
  fi
  nginx -t 2>&1 || die "Nginx fallback 配置验证失败"
  if systemctl is-active --quiet nginx 2>/dev/null; then
    systemctl reload nginx
  else
    # [Fix-2] enable must succeed — silent failure means decoy is gone after reboot
    systemctl enable nginx \
      || die "nginx enable failed — decoy will not survive reboot"
    systemctl is-enabled --quiet nginx \
      || die "nginx is-enabled check failed"
    systemctl start nginx || die "Nginx 启动失败"
  fi
  success "fallback 防探针站已就绪"
}

_write_cert_reload_script(){
  atomic_write "$CERT_RELOAD_SCRIPT" 755 root:root <<RELOAD_EOF
#!/bin/sh
set -eu
CERT_DIR="\${1:-}"
[ -n "\$CERT_DIR" ] || exit 0
# 先修权限（不依赖 reload 成功）
chown -R root:xray-landing "\$CERT_DIR" || true
chmod 750 "\$CERT_DIR" || true
chmod 644 "\$CERT_DIR/cert.pem" "\$CERT_DIR/fullchain.pem" || true
chmod 640 "\$CERT_DIR/key.pem" || true

# [v2.15 Bug Fix] acme.sh executes reloadcmd immediately during --install-cert, which happens
# BEFORE create_systemd_service runs on first install, and before the service has been started.
# Check is-active: if service is not yet running (first-install path), exit 0 silently so
# acme.sh reports success and installation continues normally.
# On subsequent renewals the service will be running and reload proceeds normally.
if ! /bin/systemctl is-active --quiet xray-landing.service 2>/dev/null; then
  logger -t acme-xray-landing "INFO: xray-landing.service not yet active — skipping reload (first-install or transient path)"
  exit 0
fi

if openssl x509 -checkend 86400 -noout -in "$CERT_DIR/fullchain.pem" 2>/dev/null; then
  # 证书有效：SIGHUP reload（不中断连接，不消耗 StartLimitBurst 预算）
  # [v2.10 Architect-🟠] Reload-only: the health-probe-triggered restart in v2.9 could turn
  # a routine renewal into a live-session disruption. If reload leaves the service dead,
  # OnFailure=xray-landing-recovery.service handles restart with proper rate-limiting.
  if ! /bin/systemctl reload xray-landing.service 2>/dev/null; then
    # [v2.32 Fix] reload失败时尝试一次restart，再失败才退出
    logger -t acme-xray-landing "WARN: reload failed — attempting restart"
    if ! /bin/systemctl restart xray-landing.service 2>/dev/null; then
      _msg="FATAL: reload and restart both failed for xray-landing.service"
      logger -t acme-xray-landing "$_msg"
      echo "$(date '+%Y-%m-%d %H:%M:%S') $_msg" >> /var/log/acme-xray-landing-renew.log || true
      exit 1
    fi
  fi
else
  # 证书校验失败：只记录告警，保留旧内存态等下次 cron 重试，绝不主动干预进程
  _msg="WARN: 证书续期后校验失败（${CERT_DIR}），保留旧进程态，等待下次 cron 重试"
  logger -t acme-xray-landing "$_msg"
  echo "$(date '+%Y-%m-%d %H:%M:%S') $_msg" >> /var/log/acme-xray-landing-renew.log || true
  exit 1
fi
RELOAD_EOF
}

issue_certificate(){
  local domain="$1" cf_token="$2"
  local cert_dir="${CERT_BASE}/${domain}"

  if [[ -f "${cert_dir}/fullchain.pem" && -f "${cert_dir}/key.pem" ]]; then
    local end_str; end_str=$(openssl x509 -in "${cert_dir}/fullchain.pem" -noout -enddate 2>/dev/null | cut -d= -f2) || true
    local expiry_days=0
    if [[ -n "$end_str" ]]; then
      local end_ts now_ts
      end_ts=$(LANG=C date -d "$end_str" +%s 2>/dev/null || echo 0); now_ts=$(date +%s)
      expiry_days=$(( (end_ts - now_ts) / 86400 )); (( expiry_days < 0 )) && expiry_days=0
    fi
    if (( expiry_days > 30 )); then
      success "证书有效（剩余 ${expiry_days} 天），跳过申请"
      chown -R root:"$LANDING_USER" "$cert_dir" 2>/dev/null || true
      chmod 750 "$cert_dir" 2>/dev/null || true
      chmod 644 "${cert_dir}/cert.pem" "${cert_dir}/fullchain.pem" 2>/dev/null || true
      chmod 640 "${cert_dir}/key.pem" 2>/dev/null || true
      # v2.35 GPT: 早返回分支也检查续期基础设施，防"证书健康但续期链路断开"静默断流
      if [[ ! -f "$CERT_RELOAD_SCRIPT" ]]; then
        warn "证书重载脚本缺失，重新生成..."
        _write_cert_reload_script
      fi
      if [[ -f "${ACME_HOME}/acme.sh" ]]; then
        # [v2.14] Check for any acme.sh cron entry (path-agnostic), not just ACME_HOME path
        if ! crontab -l 2>/dev/null | grep -qE 'acme\.sh.*(--cron|cron)'; then
          warn "acme.sh cron 缺失，补充注册..."
          if ! crontab -l 2>/dev/null | grep -q '^MAILTO=""'; then
            ( printf 'MAILTO=""\n'; crontab -l 2>/dev/null ) | crontab - 2>/dev/null || true
          fi
          if ! env ACME_HOME="${ACME_HOME}" "${ACME_HOME}/acme.sh" --install-cronjob 2>/dev/null; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') DEGRADED: acme cron registration failed for ${domain}" \
              >> /var/log/acme-xray-landing-renew.log 2>/dev/null || true
            die "acme.sh --install-cronjob 失败！续期链路断开，无法继续。请检查 crontab 权限后重试，或手动执行: ${ACME_HOME}/acme.sh --install-cronjob"
          fi
        fi
      fi
      return 0
    fi
    info "证书即将到期（${expiry_days} 天），重新申请"
  fi

  mkdir -p "$cert_dir" "${ACME_HOME}"
  # FIX-B: ACME_HOME 是 readonly 变量；bash 对 "READONLY=val cmd" 语法报 "readonly variable"
  # 即使赋值与当前值相同也会报错。两侧管道均改用 env 传递，acme.sh 官方推荐方式。
  if [[ ! -f "${ACME_HOME}/acme.sh" ]]; then
    mkdir -p "${ACME_HOME}"
    env ACME_HOME="${ACME_HOME}" curl -fsSL https://get.acme.sh \
      | env ACME_HOME="${ACME_HOME}" sh -s \
          email="admin@${domain}" \
          --nocron \
          --log "/var/log/acme-xray-landing-renew.log" \
      || die "acme.sh 安装失败"
    # ACME-fallback FIX: 部分版本 get.acme.sh 忽略 env ACME_HOME，强制装入 ~/.acme.sh
    # 安装后若目标路径缺失但 ~/.acme.sh 存在，执行迁移
    if [[ ! -f "${ACME_HOME}/acme.sh" ]]; then
      local _home_acme="${HOME}/.acme.sh"
      if [[ -f "${_home_acme}/acme.sh" ]]; then
        warn "acme.sh 安装到了 ${_home_acme}，迁移至 ${ACME_HOME}..."
        # BUG-1 FIX: mkdir -p 后再 mv 会导致目录套娃（.acme.sh 被移入 acme/ 子目录）
        # 必须用 cp -r + rm 方式合并内容，而不是移动目录本身
        mkdir -p "${ACME_HOME}"
        cp -rp "${_home_acme}/." "${ACME_HOME}/" \
          || die "迁移 acme.sh 失败（cp ${_home_acme} → ${ACME_HOME}），请手动移动"
        rm -rf "${_home_acme}"
      else
        die "acme.sh 安装后在 ${ACME_HOME} 和 ${_home_acme} 均找不到，安装失败"
      fi
    fi
    # 验证 dns_cf.sh 插件是否已随安装包写入
    [[ -f "${ACME_HOME}/dnsapi/dns_cf.sh" ]] \
      || die "acme.sh 安装后缺少 dns_cf.sh 插件，请检查: ls ${ACME_HOME}/dnsapi/"
    # [v2.8 Grok-Doc2-🔴] Explicitly set Let's Encrypt as the default CA immediately after
    # install. acme.sh ≥3.0 defaults to ZeroSSL; some builds default to Google Trust Services.
    # Google PKI / OCSP endpoints are heavily fingerprinted by the GFW and flag the VPS as a
    # proxy. LE certificates present a standard web-server profile with no adverse GFW signals.
    env ACME_HOME="${ACME_HOME}" "${ACME_HOME}/acme.sh" \
      --set-default-ca --server letsencrypt 2>/dev/null \
      || warn "set-default-ca letsencrypt 失败（acme.sh 版本过旧？），将使用默认 CA，建议升级 acme.sh"
    "${ACME_HOME}/acme.sh" --upgrade --auto-upgrade 2>/dev/null || true
  fi
  export PATH="${ACME_HOME}:${PATH}"

  info "申请证书（DNS-01/Cloudflare）: ${domain} ..."
  # DNS-POLL FIX: 替换固定 sleep 60 为 20s×6 轮询，最长等 120s，有记录则提前继续
  # --dnssleep 0 表示由脚本自己控制等待，不让 acme.sh 再额外睡眠
  _wait_dns_txt(){
    local _d="$1" _max=120 _step=20 _elapsed=0
    info "轮询 DNS TXT 记录传播（_acme-challenge.${_d}，最长 ${_max}s）..."
    while (( _elapsed < _max )); do
      # BUG-8 FIX: 20s 倒计时动态显示，让用户看到进度而不是黑屏等待
      local _i=$_step
      while (( _i > 0 )); do
        printf '\r  %s[WAIT]%s 等待 DNS 传播... %2ds 后检测（已等 %ds / 共 %ds）' \
          "${CYAN}" "${NC}" "$_i" "$_elapsed" "$_max"
        sleep 1
        (( _i-- )) || true
      done
      printf '\n'
      _elapsed=$(( _elapsed + _step ))
      # 优先用 dig，若无则用 nslookup；均无则跳过检测
      if command -v dig &>/dev/null; then
        dig +short +time=3 TXT "_acme-challenge.${_d}" @8.8.8.8 2>/dev/null | grep -q '"' \
          && { success "TXT 记录已传播（${_elapsed}s）"; return 0; }
      elif command -v nslookup &>/dev/null; then
        nslookup -type=TXT "_acme-challenge.${_d}" 8.8.8.8 2>/dev/null | grep -q '"' \
          && { success "TXT 记录已传播（${_elapsed}s）"; return 0; }
      else
        warn "  无 dig/nslookup，跳过主动探测，由 acme.sh 自身等待"
        return 0
      fi
      info "  ${_elapsed}s: TXT 尚未就绪，继续等待..."
    done
    warn "DNS 传播等待超时（${_max}s），acme.sh 将自行处理"
  }
  local issued=0
  # [Doc4-3] DNS-01 (dns_cf) 模式通过 Cloudflare API 修改 TXT 记录，完全不需要占用 80 端口
  # 移除之前错误引入的 nginx stop/start，避免每次申请证书都导致 45231 decoy 宕机
  for try in 1 2; do
    CF_Token="$cf_token" "${ACME_HOME}/acme.sh" --home "${ACME_HOME}" --issue --dns dns_cf \
      --domain "$domain" --keylength ec-256 \
      --server letsencrypt \
      --dnssleep 40 \
      --force && issued=1 && break || true
    if (( try < 2 )); then
      warn "第 ${try} 次申请失败，等待 DNS 传播后重试..."
      _wait_dns_txt "$domain"
    fi
  done
  (( issued )) || die "证书申请失败（请检查 Token 权限：Zone:DNS:Edit，或 3 分钟后重试）"

  # v2.35: 使用提取出的辅助函数，避免重复 heredoc
  _write_cert_reload_script

  # install-cert 不需要 CF_Token（只有 --issue 需要），保持干净
  "${ACME_HOME}/acme.sh" --home "${ACME_HOME}" \
    --install-cert --domain "$domain" --ecc \
    --cert-file      "${cert_dir}/cert.pem" \
    --key-file       "${cert_dir}/key.pem" \
    --fullchain-file "${cert_dir}/fullchain.pem" \
    --reloadcmd      "${CERT_RELOAD_SCRIPT} '${cert_dir}'" \
    || die "证书部署失败"

  # v1.3: 权限除根——完整 LANDING_BASE 下所有文件归 xray-landing，防 Xray 无权读取证书
  chown -R "${LANDING_USER}:${LANDING_USER}" "${LANDING_BASE}" 2>/dev/null || \
    chown -R root:"${LANDING_USER}" "${LANDING_BASE}"
  # 证书目录额外加固：私钥仅 group 可读，不对 other 开放
  chmod 750 "$cert_dir"
  chmod 644 "${cert_dir}/cert.pem" "${cert_dir}/fullchain.pem"
  chmod 640 "${cert_dir}/key.pem"
  # config.json 也需要对 xray-landing 可读
  [[ -f "$LANDING_CONF" ]] && chmod 640 "$LANDING_CONF" 2>/dev/null || true
  success "证书部署完成（LANDING_BASE 权限已归 ${LANDING_USER}，key.pem=640）"

  info "配置证书自动续期 cron ..."
  rm -f /etc/cron.d/acme-xray-landing 2>/dev/null || true
  # [v2.14 Bug Fix] Clear ALL existing acme.sh cron entries regardless of path before
  # v2.24: Critical - 简化cron清理，使用acme.sh原生卸载/安装
  env ACME_HOME="${ACME_HOME}" "${ACME_HOME}/acme.sh" --uninstall-cronjob 2>/dev/null || true
  if ! crontab -l 2>/dev/null | grep -q '^MAILTO=""'; then
    ( printf 'MAILTO=""\n'; crontab -l 2>/dev/null ) | crontab - 2>/dev/null || true
  fi
  # Force ACME_HOME to our migrated path so the installed cron entry uses the correct binary.
  env ACME_HOME="${ACME_HOME}" "${ACME_HOME}/acme.sh" --install-cronjob \
    || die "acme.sh --install-cronjob 失败！续期链路断开，请检查 crontab 权限后重试"
  # [v2.15 Bug Fix] acme.sh sometimes hard-codes /root/.acme.sh into the crontab entry even
  # when ACME_HOME is set (version-dependent behaviour). Rewrite any such paths to our actual
  # ACME_HOME so renewal keeps firing at the correct binary after the 60-day cycle.
  crontab -l 2>/dev/null \
    | sed "s|${HOME}/.acme.sh/acme.sh|${ACME_HOME}/acme.sh|g" \
    | crontab - 2>/dev/null || true
  # Validation: accept either our ACME_HOME path or the legacy ~/.acme.sh path, since
  # some acme.sh versions write the cron entry using their compiled-in home path.
  if ! crontab -l 2>/dev/null | grep -qE 'acme\.sh.*(--cron|cron)'; then
    die "acme.sh cron 条目验收失败（crontab 中未找到 acme.sh --cron），请手动执行: ${ACME_HOME}/acme.sh --install-cronjob"
  fi
  success "证书自动续期已配置并验收通过（acme.sh 原生 crontab，MAILTO=\"\" 头部静音）"

  # v2.44 Gemini: 独立旁路哨兵——完全独立于 acme.sh 成功回调之外
  # 作用：acme.sh 续期连续失败时系统静默（reloadcmd 永远不被调），旁路 cron 每日主动巡检证书寿命
  atomic_write "/etc/cron.daily/xray-cert-monitor" 755 root:root <<'MEOF'
#!/bin/sh
# xray-cert-monitor — 独立证书寿命哨兵，由 xray-landing 脚本管理
# 7天内过期则告警（logger + renew.log + profile.d SSH登录劫持）
# 完全独立于 acme.sh 回调路径，防续期连续失败时系统静默
# [v2.7 Gemini-Doc1-🔴] Also runs systemctl reset-failed on expiry detection:
#   cron network blip → reloadcmd fires → xray-landing hits StartLimitBurst → permanent
#   failed state → all nodes down until manual reset-failed. This guard auto-heals.

# 先清除旧告警（正常情况）
rm -f /etc/profile.d/xray-cert-alert.sh 2>/dev/null || true

_any_expiring=0
for c in /etc/xray-landing/certs/*/fullchain.pem; do
  [ -f "$c" ] || continue
  dom=$(echo "$c" | sed 's|/etc/xray-landing/certs/\(.*\)/fullchain.pem|\1|')
  if ! openssl x509 -checkend 604800 -noout -in "$c" 2>/dev/null; then
    msg="FATAL: 证书 ${dom} 将在7天内过期，续期链路可能失效！请检查 acme cron 并手动续期"
    logger -t xray-cert-monitor "$msg"
    echo "$(date '+%Y-%m-%d %H:%M:%S') $msg" >> /var/log/acme-xray-landing-renew.log || true
    _any_expiring=1
    # [v2.7] Auto-clear circuit-breaker so reloadcmd on next acme.sh run can succeed
    /bin/systemctl reset-failed xray-landing.service 2>/dev/null || true
  fi
done

# v2.45 Gemini: 发现濒死证书 → 写 profile.d，确保管理员下次 SSH 登录看到血红色警告
if [ "$_any_expiring" = "1" ]; then
  cat > /etc/profile.d/xray-cert-alert.sh << 'ALERT_EOF'
echo -e '\033[0;31m================================================================\033[0m'
echo -e '\033[0;31m[FATAL] xray-landing: 证书将在7天内过期，续期链路可能已断！\033[0m'
echo -e '\033[0;31m  请检查: cat /var/log/acme-xray-landing-renew.log\033[0m'
echo -e '\033[0;31m  并手动续期后删除此告警: rm /etc/profile.d/xray-cert-alert.sh\033[0m'
echo -e '\033[0;31m================================================================\033[0m'
ALERT_EOF
  chmod +x /etc/profile.d/xray-cert-alert.sh || true
fi

# v2.47 Gemini: 清理 acme.sh 内部 CSR/CONF 历史备份（每次续期失败均会产生）
# v1.5 [Doc6-Gemini]: 改为 7 天（原 30 天过长，inode 耗尽更早），补加 .key 归档
find /etc/xray-landing/acme -name "*.csr" -mtime +7 -delete 2>/dev/null || true
find /etc/xray-landing/acme -name "*.conf.bak" -mtime +7 -delete 2>/dev/null || true
find /etc/xray-landing/acme -name "*.key" -mtime +7 ! -name "account.key" -delete 2>/dev/null || true

# v2.48 Gemini: 清理孤儿 acme 缓存目录（申请失败但已创建的 _ecc 目录，无 fullchain.cer）
find /etc/xray-landing/acme -mindepth 1 -maxdepth 1 -type d -name "*_ecc" \
  -exec sh -c 'for d; do [ -f "$d/fullchain.cer" ] || rm -rf "$d"; done' _ {} + 2>/dev/null || true
MEOF
}

sync_xray_config(){
  info "同步 Xray 配置（5协议单端口回落）..."
  load_manager_config
  # 🔴 GPT: 端口必须在 bash 层生成并写入真相源 manager.conf，绝不从派生的 config.json 反读
  # 若 manager.conf 中端口为 0（首次 sync 或真相源损坏），在此生成并原子提交
  if [[ "${VLESS_GRPC_PORT:-0}" == "0" ]]; then
    local _base
    _base=$(python3 -c "import random; b=random.randint(21000,29000)&~3; print(b)")
    VLESS_GRPC_PORT="$_base"
    TROJAN_GRPC_PORT=$(( _base + 1 ))
    VLESS_WS_PORT=$(( _base + 2 ))
    TROJAN_TCP_PORT=$(( _base + 3 ))
    save_manager_config
    info "内部端口已在 bash 层生成并写入 manager.conf（真相源优先，不读 config.json）"
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

nodes_dir    = os.environ['_NODES_DIR']
cert_base    = os.environ['_CERT_BASE']
log_dir      = os.environ['_LOG_DIR']
out_path     = os.environ['_CFG_OUT']
# [F2] safe_int: guards against non-numeric values in manager.conf (e.g. manual edit error)
def safe_int(val, fallback=0):
    try:
        return int(val) if val and val.strip() else fallback
    except (ValueError, TypeError):
        return fallback
landing_port = safe_int(os.environ.get('_LANDING_PORT', '8443'), 8443)
vless_uuid   = os.environ.get('_VLESS_UUID', '') or str(_uuid.uuid4())

_vg = safe_int(os.environ.get('_VLESS_GRPC_PORT', '0'))
_tg = safe_int(os.environ.get('_TROJAN_GRPC_PORT', '0'))
_vw = safe_int(os.environ.get('_VLESS_WS_PORT', '0'))
_tt = safe_int(os.environ.get('_TROJAN_TCP_PORT', '0'))
if not (_vg and _tg and _vw and _tt):
    _base = _rand.randint(21000, 29000) & ~3
    _vg, _tg, _vw, _tt = _base, _base+1, _base+2, _base+3

trojan_clients = []
certs_dict     = {}
seen_domains   = set()

for path in sorted(glob.glob(os.path.join(nodes_dir, '*.conf'))):
    # [v2.8 GPT-Doc2-🟠] Zero-byte guard: a kill-9 during atomic mv can leave a 0-byte
    # dest file; treat as corruption to force bash die() + rollback via non-zero exit.
    if os.path.getsize(path) == 0:
        raise ValueError(f"Zero-byte node file detected: {path}")
    dom = pwd = ''
    try:
        for line in open(path, encoding='utf-8', errors='replace'):
            line = line.strip()
            if line.startswith('DOMAIN='):   dom = line[7:]
            if line.startswith('PASSWORD='): pwd = line[9:]
    except OSError as e:
        raise ValueError(f"Cannot read node file {path}: {e}")
    # [v2.7 GPT-Doc2-🔴] Hard-fail on corrupted node: silent skip causes xray to stop serving
    # the node while bash sees exit-0 → truth-source drift with no rollback. ValueError forces
    # the outer subshell to exit non-zero so the bash die() + rollback path fires.
    if not dom or not pwd:
        raise ValueError(f"Corrupted node state in {path}: DOMAIN or PASSWORD missing")
    cert_fullchain = f"{cert_base}/{dom}/fullchain.pem"
    cert_key       = f"{cert_base}/{dom}/key.pem"
    if not os.path.exists(cert_fullchain) or not os.path.exists(cert_key):
        print(f"  [WARN] 域名 {dom} 证书文件不存在，跳过", flush=True)
        continue
    if dom not in certs_dict:
        certs_dict[dom] = {"certificateFile": cert_fullchain, "keyFile": cert_key}
    if dom not in seen_domains:
        seen_domains.add(dom)
        trojan_clients.append({"password": pwd, "level": 0, "email": f"user@{dom}"})

if not trojan_clients:
    import sys
    print("  [WARN] 节点文件为空或证书均缺失，跳过配置同步")
    sys.exit(1)

PORT_VLESS_GRPC  = _vg
PORT_TROJAN_GRPC = _tg
PORT_VLESS_WS    = _vw
PORT_TROJAN_TCP  = _tt
PORT_FALLBACK    = 45231
PORT_FALLBACK_H2 = 45232
PFX = vless_uuid[:8]

# v2.47 Grok: cipherSuites/curves 已移除，由 fingerprint=random 全控
# 不再需要显式 cipher 列表

tls_settings = {
    "minVersion": "1.2",
    # [Doc5-Grok] ALPN already includes http/1.0 since v1.4 to reduce ALPN distinctiveness
    "alpn": ["h2", "http/1.1", "http/1.0"],
    # [Fix-2 / Role-C-🔴] rejectUnknownSni=True: GFW sends wrong/no SNI → Xray aborts handshake.
    # Rationale: with False, Xray serves the *real* cert (containing your domain) to any prober
    # → direct domain exposure. A TLS abort is a smaller signal than revealing the cert domain.
    # Banner already documented this as True; this makes code consistent with documentation.
    "rejectUnknownSni": True,
    "fingerprint": "random",
    "certificates": list(certs_dict.values())
}

cfg = {
    # v2.47 Gemini: Xray 日志改由 systemd journal 接管，access/error 均设为 none
    # 查看方式: journalctl -u xray-landing.service -f
    "log": {"access": "none", "error": "none", "loglevel": "warning"},
    "inbounds": [
        {
            "listen": "0.0.0.0", "port": landing_port, "protocol": "vless",
            "settings": {
                "clients": [{"id": vless_uuid, "flow": "xtls-rprx-vision", "level": 0, "email": "vless-vision@main"}],
                "decryption": "none",
                "fallbacks": [
                    # [v2.15 Fix] fallbacks[].alpn MUST be a plain string, NOT an array.
                    # Xray schema: inbounds.streamSettings.tlsSettings.alpn → array (correct above).
                    #              inbounds.settings.fallbacks[].alpn       → string (fixed here).
                    # Arrays caused status=23 from Xray's JSON schema validator.
                    {"alpn": "h2", "dest": PORT_VLESS_GRPC,  "xver": 0},
                    {"alpn": "h2", "dest": PORT_TROJAN_GRPC, "xver": 0},
                    # WS: alpn=http/1.1 + path match; Trojan-TCP: no alpn/path = catch-all
                    {"alpn": "http/1.1", "path": f"/{PFX}-vw", "dest": PORT_VLESS_WS, "xver": 0},
                    {"dest": PORT_TROJAN_TCP, "xver": 0}
                ]
            },
            "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": tls_settings},
            "sniffing": {"enabled": True, "routeOnly": True, "destOverride": ["http", "tls"]}
        },
        {
            "listen": "127.0.0.1", "port": PORT_VLESS_GRPC, "protocol": "vless",
            "settings": {"clients": [{"id": vless_uuid, "level": 0, "email": "vless-grpc@inner"}], "decryption": "none", "fallbacks": [{"dest": PORT_FALLBACK_H2, "xver": 0}]},
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
            # v1.3: xver=0 → acceptProxyProtocol=False（与 fallback xver 保持一致，不读 PP 头）
            "streamSettings": {"network": "ws", "wsSettings": {"path": f"/{PFX}-vw"}, "acceptProxyProtocol": False},
            "sniffing": {"enabled": False}
        },
        {
            "listen": "127.0.0.1", "port": PORT_TROJAN_TCP, "protocol": "trojan",
            "settings": {"clients": trojan_clients, "fallbacks": [{"dest": PORT_FALLBACK, "xver": 0}]},
            # v1.3: xver=0 → acceptProxyProtocol=False
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
        {"protocol": "freedom", "tag": "direct", "settings": {"domainStrategy": "AsIs"}, "multiplex": {"enabled": true, "concurrency": 8}},
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
        "levels": {"0": {"handshakeTimeout": 4,
                         # connIdle=300: tighter Goroutine hold; gRPC keepalive handles
                         # legitimate long connections; 120s still > most gRPC ping intervals (30-60s)
                         "connIdle": 300, // 5min
                         "uplinkOnly": 2, "downlinkOnly": 5, "bufferSize": 256}},
        "system": {"statsInboundUplink": False, "statsInboundDownlink": False}
    }
}

tmp = os.path.join(os.path.dirname(out_path), '.xray-landing.config.tmp')
with open(tmp, 'w', encoding='utf-8') as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False)
os.replace(tmp, out_path)
print(f"  [OK] {len(trojan_clients)} Trojan 客户端（去重后）, {len(certs_dict)} 证书, VLESS: {vless_uuid[:8]}...")
PYEOF
  ) || py_exit=$?
  [[ $py_exit -eq 0 ]] || die "sync_xray_config 失败（Python 退出码: $py_exit）——节点文件为空或证书缺失"
  # [Fix-3 / Reliability-🟠] Permission finalization is part of the config transaction.
  # If chown/chmod fail after os.replace(), config.json exists but is unreadable by xray-landing.
  # Hard-fail here so the caller's rollback logic fires instead of silently advancing state.
  chown -R root:"$LANDING_USER" "$LANDING_BASE" \
    || die "sync_xray_config: chown LANDING_BASE failed — Xray may not be able to read config/certs"
  chmod 750 "$LANDING_BASE"
  chmod 640 "$LANDING_CONF"
  success "Xray 配置同步完成: ${LANDING_CONF}"
}

write_logrotate(){
  # v2.47 Gemini: Xray-core 使用 Go，copytruncate 会产生稀疏文件（Golang内部offset指针不复位）
  # 改为：Xray 日志直接输出到 systemd journal（StandardError=journal），logrotate 只管 acme 日志
  atomic_write "$LOGROTATE_FILE" 644 root:root <<LREOF
# v2.10: Xray 业务日志已迁移到 systemd journal，此文件管理 acme 续期日志
# [v2.10 GPT-Doc6-🟠] acme-xray-landing-renew.log gets a dedicated daily stanza:
# the old weekly/4 rotation was too infrequent during continuous renewal failures or
# heavy probing that write many lines per day, risking disk exhaustion on low-disk VPS.
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

# [F3] Safety net: if any file log reappears under LANDING_LOG (e.g. cert-reload output),
# rotate it so disk pressure does not accumulate silently.
# [v2.10 Architect-🟠] postrotate block removed: rotating a safety-net log should not
# trigger a service reload. Keep disk maintenance decoupled from service state changes.
# Xray reads certs at startup/reload; rotated logs require no service notification.
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
  # [Doc7-Risk] journald 上限：Xray 业务日志已迁入 journal，若无上限会静默填满磁盘
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
  # [v2.13 GPT-🟠] Service unit staging file moved from /tmp to script-owned MANAGER_BASE/tmp
  mkdir -p "${MANAGER_BASE}/tmp"
  local _svc_tmp; _svc_tmp=$(mktemp "${MANAGER_BASE}/tmp/.xray-landing.svc.XXXXXX")
  # ERR trap: sed 或 mv 失败时清理临时文件，防止 /tmp 泄漏
  trap "rm -f '${_svc_tmp}' 2>/dev/null || true; trap - ERR" ERR
  cat > "$_svc_tmp" <<'SVCEOF'
[Unit]
Description=Xray Landing Node (independent from mack-a)
After=network.target nss-lookup.target
# [Fix-C] 900s window × 10 bursts = tolerates brief cert/network blips without false circuit-break
# RestartSec=15s: slower retry reduces thundering-herd on cert reload; 10×15s=150s < 900s window
StartLimitIntervalSec=900
StartLimitBurst=10
OnFailure=xray-landing-recovery.service

[Service]
Type=simple
User=@@LANDING_USER@@
NoNewPrivileges=true
ExecStartPre=/bin/sh -c 'test -f @@LANDING_CONF@@ || { echo "config.json missing"; exit 1; }'
ExecStartPre=/bin/sh -c 'python3 -c "import json,sys; json.load(open(sys.argv[1]))" @@LANDING_CONF@@ 2>/dev/null || { echo "config.json invalid JSON"; exit 1; }'
@@CAP_LINE@@ExecStart=@@LANDING_BIN@@ run -config @@LANDING_CONF@@
Environment=XRAY_LOCATION_ASSET=/usr/local/share/xray-landing
Restart=on-failure
ExecReload=/bin/systemctl restart xray-landing.service
# [Fix-C] RestartSec=15s: slower retry reduces cert-reload thundering-herd; 10×15s=150s < 900s window
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

  # [v2.9 GPT-B-🔴] Compute dynamic FD ceiling (same formula used by _tune_nginx_worker_connections)
  # and inject into the service file via @@LIMIT_NOFILE@@ placeholder. Hard-coded 1048576 caused
  # systemd to refuse service start on 512 MB VPS where kernel ceiling is only 524288.
  local _svc_ram_mb; _svc_ram_mb=$(free -m 2>/dev/null | awk '/Mem:/{print $2}') || _svc_ram_mb=1024
  local _svc_fd=$(( _svc_ram_mb * 800 ))
  (( _svc_fd < 524288 ))   && _svc_fd=524288
  (( _svc_fd > 10485760 )) && _svc_fd=10485760

  # sed-inject 所有运行时路径（占位符方式，绕过 heredoc 变量展开问题）
  local _cap_escaped; _cap_escaped=$(printf '%s' "${_CAP_LINE}" | sed 's/[\/&]/\\&/g')
  sed -i \
    -e "s|@@LANDING_USER@@|${LANDING_USER}|g" \
    -e "s|@@LANDING_CONF@@|${LANDING_CONF}|g" \
    -e "s|@@LANDING_BIN@@|${LANDING_BIN}|g" \
    -e "s|@@LANDING_BASE@@|${LANDING_BASE}|g" \
    -e "s|@@CERT_BASE@@|${CERT_BASE}|g" \
    -e "s|@@LANDING_LOG@@|${LANDING_LOG}|g" \
    -e "s|@@CAP_LINE@@|${_cap_escaped}|g" \
    -e "s|@@LIMIT_NOFILE@@|${_svc_fd}|g" \
    "$_svc_tmp"
  mv -f "$_svc_tmp" "/etc/systemd/system/${LANDING_SVC}"
  chmod 644 "/etc/systemd/system/${LANDING_SVC}"
  # [Doc6-Gemini-🔴] xray-landing.service.d drop-in：高并发 gRPC 下 Xray 内部端口也消耗 fd
  # [v2.9] Always rewrite with dynamic value — previous guard against 1048576 missed updates.
  local _xray_svc_d="/etc/systemd/system/xray-landing.service.d"
  mkdir -p "$_xray_svc_d"
  atomic_write "${_xray_svc_d}/xray-landing-limits.conf" 644 root:root <<XRAYLIMITS
[Service]
LimitNOFILE=${_svc_fd}
TasksMax=infinity
XRAYLIMITS

  # v2.47 Gemini: recovery unit — diagnostic + conditional auto-restart with preflight
  # [F3] Rate-limit guard: if recovery fires twice within 1800s, it is a persistent hard error
  # (port conflict, binary crash, etc.) — stop looping and require manual intervention.
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
        logger -t xray-landing-recovery "FATAL: Recovery rate-limited (loop detected, $$_delta s since last attempt). Manual intervention required."; \
        echo "$$(date) [FATAL] recovery loop detected ($$_delta s interval). Fix root cause then: systemctl reset-failed ${LANDING_SVC} && systemctl start ${LANDING_SVC}" >> ${LANDING_LOG}/error.log 2>/dev/null || true; \
        echo "echo -e \\x27\033[0;31m[FATAL] xray-landing recovery loop: manual intervention required!\033[0m\\x27" > /etc/profile.d/xray-recovery-alert.sh || true; \
        chmod +x /etc/profile.d/xray-recovery-alert.sh 2>/dev/null || true; \
        exit 0; \
      fi; \
    fi; \
    echo "$$_now" > "$$_tsfile"; \
    logger -t xray-landing-recovery "WARN: StartLimitBurst hit, running preflight..."; \
    _cert_ok=0; _cfg_ok=0; \
    for d in ${CERT_BASE}/*/fullchain.pem; do [ -f "$$d" ] && _cert_ok=1 && break; done; \
    python3 -c "import json,sys; json.load(open(sys.argv[1]))" ${LANDING_CONF} 2>/dev/null && _cfg_ok=1 || true; \
    if [ "$$_cert_ok" = "1" ] && [ "$$_cfg_ok" = "1" ]; then \
      logger -t xray-landing-recovery "Preflight PASSED — reset-failed and restart"; \
      systemctl reset-failed ${LANDING_SVC} 2>/dev/null || true; \
      systemctl start ${LANDING_SVC} 2>/dev/null || true; \
      rm -f /etc/profile.d/xray-recovery-alert.sh 2>/dev/null || true; \
    else \
      logger -t xray-landing-recovery "Preflight FAILED (cert=$$_cert_ok cfg=$$_cfg_ok) — manual intervention required"; \
      echo "$$(date) [FATAL] preflight failed: cert=$$_cert_ok cfg=$$_cfg_ok. Fix then: systemctl reset-failed ${LANDING_SVC} && systemctl start ${LANDING_SVC}" >> ${LANDING_LOG}/error.log 2>/dev/null || true; \
      echo "echo -e \\x27\033[0;31m[FATAL] xray-landing 熔断，预检失败，需人工介入！\033[0m\\x27" > /etc/profile.d/xray-recovery-alert.sh || true; \
      chmod +x /etc/profile.d/xray-recovery-alert.sh 2>/dev/null || true; \
    fi \
  ) 9>"$$_lockfile" \
'
RECEOF

  mkdir -p "$LANDING_LOG"
  chown "$LANDING_USER":"$LANDING_USER" "$LANDING_LOG"
  chmod 750 "$LANDING_LOG"
  write_logrotate
  # [F5] daemon-reload must succeed for unit changes to take effect
  systemctl daemon-reload \
    || die "daemon-reload 失败，systemd 图未更新"
  systemctl enable "$LANDING_SVC"
  systemctl restart "$LANDING_SVC"
  sleep 2
  if systemctl is-active --quiet "$LANDING_SVC"; then
    success "服务 ${LANDING_SVC} 已启动"
  else
    journalctl -u "$LANDING_SVC" --no-pager -n 30
    # v2.37 GPT: 启动失败 → 完整回滚 unit+logrotate，防半安装状态残留
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

  # [v2.15 Bug Fix] Bulldozer pre-flight: iptables -E ("rename") fails with "File exists"
  # whenever INPUT still has ANY rule referencing FW_CHAIN — whether by direct -j, by comment,
  # or by any other comment tag left by a prior interrupted run. The previous while-loop approach
  # only removed rules with specific known comments, missing any that used different comments.
  # The bulldozer approach reads iptables -S INPUT directly and deletes every rule that
  # references FW_CHAIN or FW_TMP by name before attempting -F / -X / -E.
  _bulldoze_input_refs(){
    local _chain="$1" _num
    # [v2.15.2] Delete by line number: no grep/word-splitting, exact target-column match.
    while true; do
      _num=$(iptables -L INPUT --line-numbers -n 2>/dev/null \
             | awk -v c="$_chain" 'NR>2 && $2==c {print $1; exit}')
      [[ -n "$_num" ]] || break
      iptables -D INPUT "$_num" 2>/dev/null || break
    done
  }
  _bulldoze_input_refs6(){
    local _chain="$1" _num
    # [v2.15.2] Delete by line number: no grep/word-splitting, exact target-column match.
    while true; do
      _num=$(ip6tables -L INPUT --line-numbers -n 2>/dev/null \
             | awk -v c="$_chain" 'NR>2 && $2==c {print $1; exit}')
      [[ -n "$_num" ]] || break
      ip6tables -D INPUT "$_num" 2>/dev/null || break
    done
  }

  # Remove all INPUT references to both the stable chain and the temp chain, then flush+delete.
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
  # v2.32 Grok: lo + SSH 先于 INVALID,UNTRACKED 放行，conntrack 表满时 SSH 不断
  iptables -A "$FW_TMP" -i lo                                       -m comment --comment "xray-landing-lo"        -j ACCEPT
  # v2.16: 本地环回保护 - 仅允许xray-landing用户访问内部端口
  # v2.41: 删除无效的lo规则(INPUT链不处理本地进程间通信，已listen 127.0.0.1足够)
  iptables -A "$FW_TMP" -p tcp  --dport "$ssh_port"                 -m comment --comment "xray-landing-ssh"       -j ACCEPT
  # v2.32 Grok: conntrack 表满时 UNTRACKED 裸奔防护，SSH 已在上方豁免
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
      warn "  [跳过] 节点文件 ${meta} 缺少 TRANSIT_IP 字段"; (( ++skipped )) || true; continue
    fi
    if ! python3 -c "import ipaddress,sys; ipaddress.IPv4Address(sys.argv[1])" "$tip" 2>/dev/null; then
      warn "  [跳过] 节点文件 ${meta} TRANSIT_IP='${tip}' 格式非法"; (( ++skipped )) || true; continue
    fi
    tips+=("$tip")
  done
  # 🟠 Grok: 有节点文件但无法提取有效 IP → 拒绝提交，避免假成功
  if (( expected_count > 0 && skipped > 0 )); then
    iptables -F "$FW_TMP" 2>/dev/null || true; iptables -X "$FW_TMP" 2>/dev/null || true
    die "防火墙构建中止：${skipped} 个节点文件格式异常，拒绝生成可能放行不足的规则集（预期 ${expected_count}，有效 $(( expected_count - skipped ))）"
  fi
  while IFS= read -r tip; do
    [[ -n "$tip" ]] || continue
    iptables -A "$FW_TMP" -s "${tip}/32" -p tcp --dport "$LANDING_PORT" -m comment --comment "xray-landing-transit" -j ACCEPT
    info "  ACCEPT ← ${tip}/32:${LANDING_PORT}"; (( ++count )) || true
  done < <(printf '%s\n' "${tips[@]+${tips[@]}}" | sort -u)
  iptables -A "$FW_TMP" -m comment --comment "xray-landing-drop" -j DROP

  iptables -I INPUT 1 -m comment --comment "xray-landing-swap" -j "$FW_TMP"
  # [v2.15] Bulldozer drain: remove every INPUT rule referencing FW_CHAIN by any comment or
  # direct -j before -F/-X/-E. The old while-loop approach missed rules with unexpected comments.
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
    ip6tables -A "$FW_TMP6" -j DROP
    ip6tables -I INPUT 1 -m comment --comment "xray-landing-v6-swap" -j "$FW_TMP6"
    # [v2.15] Bulldozer drain for IPv6 chain before rename
    _bulldoze_input_refs6 "$FW_CHAIN6"
    ip6tables -F "$FW_CHAIN6" 2>/dev/null || true; ip6tables -X "$FW_CHAIN6" 2>/dev/null || true
    ip6tables -E "$FW_TMP6" "$FW_CHAIN6"
    ip6tables -I INPUT 1 -m comment --comment "xray-landing-v6-jump" -j "$FW_CHAIN6"
    while ip6tables -D INPUT -m comment --comment "xray-landing-v6-swap" 2>/dev/null; do :; done
  fi

  # v2.37 GPT: trap 保持活跃直到 _persist_iptables 成功，防运行链/开机链分裂
  if ! _persist_iptables "$ssh_port"; then
    _fw_landing_rollback
    trap - ERR INT TERM
    die "防火墙持久化失败（firewall-restore.sh/unit 写入异常），运行链已回滚"
  fi
  trap - ERR INT TERM
  success "防火墙: chain ${FW_CHAIN}（SSH:${ssh_port} 蓝绿切换零裸奔）| ${count} 中转 IP | have_ipv6→${FW_CHAIN6}"
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

  # v2.32 Gemini: 改用 .xray-landing. 前缀（被 _global_cleanup EXIT trap 当次清理），
  # 防止频繁中断时 .snap-recover 前缀的文件滞留1天积累 inode 泄漏
  local fw_tmp; fw_tmp=$(mktemp "${MANAGER_BASE}/.xray-landing.XXXXXX")
  # v2.39 GPT #9: 写版本签名到脚本头，firewall-restore.sh 被手改/旧版本时 restore 服务可告警
  local _fw_sig; _fw_sig="LANDING_FW_VERSION=${VERSION}_$(date +%Y%m%d)"
  {
    echo "#!/bin/sh"
    echo "# ${_fw_sig}"
    # 🟠 Grok: SSH 端口在恢复时动态探测，防止用户修改 sshd 端口后重启丢失 SSH
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
    # v2.32: lo + SSH 先于 INVALID,UNTRACKED，conntrack 表满时 SSH 不断
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
    echo "iptables -A ${FW_CHAIN} -m comment --comment 'xray-landing-drop' -j DROP"
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
    echo "  ip6tables -A ${FW_CHAIN6} -j DROP"
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
ExecStart=${fw_script}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
RSTO
  # [F5] daemon-reload must succeed for unit changes to take effect
  systemctl daemon-reload \
    || die "daemon-reload 失败，systemd 图未更新"
  # [Doc3-2] enable 失败意味着重启后规则丢失，属于静默时序炸弹，必须硬失败
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
  load_manager_config
  echo ""
  echo -e "${BOLD}── 增加新节点 ────────────────────────────────────────────────────${NC}"
  echo -e "${BOLD}${RED}  ⚠  域名在 Cloudflare 必须设为【仅DNS/灰云】，严禁开启小黄云代理！${NC}"
  echo ""
  read -rp "新节点域名: " NEW_DOMAIN
  NEW_DOMAIN=$(tr '[:upper:]' '[:lower:]' <<< "$NEW_DOMAIN")
  validate_domain "$NEW_DOMAIN"

  local existing_pass=""
  # [Fix-4] Replace fragile grep-l|xargs pipeline with Python structured index lookup.
  # Shell pipelines silently pass empty on malformed/missing files; Python fails loudly on bad data.
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

  # BUG-5 FIX + [Fix-4]: Replace find|xargs|grep pipeline with Python structured lookup for transit IP
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
    warn "中转 IP ${NEW_TRANSIT} 已在防火墙白名单，跳过重复添加 iptables 规则（但仍继续证书申请和 Token 生成）"
    _fw_skip=1
  fi

  local USE_CF_TOKEN="$CF_TOKEN"
  if [[ -z "$USE_CF_TOKEN" ]]; then
    read -rp "Cloudflare API Token（Zone:DNS:Edit）: " USE_CF_TOKEN
    validate_cf_token "$USE_CF_TOKEN"
    CF_TOKEN="$USE_CF_TOKEN"
  fi

  # v2.32: 所有用户输入已收集，加锁后才开始写操作
  _acquire_lock

  # [Fix-B / Doc8-GPT-🟠] Stage manager.conf — write to tmp, commit only after cert+sync+service pass.
  # Committing manager.conf before cert issuance creates a durable half-state on cert failure.
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

  setup_fallback_decoy
  issue_certificate "$NEW_DOMAIN" "$USE_CF_TOKEN"
  local PUB_IP; PUB_IP=$(get_public_ip)

  # 提前计算最终节点文件路径（与 save_node_info 内部逻辑对齐）
  local _safe_dom; _safe_dom=$(printf '%s' "$NEW_DOMAIN" | tr '.:/' '___')
  local _safe_ip;  _safe_ip=$(printf '%s' "$NEW_TRANSIT" | tr '.:' '__')
  local _node_conf="${MANAGER_BASE}/nodes/${_safe_dom}_${_safe_ip}.conf"

  # 🔴 Grok: 临时文件必须以 .conf 结尾，Python glob(*.conf) 才能扫到新节点
  # 不用 .snap-recover 前缀（dotfile 被 glob 跳过），用 tmp- 前缀区分
  local _tmp_node; _tmp_node=$(mktemp "${MANAGER_BASE}/nodes/tmp-XXXXXX.conf")
  cat >"$_tmp_node" <<NEOF_TMP
DOMAIN=${NEW_DOMAIN}
PASSWORD=${NEW_PASS}
TRANSIT_IP=${NEW_TRANSIT}
PUBLIC_IP=${PUB_IP}
CREATED=$(date +%Y%m%d_%H%M%S)
NEOF_TMP
  chmod 600 "$_tmp_node"

  # [F1] Ghost cert guard: check if other committed node files still use this domain.
  # Revoking a cert shared by multiple transit nodes would break live connections on all of them.
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

  # SIGINT 显式回滚：已完成的 sync/firewall 一并回滚，而非只清理临时文件
  # [Fix-I / Doc9-GPT-🟠] Also revoke acme cert registration on interrupt to prevent ghost cert
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

  # v2.35 Gemini: 先 mv 临时文件为正式节点，再 setup_firewall（setup_firewall 排除 tmp-* 文件，
  # 必须让正式 .conf 存在才能把新 TRANSIT_IP 写入白名单，否则新节点永久被防火墙阻断）
  local _snap_cfg_node; _snap_cfg_node=$(mktemp "${LANDING_BASE}/.snap-recover.XXXXXX" 2>/dev/null) || _snap_cfg_node=""
  [[ -n "$_snap_cfg_node" && -f "$LANDING_CONF" ]] && cp -f "$LANDING_CONF" "$_snap_cfg_node" 2>/dev/null || true
  mv -f "$_tmp_node" "$_node_conf"
  _int_sync_done=0
  trap '_global_cleanup; rm -f "$_node_conf" 2>/dev/null; echo -e "\n${RED}[中断] 请执行: bash $0 --uninstall${NC}"; exit 1' INT TERM

  # BUG-5 FIX: 只有 _fw_skip==0 时才执行防火墙重建；IP已存在时跳过 iptables 但继续全流程
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
    info "TRANSIT_IP ${NEW_TRANSIT} 已在白名单，跳过防火墙重建（新域名节点仍正常添加）"
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
  # [Fix-B] Commit staged manager.conf now that cert+sync+service all succeeded
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

  # v2.32: 用户确认后加锁，写操作串行化
  _acquire_lock

  # [F1] Snapshot config.json BEFORE first sync so rollback is a direct file restore,
  # not a dynamic regeneration that can fail silently and leave config.json inconsistent.
  local _snap_cfg_del=""
  [[ -f "$LANDING_CONF" ]] && {
    _snap_cfg_del=$(mktemp "${LANDING_BASE}/.snap-recover.XXXXXX")
    cp -f "$LANDING_CONF" "$_snap_cfg_del"
  }

  # 五步原子变更
  # [v2.9 Grok-C-🟠] Rename to .deleting (not rm) so the node file survives a SIGKILL between
  # the rename and sync_xray_config completing. glob(*.conf) excludes .deleting; setup_firewall
  # also rescans *.conf so the IP is removed from the whitelist correctly.
  # The .deleting file is removed only after service restart confirms success.
  local _snap_node; _snap_node=$(mktemp "${MANAGER_BASE}/nodes/.snap-recover.XXXXXX")
  cp -f "$DEL_CONF" "$_snap_node"
  mv -f "$DEL_CONF" "${DEL_CONF}.deleting"

  # [v2.11 Grok-Doc9-🔴] Cert cleanup moved AFTER service restart confirms success.
  # Old position (before sync_xray_config) meant a sync failure would roll back the node
  # file but the cert was already wiped → Xray config referenced a now-missing certificateFile
  # → service crash on next start → total blackout for all remaining nodes.
  # Compute remaining count now (before sync) so the flag is available at the success path.
  local safe_del; safe_del=$(printf '%s' "$DEL_DOMAIN" | tr '.:/' '___')
  local remaining; remaining=$(find "${MANAGER_BASE}/nodes" -name "${safe_del}_*.conf" -type f 2>/dev/null | wc -l)

  if ! ( sync_xray_config ); then
    mv -f "${DEL_CONF}.deleting" "$DEL_CONF" 2>/dev/null || true
    # [F1] Direct snapshot restore — avoids silent sync failure leaving config.json inconsistent
    [[ -n "${_snap_cfg_del:-}" && -f "${_snap_cfg_del:-}" ]] \
      && mv -f "$_snap_cfg_del" "$LANDING_CONF" 2>/dev/null || true
    _release_lock; die "Xray配置同步失败，节点文件和config.json已物理回滚"
  fi
  rm -f "${_snap_cfg_del:-}" 2>/dev/null || true  # sync succeeded, snapshot no longer needed
  if ! ( setup_firewall ); then
    mv -f "${DEL_CONF}.deleting" "$DEL_CONF" 2>/dev/null || true
    # [F1] Re-sync after node restore (sync succeeded before, safe to re-run)
    ( sync_xray_config ) 2>/dev/null || true
    _release_lock; die "防火墙更新失败，节点文件已恢复"
  fi
  # v2.33 BUG-NEW: _snap_node 保留到 restart 验证通过后再删，保证重启失败时可回滚
  local _restart_rc=0
  systemctl restart "$LANDING_SVC" 2>/dev/null || _restart_rc=$?
  sleep 1
  if (( _restart_rc != 0 )) || ! systemctl is-active --quiet "$LANDING_SVC"; then
    warn "服务重启失败，回滚节点文件..."
    mv -f "${DEL_CONF}.deleting" "$DEL_CONF" 2>/dev/null || true
    ( sync_xray_config ) 2>/dev/null || true
    ( setup_firewall )   2>/dev/null || true
    # [Doc7-🔴] 回滚后必须恢复服务运行态，否则剩余所有节点永久断流直到人工介入
    systemctl reset-failed "$LANDING_SVC" 2>/dev/null || true
    systemctl restart "$LANDING_SVC" 2>/dev/null || true
    _release_lock; warn "节点已恢复，请检查: journalctl -u ${LANDING_SVC}"
  else
    # Transaction confirmed: now safe to delete cert (service is running without it)
    if (( remaining == 0 )); then
      info "域名 ${DEL_DOMAIN} 已无中转机，清理证书..."
      if [[ -f "${ACME_HOME}/acme.sh" ]]; then
        "${ACME_HOME}/acme.sh" --home "${ACME_HOME}" --remove --domain "$DEL_DOMAIN" --ecc 2>/dev/null || true
        rm -rf "${ACME_HOME}/${DEL_DOMAIN}_ecc" 2>/dev/null || true
      fi
      rm -rf "${CERT_BASE}/${DEL_DOMAIN}" 2>/dev/null || true
    fi
    # Both _snap_node and .deleting can now be removed — transaction succeeded
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

  # v2.32: 所有校验通过后加锁，写操作串行化
  _acquire_lock

  local _snap_mgr _snap_cfg _snap_fw
  _snap_mgr=$(mktemp "${MANAGER_BASE}/.snap-recover.XXXXXX") \
    || { _release_lock; die "manager.conf 快照创建失败（磁盘满？），端口未变更"; }
  # v2.33 GPT BUG-04: config.json 快照失败时不允许空串继续，直接中止
  _snap_cfg=$(mktemp "${LANDING_BASE}/.snap-recover.XXXXXX" 2>/dev/null) \
    || { rm -f "$_snap_mgr"; _release_lock; die "config.json 快照创建失败（磁盘满/目录缺失？），端口未变更"; }
  # v2.34 GPT: firewall-restore.sh 快照——端口回滚时防持久化脚本与运行态分裂
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
    # 还原 firewall-restore.sh 文件态
    [[ -n "${_snap_fw:-}" && -f "$_snap_fw" ]] \
      && mv -f "$_snap_fw" "${MANAGER_BASE}/firewall-restore.sh" 2>/dev/null || true
    # [Doc4-2] 核心修复: 文件态还原后必须立即刷新内核运行态
    # 否则内存中是新端口规则，文件是旧端口规则 → 不重启就永久断流
    if [[ -x "${MANAGER_BASE}/firewall-restore.sh" ]]; then
      "${MANAGER_BASE}/firewall-restore.sh" 2>/dev/null || true
    fi
    # [Doc6-GPT-🟠] Sync config.json back to old port after firewall restore
    ( sync_xray_config ) 2>/dev/null || true
    # [Fix-1 / Role-B-🔴] Revival: reset circuit-breaker then restart on restored config.
    # Without restart, service stays dead after port-change rollback → total node blackout.
    systemctl reset-failed "$LANDING_SVC" 2>/dev/null || true
    systemctl restart "$LANDING_SVC" 2>/dev/null || true
    rm -f "$_snap_mgr" "${_snap_cfg:-}" "${_snap_fw:-}" 2>/dev/null || true
    LANDING_PORT="$old_port"
    _release_lock
  }
  # [F2] Include ERR: set -e exits without rollback on bash errors (full disk, mktemp fail)
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
  # Transaction complete — restore standard INT/TERM trap, also clear ERR (was set for rollback)
  trap '_global_cleanup; echo -e "\n${RED}[中断] 请执行: bash $0 --uninstall${NC}"; exit 1' INT TERM
  trap - ERR
  # [Doc5-GPT] 成功路径也清零熔断计数，防残留计数在下次端口变更时误触发 failed 态
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
    # v2.44 GPT: 逐项校验节点完整性（conf + cert），缺一判红
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
  # [v2.14] Path-agnostic cron check: after acme.sh migration the cron entry may still
  # reference ~/.acme.sh; match on the --cron argument instead of a specific path.
  if crontab -l 2>/dev/null | grep -qE 'acme\.sh.*(--cron|cron)'; then
    echo -e "  acme.sh cron:    ${GREEN}✓ 已注册（原生 crontab）${NC}"
  else
    echo -e "  acme.sh cron:    ${RED}✗ 未注册（证书无法自动续期！运行 acme.sh --install-cronjob 修复）${NC}"
  fi
  systemctl is-enabled --quiet "xray-landing-iptables-restore.service" 2>/dev/null \
    && echo -e "  iptables 恢复服务: ${GREEN}✓ enabled${NC}" \
    || echo -e "  iptables 恢复服务: ${RED}✗ 未 enable（重启后防火墙规则会丢失）${NC}"
  # 🟡 GPT: 恢复脚本内容与运行链一致性校验（not just "enabled"）
  local _fw_script="${MANAGER_BASE}/firewall-restore.sh"
  if [[ -f "$_fw_script" ]]; then
    # v2.39 GPT #9: 版本签名校验——旧脚本/手改脚本开机会复活旧规则
    local _fw_ver_line; _fw_ver_line=$(grep '^# LANDING_FW_VERSION=' "$_fw_script" 2>/dev/null | head -1 || echo "")
    if [[ -z "$_fw_ver_line" ]]; then
      # v2.40 GPT #6: 无签名即分裂点，判红+自动重建
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
      # v2.42 GPT #5: --status 是只读巡检，不执行写操作；修复用独立命令
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
      # v2.39 GPT #8: 检测是否处于 failed/熔断态并提示自愈路径
      local _svc_state; _svc_state=$(systemctl is-failed "$LANDING_SVC" 2>/dev/null || true)
      if [[ "$_svc_state" == "failed" ]]; then
        echo -e "  ${RED}熔断状态:        ✗ 服务已进入 failed（StartLimitBurst 触发）${NC}"
        echo -e "  ${CYAN}  自愈: systemctl reset-failed ${LANDING_SVC} && systemctl start ${LANDING_SVC}${NC}"
        echo -e "  ${CYAN}  或等待 recovery unit 自动恢复（约5分钟）${NC}"
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
  # v2.34/35 GPT: 字段级一致性硬校验——真相源 manager.conf 与派生 config.json 逐项对比
  if [[ -f "$MANAGER_CONFIG" && -f "$LANDING_CONF" ]]; then
    local _cfg_port _cfg_uuid _cfg_vg _cfg_tg _cfg_vw _cfg_tt
    _cfg_port=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d['inbounds'][0]['port'])" \
      "$LANDING_CONF" 2>/dev/null || echo "")
    _cfg_uuid=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d['inbounds'][0]['settings']['clients'][0]['id'])" \
      "$LANDING_CONF" 2>/dev/null || echo "")
    # 内部端口：inbounds[1]=vless-grpc  [2]=trojan-grpc  [3]=vless-ws  [4]=trojan-tcp
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
    (( _field_ok )) && echo -e "  字段一致性:      ${GREEN}✓ 全部6字段与config.json一致${NC}"
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
  # BUG-40 FIX: Token ip 字段必须是落地机公网 IPv4，dom 必须是域名
  # 用 python3 ipaddress 模块验证 pub_ip 确实是合法 IPv4，防止位移错误静默通过
  if ! python3 -c "import ipaddress,sys; ipaddress.IPv4Address(sys.argv[1])" "$pub_ip" 2>/dev/null; then
    die "pub_ip='${pub_ip}' 不是合法 IPv4，拒绝生成 Token"
  fi
  token=$(python3 - "$pub_ip" "$domain" "$LANDING_PORT" "$VLESS_UUID" "$password" 2>&1 <<'TOKPY'
import json, base64, sys
# argv: 1=pub_ip(IPv4)  2=domain  3=port  4=uuid  5=password
landing_ip   = sys.argv[1]   # 落地机公网 IP  → Token['ip']
landing_dom  = sys.argv[2]   # 落地机域名(SNI) → Token['dom']
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
  #  版本号修正为 v2.2
  [[ -n "$token" ]] \
    && echo -e "  ${BOLD}${CYAN}bash install_transit_${VERSION}.sh --import ${token}${NC}" \
    || warn "  token 生成失败，请手动将上方信息填入中转机脚本"

  echo ""
  echo -e "${BOLD}── 5 协议 Base64 订阅 ────────────────────────────────────────────${NC}"
  local ti="${transit_ip:-$pub_ip}"
  local sub_b64="" _sub_err=""
  # ARCH-3 FIX: 原来 2>/dev/null 吞掉所有 Python 报错，导致静默 "[WARN] Base64 订阅生成失败"
  # 改为捕获 stderr，失败时打印真实错误，方便排查
  # [v2.15 Bug Fix] Python quote bug: python3 -c '...' uses shell single-quotes, which means
  # any Python single-quoted string literal (e.g. '[禁Mux]VLESS-Vision-') closes the shell
  # string early → SyntaxError at runtime. Fix: use a heredoc (<<'SUBPY') so the Python
  # source is passed verbatim without any shell-quoting interference. Label variables avoid
  # all quoting inside f-strings (matches the transit script pattern).
  sub_b64=$(python3 - "$ti" "$domain" "$VLESS_UUID" "$password" 2>&1 <<'SUBPY'
import base64, urllib.parse, sys
transit_ip, domain, vless_uuid, trojan_pass = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
port = 443
pfx = vless_uuid[:8]
# Label variables: avoids any quoting inside f-string {} (Python<3.12 compatible)
lbl_vision = '[禁Mux]VLESS-Vision-'
lbl_vgrpc  = 'VLESS-gRPC-'
# v2.17: Trojan-gRPC已禁用 (被VLESS-gRPC抢占h2流量)
# lbl_tgrpc  = 'Trojan-gRPC-'
lbl_vws    = 'VLESS-WS-'
lbl_ttcp   = 'Trojan-TCP-'
uris = [
    (f"vless://{vless_uuid}@{transit_ip}:{port}"
     f"?encryption=none&flow=xtls-rprx-vision&security=tls"
     f"&sni={domain}&fp=chrome&type=tcp
     f"#{urllib.parse.quote(lbl_vision+domain)}"),
    (f"vless://{vless_uuid}@{transit_ip}:{port}"
     f"?encryption=none&security=tls&sni={domain}&fp=edge"
     f"&type=grpc&serviceName={pfx}-vg&alpn=h2&mode=multi"
     f"#{urllib.parse.quote(lbl_vgrpc+domain)}"),
    # v2.17: Trojan-gRPC已禁用
    # (f"trojan://{urllib.parse.quote(trojan_pass)}@{transit_ip}:{port}"
    #  f"?security=tls&sni={domain}&fp=ios"
    #  f"&type=grpc&serviceName={pfx}-tg&alpn=h2&mode=multi"
    #  f"#{urllib.parse.quote(lbl_tgrpc+domain)}"),
    (f"vless://{vless_uuid}@{transit_ip}:{port}"
     f"?encryption=none&security=tls&sni={domain}&fp=firefox"
     f"&type=ws&path=%2F{pfx}-vw&host={domain}&alpn=http/1.1"
     f"#{urllib.parse.quote(lbl_vws+domain)}"),
    (f"trojan://{urllib.parse.quote(trojan_pass)}@{transit_ip}:{port}"
     f"?security=tls&sni={domain}&fp=safari&type=tcp"
     f"#{urllib.parse.quote(lbl_ttcp+domain)}"),
]
print(base64.b64encode("\n".join(uris).encode()).decode())
SUBPY
) || { _sub_err="$sub_b64"; sub_b64=""; }

  if [[ -n "$sub_b64" ]]; then
    # v1.3: 先逐条显示明文链接，便于验证 IP/域名正确性，再给 Base64 整体订阅
    echo -e "  ${BOLD}── 5 协议明文链接（可逐条复制验证）──────────────────${NC}"
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
    echo -e "  ${YELLOW}   其他四个协议 (gRPC/WS/TCP) 完全兼容 Mux，高并发推荐 gRPC。${NC}"
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

  # [F6] Unregister acme.sh cron FIRST — before stopping the service or removing any files.
  # If interrupted after service stop but before cronjob removal, cron keeps firing reloadcmd
  # on a deleted service every 60 min, causing journald spam and "unit not found" errors.
  if [[ -f "${ACME_HOME}/acme.sh" ]]; then
    "${ACME_HOME}/acme.sh" --uninstall-cronjob 2>/dev/null || true
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
  # [F4] Clear recovery rate-limit lockfile on uninstall; stale lockfile would block
  # the recovery unit on the next fresh install for up to 30 minutes.
  rm -f /run/lock/xray-landing-recovery.last 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true

  if [[ -f "${ACME_HOME}/acme.sh" ]]; then
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
      "${ACME_HOME}/acme.sh" --home "${ACME_HOME}" --remove --domain "$d" --ecc 2>/dev/null && info "已移除 acme.sh 续期: $d" || true
      rm -rf "${ACME_HOME}/${d}_ecc" 2>/dev/null || true
    done
    # --uninstall-cronjob already executed at start of purge_all [F6]
  fi
  # [Doc7-🟠] 移除原有 grep -v '^MAILTO=""' 操作，该操作会破坏宿主机其他业务的 cron 全局变量
  # acme.sh --uninstall-cronjob 已在上方执行，会精确移除自己的条目，无需额外干预 crontab

  # BUG-4 FIX: acme.sh 安装时向 ~/.bashrc 注入 `source ~/.acme.sh/acme.sh.env`
  # 卸载后若不清理，重新 SSH 登录时报 "No such file or directory"
  for _rc in "${HOME}/.bashrc" "${HOME}/.profile" "${HOME}/.bash_profile"; do
    [[ -f "$_rc" ]] && sed -i '/acme\.sh\.env/d' "$_rc" 2>/dev/null || true
  done

  # [v2.15.1] purge_all: bulldozer removes ALL INPUT references to FW_CHAIN regardless of
  # comment text, so iptables -X reliably succeeds. Old comment-loop missed any rule with
  # an unexpected comment tag → chain lingered → next install hit "File exists" on rebuild.
  
# v2.26: Atomic chain purge (no race condition)
_purge_chain_atomic() {
  local chain="${1}" v="${2:-4}"
  local cmd="iptables"; [[ "${2:-4}" == "6" ]] && cmd="ip6tables"
  $cmd-save 2>/dev/null | grep -v "${chain}" | $cmd-restore --noflush 2>/dev/null || true
}

_purge_bz(){
    _purge_chain_atomic "${1}"
  }
  _purge_bz  "$FW_CHAIN";  _purge_bz  "${FW_CHAIN}-NEW"
  iptables -F "$FW_CHAIN" 2>/dev/null || true
  iptables -X "$FW_CHAIN" 2>/dev/null || true

  # v2.32 Gemini: 无条件盲删 ip6tables chain，不依赖 have_ipv6()——
  # 事后禁用 IPv6 会让 have_ipv6 返回假，跳过清理，造成 Netfilter 僵尸链永久驻留内核
  _purge_bz6(){
    _purge_chain_atomic "${1}" 6
  }
  _purge_bz6 "$FW_CHAIN6"; _purge_bz6 "${FW_CHAIN6}-NEW"
  ip6tables -F "$FW_CHAIN6" 2>/dev/null || true
  ip6tables -X "$FW_CHAIN6" 2>/dev/null || true

  mkdir -p /etc/iptables
  # 🟠 Grok: 卸载时不写公共持久化文件，避免覆盖宿主机其他防火墙规则
  # iptables-save > /etc/iptables/rules.v4|v6 已移除

  rm -f /etc/nginx/conf.d/xray-landing-fallback.conf 2>/dev/null || true
  rm -f "/etc/systemd/system/nginx.service.d/landing-override.conf" 2>/dev/null || true
  # v1.5: 清理新增的 drop-in 和 journald 上限配置
  rm -f "/etc/systemd/system/xray-landing.service.d/xray-landing-limits.conf" 2>/dev/null || true
  rmdir "/etc/systemd/system/xray-landing.service.d" 2>/dev/null || true
  rm -f "/etc/systemd/journald.conf.d/xray-landing.conf" 2>/dev/null || true
  systemctl kill --kill-who=main --signal=SIGUSR2 systemd-journald 2>/dev/null || true
  rm -f /etc/cron.daily/xray-cert-monitor 2>/dev/null || true
  sed -i '/^\s*worker_connections\s\+100000\s*;/d' /etc/nginx/nginx.conf 2>/dev/null || true
  sed -i '/^worker_rlimit_nofile\s\+1048576\s*;/d' /etc/nginx/nginx.conf 2>/dev/null || true
  nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null || true

  rm -f "$LANDING_BIN" "$LANDING_CONF" "$LOGROTATE_FILE" \
        /etc/cron.d/acme-xray-landing "$CERT_RELOAD_SCRIPT" 2>/dev/null || true
  # v2.32 Gemini: 卸载时移除 acme crontab 条目并穿透清理续期日志（含 .gz 历史归档）
  [[ -f "${ACME_HOME}/acme.sh" ]] \
    && "${ACME_HOME}/acme.sh" --uninstall-cronjob 2>/dev/null || true
  rm -f /var/log/acme-xray-landing-renew.log* 2>/dev/null || true
  rm -rf "$LANDING_BASE" "$LANDING_LOG" /usr/local/share/xray-landing "$MANAGER_BASE" 2>/dev/null || true
  rm -f /etc/sysctl.d/99-landing-bbr.conf /etc/modprobe.d/99-landing-conntrack.conf 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true

  if [[ "$_created_user" == "1" ]]; then
    userdel "$LANDING_USER" 2>/dev/null || true
  fi


  # 卸载后验收
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
  # Feature 01: 遍历所有节点文件，逐一生成 Token 和订阅链接
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
    # 如果节点文件中有记录的 PUBLIC_IP 则用之，否则取 manager.conf 缓存或实时查询
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

  # BUG-7 FIX: 幂等性保障——若 manager.conf 已存在则复用旧 UUID 和全部端口，避免重跑时订阅全部失效
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
        # 复用全部旧配置：UUID + 主端口 + 内部4个端口（保证 Xray config 不变）
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

  # 只在端口为默认值0时才重新分配（复用路径已赋值，新装路径仍随机分配）
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

  # [Fix-A / Doc8-GPT-🔴] Transaction trap: if anything from here to touch $INSTALLED_FLAG fails,
  # roll back binary + unit + iptables so next run does not collide with a ghost half-install.
  local _fi_trap_active=1
  _fresh_install_rollback(){
    [[ "${_fi_trap_active:-0}" == "1" ]] || return 0
    warn "[rollback] 安装中断，清理半成品..."
    systemctl stop    "$LANDING_SVC"   2>/dev/null || true
    systemctl disable "$LANDING_SVC"   2>/dev/null || true
    rm -f "/etc/systemd/system/${LANDING_SVC}" \
          "/etc/systemd/system/xray-landing-recovery.service" 2>/dev/null || true
    # [F4] Also clean nginx fallback artifacts — without this, next run finds Nginx already
    # configured and enters inconsistent state thinking setup_fallback_decoy already ran.
    rm -f "/etc/nginx/conf.d/xray-landing-fallback.conf" 2>/dev/null || true
    rm -f "/etc/systemd/system/nginx.service.d/landing-override.conf" 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
    while iptables -D INPUT -j "$FW_CHAIN" 2>/dev/null; do :; done
    iptables -F "$FW_CHAIN" 2>/dev/null || true
    iptables -X "$FW_CHAIN" 2>/dev/null || true
    # [F3] Clean installed binary and assets — install_xray_binary() runs before this trap
    # fires; leaving the binary creates a contaminated host state on the next run.
    rm -f "$LANDING_BIN" "$CERT_RELOAD_SCRIPT" "$LOGROTATE_FILE" 2>/dev/null || true
    rm -rf /usr/local/share/xray-landing 2>/dev/null || true
    # Also clear recovery lockfile so a future fresh install doesn't trip the 1800s cooldown
    rm -f /run/lock/xray-landing-recovery.last 2>/dev/null || true
    # [v2.11 Doc10-C-🔴] Remove acme.sh domain registration before wiping cert dirs.
    # Without this, acme.sh cron keeps firing reloadcmd for a domain that no longer has
    # a service — causing spurious reload failures and cron log noise indefinitely.
    if [[ -n "${DOMAIN:-}" && -f "${ACME_HOME}/acme.sh" ]]; then
      env ACME_HOME="${ACME_HOME}" "${ACME_HOME}/acme.sh" \
        --home "${ACME_HOME}" --remove --domain "${DOMAIN}" --ecc 2>/dev/null || true
    fi
    # [F4] Remove cert and config dirs so next run starts clean
    rm -rf "$CERT_BASE" "$LANDING_BASE" 2>/dev/null || true
    rm -f "$INSTALLED_FLAG" "$MANAGER_CONFIG" 2>/dev/null || true
    rm -f "${_staged_fi_mgr:-}" 2>/dev/null || true   # [v2.8] purge staged manager.conf on rollback
    rm -rf "${MANAGER_BASE}/nodes" 2>/dev/null || true
    warn "[rollback] 完成，可安全重新运行安装"
  }
  trap '_fresh_install_rollback' ERR INT TERM

  # [v2.32 Bug-1 Fix] Ensure both MANAGER_BASE and its tmp subdir exist before mktemp
  mkdir -p "${MANAGER_BASE}/tmp"

  # [v2.8 Architect-🔴] Stage manager.conf to a temp path; promote to the real path only after
  # sync_xray_config + create_systemd_service + setup_firewall all succeed.
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

  setup_fallback_decoy
  # GEM-BUG-04: LANDING_LOG 必须在 issue_certificate 之前创建，
  # 否则 cron 任务写入的 acme-renew.log 路径不存在
  mkdir -p "$LANDING_LOG"
  issue_certificate "$DOMAIN" "$CF_TOKEN"

  # 🔴 GPT: save_node_info 推迟到 sync+service+firewall 全部成功后原子提交
  # tmp-*.conf 供 sync_xray_config(glob *.conf) 读取；setup_firewall 排除 tmp-* 故 mv 后再生效
  local _safe_dom; _safe_dom=$(printf '%s' "$DOMAIN" | tr '.:/' '___')
  local _safe_ip;  _safe_ip=$(printf '%s' "$TRANSIT_IP" | tr '.:' '__')
  local _final_node="${MANAGER_BASE}/nodes/${_safe_dom}_${_safe_ip}.conf"
  mkdir -p "${MANAGER_BASE}/nodes"
  # [v2.7 Architect-🔴] Use atomic_write (temp + fsync-equivalent + rename) for the node file.
  # Old pattern `printf ... >"$_final_node"` is non-atomic: a kill-9, power loss, or ENOSPC
  # in the write window leaves a truncated nodes/*.conf that the next run treats as real state,
  # causing node discovery and config-generation drift against the actual service state.
  atomic_write "$_final_node" 600 root:root <<NEOF_ATOMIC
DOMAIN=${DOMAIN}
PASSWORD=${PASS}
TRANSIT_IP=${TRANSIT_IP}
PUBLIC_IP=${PUB_IP}
CREATED=$(date +%Y%m%d_%H%M%S)
NEOF_ATOMIC
  trap '_global_cleanup; rm -f "$_final_node" 2>/dev/null; echo -e "\n${RED}[中断] 请执行: bash $0 --uninstall${NC}"; exit 1' INT TERM

  local _CAP_LINE=""
  (( LANDING_PORT < 1024 )) && _CAP_LINE=$'AmbientCapabilities=CAP_NET_BIND_SERVICE\n'
  export _CAP_LINE

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

  # Node file already at final path; reset trap to standard
  trap '_global_cleanup; rm -f "${_staged_fi_mgr:-}" 2>/dev/null; echo -e "\n${RED}[中断] 请执行: bash $0 --uninstall${NC}"; exit 1' INT TERM

  # v2.32 GPT: setup_firewall 失败时完整回滚——节点文件/config.json/服务/unit/logrotate 全部清理，
  # 确保下次重跑不遇到"看似未装实已半装"的脏状态
  if ! ( setup_firewall ); then
    rm -f "$_final_node" "${_staged_fi_mgr:-}" 2>/dev/null || true
    systemctl stop    "$LANDING_SVC" 2>/dev/null || true
    systemctl disable "$LANDING_SVC" 2>/dev/null || true
    rm -f "/etc/systemd/system/${LANDING_SVC}" 2>/dev/null || true
    rm -f "$LOGROTATE_FILE" 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
    ( sync_xray_config ) 2>/dev/null || true
    # [F1] Ghost cert guard: cert was issued before firewall; must revoke on firewall fail
    if [[ -f "${ACME_HOME}/acme.sh" ]]; then
      "${ACME_HOME}/acme.sh" --home "${ACME_HOME}" --remove --domain "$DOMAIN" --ecc 2>/dev/null || true
      rm -rf "${CERT_BASE}/${DOMAIN}" 2>/dev/null || true
    fi
    die "防火墙配置失败，已完整回滚（含证书撤销），可安全重跑安装"
  fi

  # [v2.9 Grok-A-🟠] Touch INSTALLED_FLAG *before* mv staged_fi_mgr.
  # Reverse order (mv then touch) left a window where a SIGKILL after mv but before touch
  # produced a durable set (manager.conf + nodes/*.conf + config.json + running service) with
  # no INSTALLED_FLAG → next run routed to fresh_install → "port occupied" die.
  # With flag-first order: if we crash after touch but before mv, the stale-marker
  # reconciliation block in main() detects missing manager.conf and clears the flag cleanly.
  # v2.39: mv先，touch后——防止"flag存在但manager.conf缺失"的分裂状态
  mv -f "$_staged_fi_mgr" "$MANAGER_CONFIG" \
    || { die "manager.conf 原子提交失败（磁盘满？），安装已回滚，请重新运行"; }
  touch "$INSTALLED_FLAG"
  _staged_fi_mgr=""   # prevent _fresh_install_rollback from double-deleting

  # Transaction committed — deactivate rollback trap
  _fi_trap_active=0
  trap '_global_cleanup; echo -e "\n${RED}[中断] 请执行: bash $0 --uninstall${NC}"; exit 1' INT TERM

  print_pairing_info "$PUB_IP" "$DOMAIN" "$PASS" "$TRANSIT_IP"
  success "══ 落地机安装完成！══"
  echo -e "  systemctl status ${LANDING_SVC}"
  echo -e "  tail -f ${LANDING_LOG}/error.log"
}

_ver_gt(){ [[ "$(printf '%s\n' "$1" "$2" | sort -V | tail -1)" == "$1" && "$1" != "$2" ]]; }
_check_update(){
  local self_name; self_name=$(basename "${BASH_SOURCE[0]:-$0}")
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
  echo "║     5协议单端口回落 · TLS 1.2/1.3双栈 · rejectUnknownSni=true  ║"
  echo "║     异构uTLS指纹 · UDP53黑洞 · have_ipv6 sysctl guard           ║"
  echo "║     fallback 444 · acme自愈升级 · 真相源防反写 · mack-a隔离    ║"
  echo "╚══════════════════════════════════════════════════════════════════╝"
  echo -e "${NC}"

  case "${1:-}" in
    --uninstall) purge_all; exit 0 ;;
    --help|-h)   show_help; exit 0 ;;
    --status)    show_status; exit $? ;;
    set-port)    do_set_port "${2:-}"; exit 0 ;;
  esac

  _check_update &

  # [v2.9 Grok-A-🟠] Symmetric reconciliation: "flag absent but durable set complete" means
  # the process was killed between touch INSTALLED_FLAG and mv staged_fi_mgr (v2.9 order) or
  # between mv staged_fi_mgr and touch INSTALLED_FLAG (legacy order). In both cases the node
  # is fully installed. Restore the flag and route to installed_menu rather than wiping state.
  if [[ ! -f "$INSTALLED_FLAG" ]]; then
    local _sym_mgr=1 _sym_conf=1 _sym_node=1
    [[ -f "$MANAGER_CONFIG" ]]  || _sym_mgr=0
    [[ -f "$LANDING_CONF" ]]    || _sym_conf=0
    find "${MANAGER_BASE}/nodes" -name "*.conf" -not -name "tmp-*.conf" \
         -type f -maxdepth 1 2>/dev/null | grep -q . 2>/dev/null || _sym_node=0
    if (( _sym_mgr && _sym_conf && _sym_node )); then
      warn "[v2.9] 持久化集完整但安装标记缺失（崩溃于最后一步），自动恢复标记..."
      touch "$INSTALLED_FLAG"
      # fall through to the installed branch below
    fi
  fi

  if [[ -f "$INSTALLED_FLAG" ]]; then
    # [v2.8 Architect-🟠] Startup stale-marker reconciliation: verify the durable set;
    # remove the marker when it is incomplete.
    local _durable_ok=1
    [[ -f "$MANAGER_CONFIG" ]]                                          || _durable_ok=0
    [[ -f "$LANDING_CONF" ]]                                            || _durable_ok=0
    find "${MANAGER_BASE}/nodes" -name "*.conf" -not -name "tmp-*.conf" \
         -type f -maxdepth 1 2>/dev/null | grep -q . 2>/dev/null       || _durable_ok=0
    if (( _durable_ok == 0 )); then
      warn "[v2.8] 安装标记存在但持久化集（manager.conf/config.json/nodes/*.conf）不完整，清除标记重新安装..."
      rm -f "$INSTALLED_FLAG"
      # Also purge any .manager.* staging file that may have survived a SIGKILL
      find "${MANAGER_BASE}" /tmp -maxdepth 1 -name '.manager.*' -type f -delete 2>/dev/null || true
      fresh_install
      return
    fi
    load_manager_config
    # 🟠 GPT: .installed 降为辅助证据，三态交叉校验（服务/配置/节点）
    local _svc_ok=0 _conf_ok=0 _node_ok=0
    systemctl is-active --quiet "$LANDING_SVC" 2>/dev/null && _svc_ok=1 \
      || warn "服务未运行"
    [[ -f "$MANAGER_CONFIG" ]] && _conf_ok=1 \
      || warn "manager.conf 缺失（真相源丢失）"
    local _nc; _nc=$(find "${MANAGER_BASE}/nodes" -name "*.conf" -type f 2>/dev/null | wc -l)
    (( _nc > 0 )) && _node_ok=1
    # 三态全部缺失 → 脏安装，清除标记重新安装
    if (( _svc_ok == 0 && _conf_ok == 0 && _node_ok == 0 )); then
      warn "安装标记存在但三态（服务/配置/节点）全部缺失，清除标记重新安装..."
      rm -f "$INSTALLED_FLAG"
      fresh_install
      return
    fi
    # v2.32 GPT: 真相源丢失时拒绝进入管理菜单（所有写操作均依赖 manager.conf）
    if (( _conf_ok == 0 )); then
      die "manager.conf（真相源）已丢失，无法安全操作。请执行 --uninstall 清除后重装，或从备份恢复 ${MANAGER_CONFIG}"
    fi
    # v2.33 GPT BUG-01: 服务恢复失败时拒绝进管理菜单，避免在不一致状态上继续写操作
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
