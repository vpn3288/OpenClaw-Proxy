#!/usr/bin/env bash
# install_transit_optimized.sh — 中转机安装脚本 (v2.50 + v2.16 双栈融合完整版)
# SNI嗅探 → 纯TCP盲传(TFO+KA=3m:10s:3+backlog=65535) → 落地机 | 动态双栈兼容
# 空/无匹配SNI→17.253.144.10:443（苹果CDN，无DNS）· proxy_timeout=315s
# 完整保留所有架构演进注释与安全回滚陷阱
set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
readonly VERSION="v2.50-Optimized"
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()     { error "$*"; exit 1; }

readonly MANAGER_BASE="/etc/transit_manager"
readonly CONF_DIR="${MANAGER_BASE}/conf"
readonly INSTALLED_FLAG="${MANAGER_BASE}/.installed"
readonly NGINX_MAIN_CONF="/etc/nginx/nginx.conf"
readonly NGINX_STREAM_CONF="/etc/nginx/stream-transit.conf"
readonly SNIPPETS_DIR="/etc/nginx/stream-snippets"
readonly STREAM_INCLUDE_MARKER="transit-manager-stream-include"
readonly LISTEN_PORT=443
readonly FW_CHAIN="TRANSIT-MANAGER"
readonly FW_CHAIN6="TRANSIT-MANAGER-v6"
readonly LOG_DIR="/var/log/transit-manager"
readonly LOGROTATE_FILE="/etc/logrotate.d/transit-manager"
readonly TRANSIT_IPV4_ONLY="${TRANSIT_IPV4_ONLY:-1}"

[[ $EUID -eq 0 ]] || die "必须以 root 身份运行"

# [F1] Startup stale snapshot sweep — SIGKILL leaves .snap-recover files that EXIT trap cannot clean
find "${MANAGER_BASE}" "${SNIPPETS_DIR}" "${CONF_DIR}" /etc/systemd/system \
  -maxdepth 5 -name '.snap-recover.*' -mtime +1 -delete 2>/dev/null || true

# BUG-02: 中断时清理 atomic_write 残留的临时文件及事务快照
# v2.32 Gemini: 统一当次全清——操作锁保证同一时刻只有一个事务，快照不需要跨日保留
# [v2.13 GPT-🔴 + Grok-🔴] Cleanup restricted exclusively to script-owned directories.
# Broad /tmp scans risk touching unrelated user files; all scratch files are now under
# ${MANAGER_BASE}/tmp so a targeted find there is sufficient and safe.
_global_cleanup(){
  find "${MANAGER_BASE}" "${SNIPPETS_DIR}" "${CONF_DIR}" /etc/systemd/system /etc/logrotate.d \
    -maxdepth 5 \
    \( -name '.transit-mgr.*' -o -name '.snap-recover.*' \) \
    -type f -delete 2>/dev/null || true
  # Script-owned tmp — the only scratch space used since v2.13
  find "${MANAGER_BASE}/tmp" \
    -maxdepth 1 -type f \
    \( -name '.transit-mgr.*' -o -name '.snap-recover.*' -o -name '.nginx-conf-snap.*' \) \
    -delete 2>/dev/null || true
}
trap '_global_cleanup' EXIT
trap 'echo -e "\n${RED}[中断] 安装已中断。如需清理残留，请执行: bash $0 --uninstall${NC}"; exit 1' INT TERM
trap '_global_cleanup' EXIT
trap 'echo -e "\n${RED}[中断] 安装已中断。如需清理残留，请执行: bash $0 --uninstall${NC}"; exit 1' INT TERM

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
  tmp="$(mktemp "$dir/.transit-mgr.XXXXXX")"
  trap 'rm -f "$tmp" 2>/dev/null || true' EXIT
  cat >"$tmp"
  chmod "$mode" "$tmp"
  chown "$owner_group" "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$target"
)

# v2.32: 全局写操作互斥锁，防止两个终端并发修改同一状态
# [v2.13 GPT-🔴] Lock file moved from /tmp to script-owned ${MANAGER_BASE}/tmp so interrupted
# runs cannot leave phantom locks visible to unrelated processes and the directory is
# cleaned up on --uninstall rather than left in the global temporary namespace.
# mkdir -p is called inside _acquire_lock so the path always exists before flock.
readonly TRANSIT_LOCK_FILE="${MANAGER_BASE}/tmp/transit-manager.lock"
_acquire_lock(){
  mkdir -p "${MANAGER_BASE}/tmp"
  exec 200>"$TRANSIT_LOCK_FILE"
  flock -w 10 200 || die "配置正在被其他进程修改，请稍后重试（等待超时 10s）"
}
_release_lock(){ flock -u 200 2>/dev/null || true; }

have_ipv6(){
  [[ "${TRANSIT_IPV4_ONLY}" == "1" ]] && return 1
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
    # 允许环境变量覆盖，方便自动化场景
    if [[ "${detect_ssh_port_override:-}" =~ ^[0-9]+$ ]]; then
      p="$detect_ssh_port_override"
    else
      exit 1
    fi
  fi
  printf '%s\n' "$p"
}

validate_domain(){
  local d="$1"
  # RFC1035 长度守卫 + 必须含点
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
    ipaddress.IPv4Address(sys.argv[1].strip())
except ValueError:
    raise SystemExit(1)
PY
}

validate_ip(){
  local ip="$1"
  [[ "$ip" =~ : ]] && die "拓扑冲突：中转机无 IPv6 路由时（CN2GIA），严禁使用 IPv6 落地机地址: $ip"
  
  # v2.27: Python使用argv传参避免注入
  python3 - "$ip" <<'PYEOF'
import ipaddress, sys
ip = sys.argv[1]
try:
    a = ipaddress.IPv4Address(ip)
    if a.is_loopback or a.is_private or a.is_link_local or a.is_multicast or a.is_reserved or a.is_unspecified:
        sys.exit(1)
except:
    sys.exit(1)
PYEOF
  [[ $? -eq 0 ]] || die "IP 地址属于保留/特殊范围，禁止使用: $ip"
  
  validate_ipv4 "$ip"
}

validate_port(){
  local p="$1"
  [[ "$p" =~ ^[0-9]+$ ]] || die "端口格式非法: $p"
  (( p >= 1 && p <= 65535 )) || die "端口超范围（1-65535）: $p"
}

domain_to_safe()  {
  local raw="$(printf '%s' "$1" | tr '.' '_' | tr -cd 'a-zA-Z0-9_-')"
  local hash="$(printf '%s' "$1" | sha256sum | cut -c1-8)"
  printf '%s_%s' "${raw:0:40}" "$hash"
}
nginx_domain_str(){ printf '%s' "$1" | tr -cd 'a-zA-Z0-9._-'; }
nginx_ip_str()    { printf '%s' "$1" | tr -cd 'a-zA-Z0-9.'; }
# [F2] Compatibility reader: accepts both old IP= and new TRANSIT_IP= field names in .meta files.
# Old files written before v2.3 used IP=; new files use TRANSIT_IP=.
read_meta_ip()    { awk -F= '/^(TRANSIT_IP|IP)=/{print $2; exit}' "$1"; }

# ARCH-2: 中转机公网 IP — 两种调用模式
# get_public_ip [--strict]：strict 模式下获取失败直接 die（用于 Token/订阅生成）
# get_public_ip           ：宽松模式返回占位符（仅用于只读展示）
get_public_ip(){
  # v2.22: Bug2 - 环境变量检查移到函数开头，优先使用
  # v2.24: P1 - env var需要验证
  [[ -n "${TRANSIT_PUBLIC_IP:-}" ]] && { validate_ip "$TRANSIT_PUBLIC_IP"; printf "%s" "$TRANSIT_PUBLIC_IP"; return 0; }
  local _strict=0
  [[ "${1:-}" == "--strict" ]] && _strict=1
  local _ip=""
  for _src in \
      "https://api.ipify.org" \
      "https://ifconfig.me" \
      "https://ipecho.net/plain" \
      "https://checkip.amazonaws.com"; do
    _ip=$(curl -4 -fsSL --connect-timeout 5 "$_src" 2>/dev/null | tr -d '[:space:]') \
      && [[ -n "$_ip" ]] && break || true
  done
  # [Doc3-3] strict 模式：IP 获取失败 → 硬退出，占位符绝不进入 Token/订阅生成链路
  if [[ -z "$_ip" ]]; then
    if (( _strict )); then
      die "无法获取中转机公网 IPv4，节点订阅无法生成。请检查网络或手动指定: TRANSIT_PUBLIC_IP=x.x.x.x bash $0 --import <token>"
    else
      warn "无法获取中转机公网 IP，展示将使用占位符 <TRANSIT_IP>"
      _ip="<TRANSIT_IP>"
    fi
  fi
  printf '%s' "$_ip"
}

show_help(){
  cat <<HELP
用法: bash install_transit_optimized.sh [选项]

  （无参数）        交互式安装或管理菜单
  --uninstall       清除本脚本所有内容（不影响 mack-a）
  --import <token>  从落地机 Base64 token 自动导入路由规则
  --status          显示当前状态
  --help            显示此帮助
HELP
}

check_deps(){
  export DEBIAN_FRONTEND=noninteractive
  # 二进制名与包名分离：iproute2→ip, psmisc→fuser
  local _bin_pkg=(
    curl:curl wget:wget iptables:iptables python3:python3
    ip:iproute2 nginx:nginx fuser:psmisc crontab:cron
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
  # 验证关键二进制均可用
  for bp in "${_bin_pkg[@]}"; do
    local bin="${bp%%:*}"
    command -v "$bin" &>/dev/null || die "依赖 ${bin} 安装后仍无法找到"
  done
}

optimize_kernel_network(){
  local bbr_conf="/etc/sysctl.d/99-transit-bbr.conf"
  [[ -f "$bbr_conf" ]] && grep -q 'tcp_timestamps' "$bbr_conf" 2>/dev/null && return 0

  info "优化内核并发参数（拥塞控制权归 BBRPlus）..."
  # v2.48 Gemini: tcp_max_tw_buckets 动态计算（每桶256B；内存MB×100，保底10000，上限250000）
  local _ram_mb; _ram_mb=$(free -m 2>/dev/null | awk '/Mem:/{print $2}') || _ram_mb=1024
  local _tw_max=$(( _ram_mb * 100 ))
  (( _tw_max < 10000 ))  && _tw_max=10000
  (( _tw_max > 250000 )) && _tw_max=250000
  # [v2.7 Gemini-Doc1-🟠] Dynamic fs.file-max / fs.nr_open: fixed 10M on a 512MB VPS still
  # consumes PAM/kernel overhead; scale to RAM×800 (floor 524288, cap 10485760) so SSH subshells
  # and PAM sessions are not FD-starved when nginx workers each hold ~1M FD slots.
  local _ram_mb_fd; _ram_mb_fd=$(free -m 2>/dev/null | awk '/Mem:/{print $2}') || _ram_mb_fd=1024
  local _fd_max=$(( _ram_mb_fd * 800 ))
  (( _fd_max < 524288 ))  && _fd_max=524288
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
  echo "options nf_conntrack hashsize=262144" > /etc/modprobe.d/nf_conntrack.conf 2>/dev/null || true
  modprobe nf_conntrack 2>/dev/null || true
  # v2.42 Grok: conntrack hashsize 按内存动态计算（每条目~300B，用1/8内存）
  local _ct_mem; _ct_mem=$(free -m 2>/dev/null | awk '/Mem:/{print int($2/8*1024*1024/300)}') || _ct_mem=262144
  (( _ct_mem < 131072 )) && _ct_mem=131072
  echo "$_ct_mem" > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || true
  # nf_conntrack_max 也动态设为 hashsize*4
  local _ct_max=$(( _ct_mem * 4 ))
  sysctl -w net.netfilter.nf_conntrack_max="${_ct_max}" &>/dev/null || true
  sed -i "s/net.netfilter.nf_conntrack_max=.*/net.netfilter.nf_conntrack_max=${_ct_max}/" \
    /etc/sysctl.d/99-transit-bbr.conf 2>/dev/null || true
  sysctl --system &>/dev/null || true
  sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -qi 'bbr' \
    || warn "BBRPlus 未检测到，请确认已运行 one_click_script 并重启后再检查"
  # [v2.8 GPT-Doc2-🟠] PAM limits must match the dynamic _fd_max value.
  # Hard-coded 1048576 on a 512 MB VPS exceeds the dynamic sysctl value (524288),
  # causing SSH subshells and acme.sh cron to hit a PAM hard limit above the kernel ceiling.
  # Idempotent: strip any stale xray-transit nofile block then re-append current value.
  local _lim_file="/etc/security/limits.conf"
  sed -i '/# xray-transit: raised for high-concurrency/,/^root hard nofile/d' "$_lim_file" 2>/dev/null || true
  cat >> "$_lim_file" <<LIMEOF
# xray-transit: raised for high-concurrency gRPC — install_transit_v2.14.sh
* soft nofile ${_fd_max}
* hard nofile ${_fd_max}
root soft nofile ${_fd_max}
root hard nofile ${_fd_max}
LIMEOF
  success "内核网络参数已优化（conntrack hashsize=262144 / 拥塞控制权归 BBRPlus）"
}

install_nginx(){
  # ENV-1 FIX: nginx -V 含 --with-stream=dynamic 但动态库未装时仍报 "unknown directive stream"
  # 必须强制安装 libnginx-mod-stream，不能仅靠 -V 输出判断
  if command -v nginx &>/dev/null; then
    # 已安装：测试 stream 指令是否真的可用（不只是 -V 标志）
    if echo 'stream{}' | nginx -t -c /dev/stdin 2>/dev/null \
        || (nginx -V 2>&1 | grep -qE 'with-stream[^_]' \
           && dpkg -l libnginx-mod-stream 2>/dev/null | grep -q '^ii' 2>/dev/null); then
      success "Nginx 已安装且 stream 模块可用"
    else
      info "Nginx 已安装但 stream 模块不可用，补充安装 libnginx-mod-stream..."
      export DEBIAN_FRONTEND=noninteractive
      apt-get install -y libnginx-mod-stream 2>/dev/null \
        || warn "libnginx-mod-stream 安装失败，stream 模块可能不可用"
    fi
  else
    info "安装 Nginx（含 stream 模块）..."
    export DEBIAN_FRONTEND=noninteractive
    if command -v apt-get &>/dev/null; then
      apt-get update -qq
      # ENV-1 FIX: 同时安装 nginx-common libnginx-mod-stream nginx，确保动态库就位
      apt-get install -y nginx-common libnginx-mod-stream nginx 2>/dev/null \
        || apt-get install -y nginx \
        || die "Nginx 安装失败（apt-get 返回非零），请检查 apt 源或手动安装 nginx libnginx-mod-stream"
    elif command -v yum &>/dev/null; then
      yum install -y epel-release 2>/dev/null || true
      yum makecache 2>/dev/null || true
      yum install -y nginx nginx-mod-stream 2>/dev/null || yum install -y nginx \
        || die "Nginx 安装失败（yum 返回非零）"
    elif command -v dnf &>/dev/null; then
      dnf install -y nginx nginx-mod-stream 2>/dev/null || dnf install -y nginx \
        || die "Nginx 安装失败（dnf 返回非零）"
    else
      die "不支持的包管理器，请手动安装含 stream 模块的 Nginx"
    fi
    success "Nginx 安装完成"
  fi
  # 最终确认 stream 指令可用
  nginx -V 2>&1 | grep -qE 'with-stream' \
    || die "安装的 Nginx 不含 stream 支持，请安装 libnginx-mod-stream"
  _tune_nginx_worker_connections
}

_tune_nginx_worker_connections(){
  local mc="$NGINX_MAIN_CONF"
  # [F4] Snapshot before sed mutations so nginx.conf can be restored on nginx -t failure
  # [v2.13 GPT-🟠] nginx.conf snapshot moved from /tmp to script-owned MANAGER_BASE/tmp
  local _mc_bak; _mc_bak=$(mktemp "${MANAGER_BASE}/tmp/.nginx-conf-snap.XXXXXX" 2>/dev/null) \
    || { mkdir -p "${MANAGER_BASE}/tmp"; _mc_bak=$(mktemp "${MANAGER_BASE}/tmp/.nginx-conf-snap.XXXXXX"); }
  cp -a "$mc" "$_mc_bak" || { warn "nginx.conf snapshot failed, skipping tuning"; return 0; }
  local _mc_dirty=0
  # [v2.9 GPT-A-🟠] Recompute _fd_max here (same RAM×800 formula as optimize_kernel_network)
  # so worker_rlimit_nofile always matches the systemd LimitNOFILE drop-in value on this host.
  local _tune_ram_mb; _tune_ram_mb=$(free -m 2>/dev/null | awk '/Mem:/{print $2}') || _tune_ram_mb=1024
  local _tune_fd=$(( _tune_ram_mb * 800 ))
  (( _tune_fd < 524288 ))   && _tune_fd=524288
  (( _tune_fd > 10485760 )) && _tune_fd=10485760
  local _wc_ram; _wc_ram=$(free -m 2>/dev/null | awk '/Mem:/{print int($2/2*1000)}') || _wc_ram=100000
  (( _wc_ram < 10000 )) && _wc_ram=10000
  (( _wc_ram > 200000 )) && _wc_ram=200000
  local _wc_val="$_wc_ram"
  grep -qE "^\s*worker_connections\s+${_wc_val}\s*;" "$mc" 2>/dev/null || {
    _mc_dirty=1
    if grep -qE '^\s*worker_connections' "$mc" 2>/dev/null; then
      sed -i "s/^\s*worker_connections\s\+[0-9]\+;/    worker_connections ${_wc_val};/" "$mc"
    else
      sed -i "/^events\s*{/a\    worker_connections ${_wc_val};" "$mc"
    fi
  }
  # Idempotent: strip any stale worker_rlimit_nofile line then re-inject current dynamic value
  grep -qE "^worker_rlimit_nofile\s+${_tune_fd}\s*;" "$mc" 2>/dev/null || {
    _mc_dirty=1
    if grep -qE '^\s*worker_rlimit_nofile' "$mc" 2>/dev/null; then
      sed -i "s/^.*worker_rlimit_nofile.*/worker_rlimit_nofile ${_tune_fd};/" "$mc"
    else
      sed -i "/^events\s*{/i\\worker_rlimit_nofile ${_tune_fd};" "$mc"
      info "worker_rlimit_nofile ${_tune_fd} 已写入 nginx.conf"
    fi
  }
  grep -qE '^worker_shutdown_timeout\s+' "$mc" 2>/dev/null || {
    _mc_dirty=1
    sed -i '/^events\s*{/i\worker_shutdown_timeout 15s;' "$mc"
  }
  # [F4] Validate and roll back if nginx -t fails
  if ! nginx -t 2>/dev/null; then
    warn "nginx.conf tuning validation failed — restoring snapshot"
    # [F1] Hard-fail restore: both mv and cp -a attempted; if both fail the file is corrupted
    if ! mv -f "$_mc_bak" "$mc" 2>/dev/null; then
      cp -a "$_mc_bak" "$mc" || die "nginx.conf restore FAILED — manual fix required: cp ${_mc_bak} ${mc}"
    fi
    die "nginx.conf 配置验证失败，原始配置已还原; 请检查 ${NGINX_MAIN_CONF}"
  fi
  rm -f "$_mc_bak" 2>/dev/null || true
  local override_dir="/etc/systemd/system/nginx.service.d"
  mkdir -p "$override_dir"
  # [v2.8 GPT-Doc2-🟠] LimitNOFILE must equal _fd_max (dynamic); always rewrite so a
  # re-run on different-RAM hardware updates the drop-in to the correct value.
  # [v2.9] Use _tune_fd (same formula, recomputed above) for both worker_rlimit_nofile and
  # the drop-in so the nginx.conf directive and the service cap are always identical.
  local _ov="${override_dir}/transit-manager-override.conf"
  atomic_write "$_ov" 644 root:root <<SVCOV
[Unit]
# [v2.9 Architect-🟠] Widened to 600s/10 — installer restarts nginx after rewriting the
# drop-in; 300s/5 was tight enough to trip on a short maintenance burst.
StartLimitIntervalSec=600
StartLimitBurst=10

[Service]
LimitNOFILE=${_tune_fd}
TasksMax=infinity
# Gemini: nginx 自管日志，systemd journal 无需重复收集（防低配 VPS 磁盘撑爆）
StandardOutput=null
StandardError=null
SVCOV
  # [F4] Hard-fail warning for nginx drop-in daemon-reload
  systemctl daemon-reload \
    || { warn "nginx service.d daemon-reload failed; limits will take effect on next reboot"; }
  if systemctl is-active --quiet nginx 2>/dev/null; then
    # [v2.10 Architect-🟠] Reload-only for routine config application: restart consumes
    # StartLimitBurst budget and is unnecessary here; the config is known-valid via nginx -t.
    # Reserve restart for explicit maintenance or confirmed runtime corruption.
    systemctl reload nginx 2>/dev/null \
      || warn "Nginx reload 失败（配置变更将在下次重启后生效）; 如需立即生效: systemctl restart nginx"
  fi
  success "Nginx worker_connections=${_wc_val} / worker_rlimit_nofile=${_tune_fd} (dynamic)"
}


write_logrotate(){

  mkdir -p "$LOG_DIR"
  atomic_write "$LOGROTATE_FILE" 644 root:root <<EOF
${LOG_DIR}/*.log
{
    su root adm
    daily
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
    create 0640 root adm
    sharedscripts
    postrotate
        # [v2.7 Gemini-Doc2-🟠] --kill-who=main: deliver USR1 exclusively to the nginx master
        # process; bare systemctl kill targets the entire cgroup (master + workers) and
        # USR1 to workers produces undefined behaviour / silent FD leaks.
        # [v2.11 Doc10-B-🟠] nginx -s reopen fallback: if master is in reload window, the
        # USR1 via systemctl kill may be lost; reopen ensures the FD swap is committed.
        systemctl kill --kill-who=main -s USR1 nginx.service >/dev/null 2>&1 \
          || nginx -s reopen >/dev/null 2>&1 || true
    endscript
}
EOF
  # [v2.8 Gemini-Doc2-🟠] journald cap: transit nginx workers now log to journal; without a
  # size ceiling the default 1 GB cap on low-disk VPS can still fill and OOM-kill nginx workers.
  local _jd_conf="/etc/systemd/journald.conf.d/transit-manager.conf"
  mkdir -p "/etc/systemd/journald.conf.d"
  # Always rewrite so re-runs update the value if the file already exists from a prior version.
  atomic_write "$_jd_conf" 644 root:root <<'JDEOF'
[Journal]
SystemMaxUse=200M
RuntimeMaxUse=50M
JDEOF
  systemctl kill --kill-who=main --signal=SIGUSR2 systemd-journald 2>/dev/null || true
  success "logrotate 已配置；journald 上限已设 SystemMaxUse=200M"
}

init_nginx_stream(){
  # BUG-T2 FIX: nginx -t 引用 error_log 路径，若目录不存在则报 "No such file or directory"
  # 必须在 nginx -t 前创建日志目录并设置正确权限
  mkdir -p "$LOG_DIR"
  chown root:adm "$LOG_DIR" 2>/dev/null || true
  chmod 750 "$LOG_DIR"
  mkdir -p "$SNIPPETS_DIR" "$CONF_DIR"
  chmod 700 "$SNIPPETS_DIR"
  rm -f "${SNIPPETS_DIR}/"*.map "${SNIPPETS_DIR}/"*.upstream 2>/dev/null || true
  # FIX-D: dummy.map 原写 apple.com:443（域名），stream 模块无 resolver 时 nginx
  # 启动即报 "host not found in upstream"。改为 IP 直连，无需 DNS，100% 安全。
  echo "    dummy.invalid  17.253.144.10:443;" > "${SNIPPETS_DIR}/landing_dummy.map"

  if grep -q "$STREAM_INCLUDE_MARKER" "$NGINX_MAIN_CONF" 2>/dev/null; then
    info "Nginx stream include 已存在，跳过"; return 0
  fi
  if grep -qE '^\s*stream\s*\{' "$NGINX_MAIN_CONF" 2>/dev/null; then
    die "nginx.conf 已存在 stream{} 块（非本脚本），请备份后手动删除再运行"
  fi

  info "写入 Nginx stream 透传配置 ..."

  # [v2.11 Doc9-B-🟠] Dynamic zone size: 64m fixed consumed ~12% of RAM on a 512MB VPS.
  # Scale to ~3% of RAM (RAM/32), floor 5m (~100k IPs), cap 64m (~1.3M IPs).
  local _stream_ram_mb; _stream_ram_mb=$(free -m 2>/dev/null | awk '/Mem:/{print $2}') || _stream_ram_mb=1024
  local _stream_zone_mb=$(( _stream_ram_mb / 32 ))
  (( _stream_zone_mb < 5  )) && _stream_zone_mb=5
  (( _stream_zone_mb > 64 )) && _stream_zone_mb=64

  # v2.48: 全量 fallback 至 Apple CDN（dummy.invalid 映射），彻底消除本地端口
  # 空/无匹配SNI → dummy.invalid → Apple CDN 17.253.144.10:443
  # resolver 故障 → 降级至本地 45231（速率限制保护）
  atomic_write "$NGINX_STREAM_CONF" 644 root:root <<NGINX_STREAM_EOF
# stream-transit.conf — 由 install_transit_${VERSION}.sh 管理，请勿手动修改
# v2.48: 全量 fallback 至 Apple CDN（ dummy.invalid 映射），彻底消除本地端口积压
# 有效落地机SNI→落地机IP:PORT；无效/空/畸形SNI→Apple CDN（透明盲传）
stream {
    access_log off;
    error_log  ${LOG_DIR}/transit_stream_error.log emerg;

    # v2.48: 删 resolver（纯本地 fallback 无需 DNS，消除 GFW 可观测的 DNS 查询）

    # BUG-T1 FIX: limit_req_zone/limit_req 是 HTTP 模块专属指令，stream 模块不支持
    # 已移除 limit_req_zone 和 limit_req；连接数限制由 limit_conn 负责（stream 原生支持）
    # [v2.11] Dynamic zone size: ~3% of host RAM, floor 5m, cap 64m
    limit_conn_zone \$binary_remote_addr zone=transit_stream_conn:${_stream_zone_mb}m;

    # v2.48: SNI 守卫内嵌到 map——超长(≥254字节)/含控制字符/空/无匹配 → Apple CDN
    map \$ssl_preread_server_name \$backend_upstream {
        hostnames;
        include /etc/nginx/stream-snippets/landing_*.map;
        "~^.{254,}"      dummy.invalid;
        "~[\x00-\x1F]" dummy.invalid;
        ""               dummy.invalid;
        default          dummy.invalid;
    }

    server {
        listen      ${LISTEN_PORT} fastopen=256 so_keepalive=3m:10s:3 backlog=65535;
        ssl_preread on;
        preread_buffer_size 64k;  # [fix] 防止 uTLS 庞大 ClientHello 导致 SNI 嗅探失败
        # [v2.7 Grok-Doc2-🟠] 5s: legitimate TLS ClientHello is sent immediately after TCP
        # handshake; 60s allowed adversaries to drip-feed bytes and exhaust worker slots
        # (Slowloris-style slow-drain DoS bypassing Xray's internal timeout mitigations).
        preread_timeout        5s;
        proxy_pass             \$backend_upstream;
        proxy_connect_timeout  5s;
        # v1.3: 315s = 5min15s，覆盖 gRPC 长流协议；2h 会导致 Nginx worker 无法回收
        # gRPC keepalive 心跳间隔通常 60-120s，315s 足够防误断
        proxy_timeout          315s;
        proxy_socket_keepalive on;
        tcp_nodelay            on;
        # [F2] 100 per IP: gRPC multiplexes all streams over few TCP connections;
        # 2000 per IP + 315s timeout = slow-drain DoS from just 50 distributed IPs.
        limit_conn transit_stream_conn 100;
    }
}
NGINX_STREAM_EOF

  # Bug 37 FIX: 严禁用 sed -i '$a \n...' —— Ubuntu 某些版本将 \n 识别为字母 n
  # 改用 printf + >> 方式追加到临时文件后 mv，纯 POSIX，无环境差异
  local _mc_bak="${NGINX_MAIN_CONF}.transit.bak_$(date +%s)"
  cp -f "$NGINX_MAIN_CONF" "$_mc_bak" 2>/dev/null || true
  ls -t "${NGINX_MAIN_CONF}.transit.bak_"* 2>/dev/null | tail -n +3 | xargs -r rm -f 2>/dev/null || true
  local _mc_tmp; _mc_tmp=$(mktemp "${NGINX_MAIN_CONF%/*}/.snap-recover.XXXXXX")
  cp -f "$NGINX_MAIN_CONF" "$_mc_tmp"
  # 两行分开 printf，避免任何 \n 解析歧义
  printf '\n# %s\n' "$STREAM_INCLUDE_MARKER"  >> "$_mc_tmp"
  printf 'include %s;\n'    "$NGINX_STREAM_CONF" >> "$_mc_tmp"
  mv -f "$_mc_tmp" "$NGINX_MAIN_CONF"
  # 验证注入成功
  grep -q "$STREAM_INCLUDE_MARKER" "$NGINX_MAIN_CONF" \
    || die "nginx.conf include 注入失败，请检查文件权限: ${NGINX_MAIN_CONF}"

  if ! nginx -t 2>/dev/null; then
    if grep -q 'fastopen=' "$NGINX_STREAM_CONF" 2>/dev/null; then
      warn "当前环境不支持 TCP Fast Open，自动降级..."
      # v2.17: TFO降级原子化 - 失败时同时还原stream配置
      local _stream_bak="${NGINX_STREAM_CONF}.tfo.bak"
      cp -f "$NGINX_STREAM_CONF" "$_stream_bak" 2>/dev/null || true
      sed -i 's/ fastopen=[0-9]*//' "$NGINX_STREAM_CONF"
      if ! nginx -t 2>/dev/null; then
        nginx -t 2>&1 || true
        [[ -f "$_mc_bak" ]] && mv -f "$_mc_bak" "$NGINX_MAIN_CONF" 2>/dev/null || true
        mv -f "$_stream_bak" "$NGINX_STREAM_CONF" 2>/dev/null || true
        die "Nginx 配置验证失败（TFO 已移除，请检查配置）；nginx.conf 和 stream 配置均已还原"
      fi
      rm -f "$_stream_bak" 2>/dev/null || true
      warn "TCP Fast Open 已降级（功能正常，仅延迟优化受限）"
    else
      nginx -t 2>&1 || true
      # GEM-BUG-02: nginx.conf 已被 mv 覆盖，验证失败必须从快照还原
      [[ -f "$_mc_bak" ]] && mv -f "$_mc_bak" "$NGINX_MAIN_CONF" 2>/dev/null || true
      die "Nginx stream 配置验证失败；nginx.conf 已从快照还原"
    fi
  fi
  success "Nginx stream 配置写入完成（空/无匹配SNI→17.253.144.10:443 · proxy_timeout=315s）"
}

# FIX: 只生成 .map 文件，值为 IP:PORT 字符串（proxy_pass $var 直接转发，IP 无需 DNS）
# 落地机路由片段只生成 .map 文件，值为 IP:PORT 字符串
generate_landing_snippet(){
  local domain="$1" ip="$2" port="${3:-443}"
  local safe; safe=$(domain_to_safe "$domain")
  # 🔴 Grok: safe 为空 → domain_to_safe 把所有字符都过滤掉 → map 文件名非法
  [[ -n "$safe" ]] || die "域名 safe 转换后为空，拒绝生成 map（可能含非法字符）: ${domain}"
  # v2.32 Grok: 文件名截断，防超长 safe key 造成文件系统限制错误
  (( ${#safe} > 64 )) && safe="${safe:0:64}"
  rm -f "${SNIPPETS_DIR}/landing_${safe}.upstream" 2>/dev/null || true

  # 🟠 Grok: 先清除旧 map（原子覆盖），防重复 hostnames 条目导致 fallback 优先级错乱
  rm -f "${SNIPPETS_DIR}/landing_${safe}.map" 2>/dev/null || true

  atomic_write "${SNIPPETS_DIR}/landing_${safe}.map" 600 root:root <<MAPEOF
    $(nginx_domain_str "$domain")    $(nginx_ip_str "$ip"):${port};
MAPEOF
  success "路由片段已生成: ${domain} → ${ip}:${port}"
}

remove_landing_snippet(){
  local domain="$1"
  local safe; safe=$(domain_to_safe "$domain")
  local removed=0
  for f in "${SNIPPETS_DIR}/landing_${safe}.map" \
            "${SNIPPETS_DIR}/landing_${safe}.upstream" \
            "${CONF_DIR}/${safe}.meta"; do
    [[ -f "$f" ]] && { rm -f "$f"; (( ++removed )) || true; }
  done
  (( removed > 0 )) && success "已删除路由片段: ${domain}" \
    || { warn "未找到路由配置: ${domain}"; return 1; }
}

nginx_reload(){
  # BUG-T2 FIX: 确保日志目录存在，防止 nginx -t 因 error_log 路径不存在而失败
  mkdir -p "$LOG_DIR"
  info "验证 Nginx 配置 ..."
  nginx -t 2>&1 || die "Nginx 配置验证失败，请检查以上报错"
  info "热重载 Nginx ..."
  if systemctl is-active --quiet nginx 2>/dev/null; then
    systemctl reload nginx
  else
    systemctl start nginx 2>/dev/null || die "Nginx 未运行且无法启动"
  fi
  sleep 1
  success "Nginx 热重载成功（零中断）"
}

# v2.34: Atomic chain purge - replaces line-number deletion
_purge_chain_atomic() {
  local chain="${1}" v="${2:-4}"
  local cmd="${v}tables"
  local _num
  while true; do
    _num=$($cmd -L INPUT --line-numbers -n 2>/dev/null | awk -v c="$chain" 'NR>2 && $2==c {print $1; exit}')
    [[ -n "$_num" ]] || break
    $cmd -D INPUT "$_num" 2>/dev/null || break
  done
  $cmd -F "$chain" 2>/dev/null || true
  $cmd -X "$chain" 2>/dev/null || true
}

setup_firewall_transit(){
  local ssh_port; ssh_port="$(detect_ssh_port)"
  info "配置防火墙 chain ${FW_CHAIN}: SSH(${ssh_port}) + TCP(${LISTEN_PORT}) + ICMP，其余 DROP ..."

  local FW_TMP="${FW_CHAIN}-NEW"
  local FW_TMP6="${FW_CHAIN6}-NEW"

  # [v2.15 Bug Fix] Bulldozer pre-flight: iptables -E fails with "File exists" when INPUT
  # has ANY rule referencing FW_CHAIN, regardless of comment text. The old while-loop approach
  # only removed rules with specific known comments, missing rules added with different comments
  # or leftover direct -j rules. Bulldozer reads iptables -S INPUT and removes every rule
  # that names FW_CHAIN or FW_TMP before attempting -F / -X / -E.
  _bulldoze_input_refs_t(){
    local _chain="$1" _num
    # [v2.15.2] Delete by line number: no grep/word-splitting, exact target-column match.
    while true; do
      _num=$(iptables -L INPUT --line-numbers -n 2>/dev/null \
             | awk -v c="$_chain" 'NR>2 && $2==c {print $1; exit}')
      [[ -n "$_num" ]] || break
      iptables -D INPUT "$_num" 2>/dev/null || break
    done
  }
  _bulldoze_input_refs6_t(){
    local _chain="$1" _num
    # [v2.15.2] Delete by line number: no grep/word-splitting, exact target-column match.
    while true; do
      _num=$(ip6tables -L INPUT --line-numbers -n 2>/dev/null \
             | awk -v c="$_chain" 'NR>2 && $2==c {print $1; exit}')
      [[ -n "$_num" ]] || break
      ip6tables -D INPUT "$_num" 2>/dev/null || break
    done
  }

  _bulldoze_input_refs_t "$FW_CHAIN";  _bulldoze_input_refs_t "$FW_TMP"
  iptables -F "$FW_TMP"   2>/dev/null || true; iptables -X "$FW_TMP"   2>/dev/null || true
  iptables -F "$FW_CHAIN" 2>/dev/null || true; iptables -X "$FW_CHAIN" 2>/dev/null || true
  if have_ipv6; then
    _bulldoze_input_refs6_t "$FW_CHAIN6"; _bulldoze_input_refs6_t "$FW_TMP6"
    ip6tables -F "$FW_TMP6"   2>/dev/null || true; ip6tables -X "$FW_TMP6"   2>/dev/null || true
    ip6tables -F "$FW_CHAIN6" 2>/dev/null || true; ip6tables -X "$FW_CHAIN6" 2>/dev/null || true
  fi

  # v2.35 Grok: 快照旧 persist script，_persist_iptables 失败时连同 chain swap 一起回滚
  local _snap_persist=""
  local _persist_script="${MANAGER_BASE}/firewall-restore.sh"
  if [[ -f "$_persist_script" ]]; then
    _snap_persist=$(mktemp "${MANAGER_BASE}/.transit-mgr.XXXXXX") || _snap_persist=""
    [[ -n "$_snap_persist" ]] && cp -f "$_persist_script" "$_snap_persist" 2>/dev/null || _snap_persist=""
  fi

  _fw_transit_rollback(){
    iptables -D INPUT -m comment --comment "transit-manager-swap" 2>/dev/null || true
    iptables -F "$FW_TMP"  2>/dev/null || true
    iptables -X "$FW_TMP"  2>/dev/null || true
    ip6tables -D INPUT -m comment --comment "transit-manager-v6-swap" 2>/dev/null || true
    ip6tables -F "$FW_TMP6" 2>/dev/null || true
    ip6tables -X "$FW_TMP6" 2>/dev/null || true
    # v2.36 GPT: 区分"有旧快照"和"首次安装无旧文件"两种情形
    if [[ -n "${_snap_persist:-}" && -f "${_snap_persist:-}" ]]; then
      # 存在旧快照 → 还原
      mv -f "$_snap_persist" "$_persist_script" 2>/dev/null || true
    else
      # 首次安装 → 无旧脚本可还原，删除新生成的脚本和 unit，防半装状态带入开机
      rm -f "$_persist_script" 2>/dev/null || true
      systemctl disable --now transit-manager-iptables-restore.service 2>/dev/null || true
      rm -f "/etc/systemd/system/transit-manager-iptables-restore.service" 2>/dev/null || true
      systemctl daemon-reload 2>/dev/null || true
    fi
    _snap_persist=""
  }
  trap '_fw_transit_rollback; exit 130' INT TERM; trap 'exit 130' ERR
  iptables -N "$FW_TMP" 2>/dev/null || iptables -F "$FW_TMP"
  # v2.32 Grok: lo + SSH 先于 INVALID,UNTRACKED 放行，保证 conntrack 表满时 SSH 仍可新建连接
  iptables -A "$FW_TMP" -i lo                                       -m comment --comment "transit-manager-rule" -j ACCEPT
  iptables -A "$FW_TMP" -p tcp  --dport "$ssh_port"                 -m comment --comment "transit-manager-rule" -j ACCEPT
  iptables -A "$FW_TMP" -m conntrack --ctstate INVALID,UNTRACKED    -m comment --comment "transit-manager-rule" -j DROP
  iptables -A "$FW_TMP" -m conntrack --ctstate ESTABLISHED,RELATED  -m comment --comment "transit-manager-rule" -j ACCEPT
  iptables -A "$FW_TMP" -p icmp --icmp-type echo-request -m limit --limit 10/second --limit-burst 20 \
                                                                     -m comment --comment "transit-manager-rule" -j ACCEPT
  iptables -A "$FW_TMP" -p icmp --icmp-type echo-request            -m comment --comment "transit-manager-rule" -j DROP
  # v1.3: 明确 ACCEPT 新建 443 连接（connlimit/rate 只拦 DDoS，正常流量必须先过这一关）
  # 规则顺序：① connlimit（超并发 DROP）→ ② rate（超速率 DROP）→ ③ ACCEPT 剩余正常 443 新连接
  iptables -A "$FW_TMP" -p tcp  --dport "$LISTEN_PORT" \
    -m connlimit --connlimit-above 2000 --connlimit-mask 24        -m comment --comment "transit-manager-rule" -j DROP
  iptables -A "$FW_TMP" -p tcp  --dport "$LISTEN_PORT" \
    -m connlimit --connlimit-above 20000 --connlimit-mask 0        -m comment --comment "transit-manager-rule" -j DROP
  iptables -A "$FW_TMP" -p tcp  --dport "$LISTEN_PORT" \
    -m hashlimit --hashlimit-upto 8000/sec --hashlimit-burst 9999 --hashlimit-mode srcip --hashlimit-name transit_443_limit                   -m comment --comment "transit-manager-rule" -j ACCEPT
  # 超速率的 443 DROP（rate 令牌耗尽时走此规则）
  iptables -A "$FW_TMP" -p tcp  --dport "$LISTEN_PORT"              -m comment --comment "transit-manager-rule" -j DROP
  iptables -A "$FW_TMP" -p udp  --dport "$LISTEN_PORT"              -m comment --comment "transit-manager-quic" -j REJECT --reject-with icmp-port-unreachable
  iptables -A "$FW_TMP"                                              -m comment --comment "transit-manager-rule" -j DROP
  iptables -I INPUT 1 -m comment --comment "transit-manager-swap" -j "$FW_TMP"
  # [v2.15] Bulldozer drain before rename: removes every INPUT rule referencing FW_CHAIN
  _bulldoze_input_refs_t "$FW_CHAIN"
  iptables -F "$FW_CHAIN" 2>/dev/null || true; iptables -X "$FW_CHAIN" 2>/dev/null || true
  iptables -E "$FW_TMP" "$FW_CHAIN"
  iptables -I INPUT 1 -m comment --comment "transit-manager-rule" -j "$FW_CHAIN"
  while iptables -D INPUT -m comment --comment "transit-manager-swap" 2>/dev/null; do :; done

  if have_ipv6; then
    ip6tables -N "$FW_TMP6" 2>/dev/null || ip6tables -F "$FW_TMP6"
    ip6tables -A "$FW_TMP6" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ip6tables -A "$FW_TMP6" -i lo -j ACCEPT
    ip6tables -A "$FW_TMP6" -p tcp      --dport "$ssh_port"    -j ACCEPT
    ip6tables -A "$FW_TMP6" -p ipv6-icmp                        -j ACCEPT
    # v2.43 Grok: IPv6 加 connlimit+rate，与 IPv4 对等防护（/64 对应 IPv6 CGNAT 粒度）
    ip6tables -A "$FW_TMP6" -p tcp --dport "$LISTEN_PORT" \
      -m connlimit --connlimit-above 2000 --connlimit-mask 64  -j DROP
    ip6tables -A "$FW_TMP6" -p tcp --dport "$LISTEN_PORT" \
      -m connlimit --connlimit-above 20000 --connlimit-mask 0  -j DROP
    ip6tables -A "$FW_TMP6" -p tcp --dport "$LISTEN_PORT" \
      -m hashlimit --hashlimit-upto 8000/sec --hashlimit-burst 9999 --hashlimit-mode srcip --hashlimit-name transit_443_limit              -j ACCEPT
    ip6tables -A "$FW_TMP6" -p tcp --dport "$LISTEN_PORT"      -j DROP
    ip6tables -A "$FW_TMP6" -j DROP
    ip6tables -I INPUT 1 -m comment --comment "transit-manager-v6-swap" -j "$FW_TMP6"
    # [v2.15] Bulldozer drain for IPv6 before rename
    _bulldoze_input_refs6_t "$FW_CHAIN6"
    ip6tables -F "$FW_CHAIN6" 2>/dev/null || true; ip6tables -X "$FW_CHAIN6" 2>/dev/null || true
    ip6tables -E "$FW_TMP6" "$FW_CHAIN6"
    ip6tables -I INPUT 1 -m comment --comment "transit-manager-v6-jump" -j "$FW_CHAIN6"
    while ip6tables -D INPUT -m comment --comment "transit-manager-v6-swap" 2>/dev/null; do :; done
  fi

  # v2.37 GPT: trap 保持活跃直到 _persist_iptables 成功，防运行链/开机链分裂
  # 旧代码在此处提前 trap - ERR INT TERM，导致 persist 失败时无法回滚
  if ! _persist_iptables "$ssh_port"; then
    _fw_transit_rollback
    trap - ERR INT TERM
    die "防火墙持久化失败（firewall-restore.sh/unit 写入异常），运行链已回滚至旧状态"
  fi
  trap - ERR INT TERM
  rm -f "${_snap_persist:-}" 2>/dev/null || true
  success "防火墙配置完成（chain ${FW_CHAIN} + ${FW_CHAIN6}，SSH:${ssh_port} + 443 + ICMP，蓝绿原子切换零裸奔）"
}

_persist_iptables(){
  local ssh_port="${1:-22}"
  mkdir -p "$MANAGER_BASE"
  local fw_script="${MANAGER_BASE}/firewall-restore.sh"
  # v2.39 GPT #9: 版本签名嵌入脚本头，show_status 校验时可识别旧/手改脚本
  local _fw_sig="TRANSIT_FW_VERSION=${VERSION}_$(date +%Y%m%d)"
  atomic_write "$fw_script" 700 root:root <<FWEOF
#!/bin/sh
# ${_fw_sig}
  # SSH 端口在安装时固化，避免开机早期探测失败造成恢复链路漂移
  SSH_PORT="${ssh_port}"
while iptables  -D INPUT -m comment --comment "transit-manager-rule" 2>/dev/null; do :; done
while iptables  -D INPUT -m comment --comment "transit-manager-swap" 2>/dev/null; do :; done
iptables -F ${FW_CHAIN}  2>/dev/null || true; iptables -X ${FW_CHAIN}  2>/dev/null || true
iptables -N ${FW_CHAIN}  2>/dev/null || true
iptables -A ${FW_CHAIN} -i lo                                       -m comment --comment "transit-manager-rule" -j ACCEPT
iptables -A ${FW_CHAIN} -p tcp  --dport \${SSH_PORT}                -m comment --comment "transit-manager-rule" -j ACCEPT
iptables -A ${FW_CHAIN} -m conntrack --ctstate INVALID,UNTRACKED    -m comment --comment "transit-manager-rule" -j DROP
iptables -A ${FW_CHAIN} -m conntrack --ctstate ESTABLISHED,RELATED  -m comment --comment "transit-manager-rule" -j ACCEPT
iptables -A ${FW_CHAIN} -p icmp --icmp-type echo-request -m limit --limit 10/second --limit-burst 20 -m comment --comment "transit-manager-rule" -j ACCEPT
iptables -A ${FW_CHAIN} -p icmp --icmp-type echo-request            -m comment --comment "transit-manager-rule" -j DROP
iptables -A ${FW_CHAIN} -p tcp  --dport ${LISTEN_PORT} -m connlimit --connlimit-above 2000 --connlimit-mask 24 -m comment --comment "transit-manager-rule" -j DROP
iptables -A ${FW_CHAIN} -p tcp  --dport ${LISTEN_PORT} -m connlimit --connlimit-above 20000 --connlimit-mask 0  -m comment --comment "transit-manager-rule" -j DROP
iptables -A ${FW_CHAIN} -p tcp  --dport ${LISTEN_PORT} -m hashlimit --hashlimit-upto 8000/sec --hashlimit-burst 9999 --hashlimit-mode srcip --hashlimit-name transit_443_limit             -m comment --comment "transit-manager-rule" -j ACCEPT
iptables -A ${FW_CHAIN} -p udp  --dport ${LISTEN_PORT}                                                         -m comment --comment "transit-manager-quic" -j REJECT --reject-with icmp-port-unreachable
iptables -A ${FW_CHAIN} -p tcp  --dport ${LISTEN_PORT}                                                         -m comment --comment "transit-manager-rule" -j DROP
iptables -A ${FW_CHAIN}                                              -m comment --comment "transit-manager-rule" -j DROP
iptables -I INPUT 1 -m comment --comment "transit-manager-rule" -j ${FW_CHAIN}
if [ -f /proc/net/if_inet6 ] && ip6tables -L >/dev/null 2>&1 && [ "\$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 1)" != "1" ]; then
  while ip6tables -D INPUT -m comment --comment "transit-manager-v6-jump" 2>/dev/null; do :; done
  while ip6tables -D INPUT -m comment --comment "transit-manager-v6-swap" 2>/dev/null; do :; done
  ip6tables -F ${FW_CHAIN6} 2>/dev/null || true; ip6tables -X ${FW_CHAIN6} 2>/dev/null || true
  ip6tables -N ${FW_CHAIN6} 2>/dev/null || true
  ip6tables -A ${FW_CHAIN6} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ip6tables -A ${FW_CHAIN6} -i lo -j ACCEPT
  ip6tables -A ${FW_CHAIN6} -p tcp      --dport \${SSH_PORT}      -j ACCEPT
  ip6tables -A ${FW_CHAIN6} -p ipv6-icmp                          -j ACCEPT
  ip6tables -A ${FW_CHAIN6} -p tcp --dport ${LISTEN_PORT} -m connlimit --connlimit-above 2000 --connlimit-mask 64 -j DROP
  ip6tables -A ${FW_CHAIN6} -p tcp --dport ${LISTEN_PORT} -m connlimit --connlimit-above 20000 --connlimit-mask 0  -j DROP
  ip6tables -A ${FW_CHAIN6} -p tcp --dport ${LISTEN_PORT} -m hashlimit --hashlimit-upto 8000/sec --hashlimit-burst 9999 --hashlimit-mode srcip --hashlimit-name transit_443_limit -j ACCEPT
  ip6tables -A ${FW_CHAIN6} -p tcp --dport ${LISTEN_PORT} -j DROP
  ip6tables -A ${FW_CHAIN6} -j DROP
  ip6tables -I INPUT 1 -m comment --comment "transit-manager-v6-jump" -j ${FW_CHAIN6}
fi
FWEOF

  local rsvc="/etc/systemd/system/transit-manager-iptables-restore.service"
  atomic_write "$rsvc" 644 root:root <<RSTO
[Unit]
Description=Restore iptables rules for transit-manager
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
  systemctl daemon-reload
  # [Doc3-2] enable 静默失败 = 重启后规则丢失 = 静默时序炸弹，必须硬失败
  systemctl enable transit-manager-iptables-restore.service \
    || die "iptables 持久化服务 enable 失败，重启后防火墙规则将丢失"
  systemctl is-enabled --quiet transit-manager-iptables-restore.service \
    || die "iptables 持久化服务 enabled 状态验收失败"
  info "防火墙规则已写入: ${fw_script}（开机动态检测 SSH 端口，have_ipv6 守卫 ip6tables）"
}

save_landing_meta(){
  local domain="$1" ip="$2" port="${3:-443}" rollback_map="${4:-}"
  local safe; safe=$(domain_to_safe "$domain")
  mkdir -p "$CONF_DIR"
  # [F2] Field name unified to TRANSIT_IP= (was IP=) to match landing nodes/*.conf schema.
  # read_meta_ip() below accepts both old and new format for backwards compatibility.
  if ! atomic_write "${CONF_DIR}/${safe}.meta" 600 root:root <<MEOF
DOMAIN=${domain}
TRANSIT_IP=${ip}
PORT=${port}
CREATED=$(date +%Y%m%d_%H%M%S)
MEOF
  then
    # meta 写失败：回滚已生效的 .map（恢复旧备份或删除新增）
    if [[ -n "$rollback_map" && -f "$rollback_map" ]]; then
      mv -f "$rollback_map" "${SNIPPETS_DIR}/landing_${safe}.map" 2>/dev/null || true
    else
      rm -f "${SNIPPETS_DIR}/landing_${safe}.map" 2>/dev/null || true
    fi
    # 🔴 Grok: .map 已回滚，必须同步回滚 nginx 运行态，否则运行态与文件态分裂
    nginx -t 2>/dev/null && nginx -s reload 2>/dev/null || true
    die "meta 写入失败，.map 及 Nginx 运行态已回滚（真相源未分裂）"
  fi
  rm -f "$rollback_map" 2>/dev/null || true
}

# v2.35 Grok: 原子提交路由（map + meta + nginx reload 三合一）
# 正常路径: snapshot → write_map → nginx-t → reload → mv_meta → clean
# 失败路径: 任一步骤失败 → restore_map → reload_restore → die
# v2.38 Gemini: .map mv 后立即挂局部 INT/TERM trap，防中断产生"幽灵 .map"（无 .meta 对应）
_atomic_apply_route(){
  # ARCH-2 FIX: 新增 uuid/pwd/pfx 三个参数；meta 存储全量字段供 generate_nodes() 使用
  # v2.39: 先定义函数再注册trap，防止ERR触发时函数未定义
  _route_rollback(){
    [[ -n "${_snap_map:-}"  && -f "${_snap_map:-}"  ]] \
      && mv -f "$_snap_map"  "$map_target"  2>/dev/null \
      || rm -f "$map_target"  2>/dev/null || true
    [[ -n "${_snap_meta:-}" && -f "${_snap_meta:-}" ]] \
      && mv -f "$_snap_meta" "$meta_target" 2>/dev/null \
      || rm -f "$meta_target" 2>/dev/null || true
    if ! nginx -t 2>/dev/null; then
      echo "[WARN] _route_rollback: nginx -t 失败" >&2
    elif ! nginx -s reload 2>/dev/null; then
      echo "[WARN] _route_rollback: nginx reload 失败" >&2
    fi
    rm -f "${_snap_map:-}" "${_snap_meta:-}" 2>/dev/null || true
  }
  trap '_route_rollback; exit 130' INT TERM ERR
  local domain="$1" ip="$2" port="$3"
  local uuid="${4:-}" pwd="${5:-}" pfx="${6:-}"
  local safe; safe=$(domain_to_safe "$domain")
  [[ -n "$safe" ]] || die "域名 safe 转换后为空: ${domain}"
  (( ${#safe} > 64 )) && safe="${safe:0:64}"

  local map_target="${SNIPPETS_DIR}/landing_${safe}.map"
  local meta_target="${CONF_DIR}/${safe}.meta"

  # 1. 快照旧文件（失败时回滚用）
  local _snap_map="" _snap_meta=""
  mkdir -p "$SNIPPETS_DIR" "$CONF_DIR"
  [[ -f "$map_target"  ]] && { _snap_map=$(mktemp "${SNIPPETS_DIR}/.snap-recover.XXXXXX"); cp -f "$map_target"  "$_snap_map";  } || true
  [[ -f "$meta_target" ]] && { _snap_meta=$(mktemp "${CONF_DIR}/.snap-recover.XXXXXX");    cp -f "$meta_target" "$_snap_meta"; } || true

  # 2. 写新 .map（原子 mv 到正式路径供 nginx -t）
  local tmp_map; tmp_map=$(mktemp "${SNIPPETS_DIR}/.snap-recover.XXXXXX")
  local _map_key; _map_key=$(nginx_domain_str "$domain")
  [[ -n "$_map_key" && ${#_map_key} -le 200 ]] \
    || { rm -f "$tmp_map" 2>/dev/null; die "域名过滤后为空或超长，拒绝写入 map: ${domain}"; }
  printf '    %s    %s:%s;\n' "$_map_key" "$(nginx_ip_str "$ip")" "$port" > "$tmp_map"
  chmod 600 "$tmp_map"
  mv -f "$tmp_map" "$map_target"
  chmod 600 "$map_target" 2>/dev/null || true

  trap '_route_rollback; exit 130' INT TERM

  # 3. nginx -t 验证
  if ! nginx -t 2>/dev/null; then
    _route_rollback; trap - INT TERM ERR
    die "Nginx 语法校验失败，.map 已回滚（真相源未分裂）"
  fi

  # [F3] Write meta BEFORE nginx reload: if meta write fails, the running nginx is still on
  # old map (which we will roll back); prevents truth-source split where nginx routes new IP
  # but .meta is missing. Old order (reload→meta) left a window where nginx served new IP
  # with no truth record on disk-full or permission error.
  local tmp_meta; tmp_meta=$(mktemp "${CONF_DIR}/.snap-recover.XXXXXX")
  printf 'DOMAIN=%s\nTRANSIT_IP=%s\nPORT=%s\nUUID=%s\nPWD=%s\nPFX=%s\nCREATED=%s\n' \
    "$domain" "$ip" "$port" "$uuid" "$pwd" "$pfx" "$(date +%Y%m%d_%H%M%S)" > "$tmp_meta"
  chmod 600 "$tmp_meta"
  if ! mv -f "$tmp_meta" "$meta_target"; then
    rm -f "$tmp_meta" 2>/dev/null || true
    _route_rollback; trap - INT TERM ERR
    die "meta 原子提交失败，.map 已回滚（真相源未分裂）"
  fi
  chmod 600 "$meta_target" 2>/dev/null || true

  # 4. nginx reload（运行态更新）— meta is already committed; reload failure is now safe to roll back
  if ! nginx_reload; then
    _route_rollback; trap - INT TERM ERR
    die "Nginx 热重载失败，.map 和 .meta 已回滚"
  fi

  trap - INT TERM ERR
  rm -f "${_snap_map:-}" "${_snap_meta:-}" 2>/dev/null || true
  success "路由原子提交: SNI=${domain} → ${ip}:${port}"
}

list_landings(){
  echo ""
  echo -e "${BOLD}── 已配置落地机 ─────────────────────────────────────────────────${NC}"
  local n=0
  while IFS= read -r meta; do
    [[ -f "$meta" ]] || continue
    local dom ip ts port
    dom=$(grep '^DOMAIN='  "$meta" 2>/dev/null | cut -d= -f2- || echo "?")
    ip=$(read_meta_ip "$meta" 2>/dev/null) || ip="?"
    port=$(grep '^PORT='   "$meta" 2>/dev/null | cut -d= -f2-) || port=443
    ts=$(grep  '^CREATED=' "$meta" 2>/dev/null | cut -d= -f2- || echo "?")
    printf "  [%d] %-38s → %-20s :%s  创建: %s\n" $((++n)) "$dom" "$ip" "$port" "$ts"
  done < <(find "$CONF_DIR" -name "*.meta" -type f 2>/dev/null | sort)
  [[ $n -eq 0 ]] && warn "（暂无已配置落地机）"
  echo ""
}

# ARCH-2: 利用 meta 中存储的 uuid/pwd/pfx 生成完整 4 协议订阅链接
# transit_ip = 中转机公网 IP；每个 meta 对应一条落地链路的完整节点集
generate_nodes(){
  local transit_ip="${1:-}"
  if [[ -z "$transit_ip" ]]; then
    transit_ip=$(get_public_ip)
  fi

  local any=0
  while IFS= read -r meta; do
    [[ -f "$meta" ]] || continue
    local dom ip port uuid pwd pfx
    dom=$(grep  '^DOMAIN=' "$meta" 2>/dev/null | cut -d= -f2-) || continue
    ip=$(read_meta_ip "$meta" 2>/dev/null) || continue
    port=$(grep '^PORT='   "$meta" 2>/dev/null | cut -d= -f2-) || port=443
    uuid=$(grep '^UUID='   "$meta" 2>/dev/null | cut -d= -f2-) || uuid=""
    pwd=$(grep  '^PWD='    "$meta" 2>/dev/null | cut -d= -f2-)  || pwd=""
    pfx=$(grep  '^PFX='    "$meta" 2>/dev/null | cut -d= -f2-)  || pfx=""
    [[ -n "$dom" && -n "$ip" ]] || continue

    if [[ -z "$uuid" || -z "$pwd" || -z "$pfx" ]]; then
      warn "节点 ${dom} 缺少 uuid/pwd/pfx（旧版 Token 导入），跳过节点生成"
      warn "  → 请重新从落地机执行 print_pairing_info 并用新 Token 重新 --import"
      continue
    fi

    echo ""
    echo -e "${BOLD}${GREEN}── 节点订阅: ${dom} ──────────────────────────────────────────${NC}"
    echo -e "  落地机 IP: ${ip}  端口: ${port}  SNI: ${dom}"
    echo -e "  中转机 IP: ${transit_ip}  (客户端连接此 IP)"
    echo ""

    local sub_b64="" _sub_err=""
    # Bug T-1 FIX: f-string `{}` 内不能有 \" (Python<3.12 SyntaxError)
    # 改为先把标签字符串赋值给 Python 变量，再在 f-string 中引用变量
    sub_b64=$(python3 -c "
import base64, urllib.parse, sys
transit_ip, domain, vless_uuid, trojan_pass, pfx = \
    sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
port = 443
# 标签变量：避免在 f-string {} 内使用 \\\" (Python<3.12 SyntaxError)
lbl_vision = '[禁Mux]VLESS-Vision-'
lbl_vgrpc  = 'VLESS-gRPC-'
lbl_vws    = 'VLESS-WS-'
lbl_ttcp   = 'Trojan-TCP-'
uris = [
    (f'vless://{vless_uuid}@{transit_ip}:{port}'
     f'?encryption=none&flow=xtls-rprx-vision&security=tls'
     f'&sni={domain}&fp=chrome&type=tcp&mux=0'
     f'#{urllib.parse.quote(lbl_vision+domain)}'),
    (f'vless://{vless_uuid}@{transit_ip}:{port}'
     f'?encryption=none&security=tls&sni={domain}&fp=edge'
     f'&type=grpc&serviceName={pfx}-vg&alpn=h2&mode=multi'
     f'#{urllib.parse.quote(lbl_vgrpc+domain)}'),
    (f'vless://{vless_uuid}@{transit_ip}:{port}'
     f'?encryption=none&security=tls&sni={domain}&fp=firefox'
     f'&type=ws&path=%2F{pfx}-vw&host={domain}&alpn=http/1.1'
     f'#{urllib.parse.quote(lbl_vws+domain)}'),
    (f'trojan://{urllib.parse.quote(trojan_pass)}@{transit_ip}:{port}'
     f'?security=tls&sni={domain}&fp=safari&type=tcp'
     f'#{urllib.parse.quote(lbl_ttcp+domain)}'),
]
print(base64.b64encode('\n'.join(uris).encode()).decode())
" "$transit_ip" "$dom" "$uuid" "$pwd" "$pfx" 2>&1) \
    || { _sub_err="$sub_b64"; sub_b64=""; }

    if [[ -n "$sub_b64" ]]; then
      echo -e "  ${BOLD}Base64 订阅（粘贴到客户端「添加订阅」）:${NC}"
      echo ""
      echo "  $sub_b64"
      echo ""
      echo -e "  ${CYAN}（Clash Meta / NekoBox / v2rayN / Sing-box / Shadowrocket）${NC}"
      echo -e "  ${RED}${BOLD}⚠  VLESS-Vision 节点【严禁开启 Mux】！开启必断流！${NC}"
    else
      warn "  节点 ${dom} 订阅生成失败"
      [[ -n "${_sub_err:-}" ]] && error "    Python 错误: ${_sub_err}"
    fi
    (( ++any )) || true
  done < <(find "$CONF_DIR" -name "*.meta" -type f 2>/dev/null | sort)

  if (( any == 0 )); then
    warn "无可用节点（meta 文件为空或均缺少 uuid/pwd/pfx）"
  fi
}

import_token(){
  check_deps
  local raw="$1"
  [[ -n "$raw" ]] || die "需要 token 参数"
  raw=$(printf '%s' "$raw" | tr -d ' \n\r\t')
  # 🟠 Grok: 拒绝超长输入（正常 token <1KB），防止畸形 JSON 绕过解析
  (( ${#raw} <= 2048 )) || die "token 过长（${#raw} 字节），拒绝解析"

  local extracted_token=""
  extracted_token=$(printf '%s' "$raw" | grep -oE 'eyJ[a-zA-Z0-9+/=]+' | head -1) || true
  [[ -n "$extracted_token" ]] || die "无法提取 Base64 token，请检查输入"

  local json=""
  json=$(printf '%s' "$extracted_token" | base64 -d 2>/dev/null) \
    || die "Base64 解码失败，token 可能已损坏"

  local ip="" dom="" port="" uuid="" pwd="" pfx=""
  ip=$(python3  -c "import json,sys; d=json.loads(sys.stdin.read()); print(d['ip'])"  <<< "$json" 2>/dev/null) \
    || die "token 解析失败（ip 字段缺失）——请重新从落地机复制完整的导入命令"
  dom=$(python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d['dom'])" <<< "$json" 2>/dev/null) \
    || die "token 解析失败（dom 字段缺失）"
  port=$(python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('port',443))" <<< "$json" 2>/dev/null) || port=443
  [[ "$port" =~ ^[0-9]+$ ]] || port=443
  validate_port "$port"

  # Transit Bug 37 / Token import validation: ip 必须是合法 IPv4，否则给出明确指引
  if ! python3 -c "import ipaddress,sys; ipaddress.IPv4Address(sys.argv[1])" "$ip" 2>/dev/null; then
    die "token 中 ip='${ip}' 不是合法 IPv4 地址！\n  可能原因：落地机生成 Token 时 ip/dom 参数位移（Bug 40）\n  修复方法：在落地机重新执行 bash install_landing_v1.1.sh 并检查落地机 PUBLIC_IP 是否正确"
  fi

  # ARCH-2: 解析新版 Token 中的 uuid/pwd/pfx（旧版 Token 不含这些字段，给出友好告警）
  uuid=$(python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('uuid',''))"  <<< "$json" 2>/dev/null) || uuid=""
  pwd=$(python3  -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('pwd',''))"   <<< "$json" 2>/dev/null) || pwd=""
  pfx=$(python3  -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('pfx',''))"   <<< "$json" 2>/dev/null) || pfx=""
  if [[ -z "$uuid" || -z "$pwd" || -z "$pfx" ]]; then
    warn "Token 中缺少 uuid/pwd/pfx（旧版 Token），只能导入路由，无法生成完整节点订阅"
    warn "  → 请升级落地机至 v1.1 并重新执行 print_pairing_info 获取新版 Token"
  fi

  validate_ip     "$ip"
  validate_domain "$dom"
  # v2.32 Grok: 硬截断防超长域名绕过 map 语法校验
  dom="${dom:0:253}"
  # 🔴 Grok: nginx_domain_str 过滤后若为空（含纯控制字符域名），拒绝生成 map
  local _safe_check; _safe_check=$(nginx_domain_str "$dom")
  [[ -n "$_safe_check" ]] || die "域名过滤后为空（含非法字符），拒绝写入 map: ${dom}"
  info "导入路由规则: ${dom} → ${ip}:${port}"

  if [[ ! -f "$INSTALLED_FLAG" ]]; then
    info "--import 触发首次安装初始化 ..."
    ss -tlnp 2>/dev/null | grep -q ':443 ' && die "443 端口已被占用！请先停止冲突服务后再安装"

    # [v2.8 GPT-Doc2-🔴] Trap registered BEFORE the first side-effect write (check_deps).
    # v2.7 registered it after the 443 check but before check_deps; if apt-get update failed
    # inside check_deps the trap was not yet live → partial nginx install left 443 occupied
    # and the next run's 443 check blocked re-install until manual purge.
    local _import_trap_active=1
    _import_install_rollback(){
      [[ "${_import_trap_active:-0}" == "1" ]] || return 0
      warn "--import 安装中断，执行回滚..."
      systemctl stop nginx 2>/dev/null || true
      systemctl disable --now transit-manager-iptables-restore.service 2>/dev/null || true
      rm -f "/etc/systemd/system/transit-manager-iptables-restore.service" 2>/dev/null || true
      local _esc; _esc=$(printf '%s' "$NGINX_STREAM_CONF" | sed -e 's/[\/&]/\\&/g')
      sed -i "\#${STREAM_INCLUDE_MARKER}#d" "$NGINX_MAIN_CONF" 2>/dev/null || true
      sed -i "\#include ${_esc};#d" "$NGINX_MAIN_CONF" 2>/dev/null || true
      while iptables -D INPUT -j "$FW_CHAIN" 2>/dev/null; do :; done
      while ip6tables -D INPUT -j "$FW_CHAIN6" 2>/dev/null; do :; done
      iptables -F "$FW_CHAIN" 2>/dev/null || true; iptables -X "$FW_CHAIN" 2>/dev/null || true
      systemctl daemon-reload 2>/dev/null || true
      rm -f "$INSTALLED_FLAG" 2>/dev/null || true
      warn "--import 回滚完成。如需重装请重新运行脚本。"
    }
    trap '_import_install_rollback' ERR INT TERM

    write_logrotate
    # [F2] nginx enable must be durable — silent failure means decoy dies on next reboot
    systemctl enable nginx || die "nginx enable failed — decoy will not survive reboot"
    systemctl is-enabled --quiet nginx || die "nginx is-enabled check failed"
    # [v2.7 Architect-🟠] Remove raw `nginx` fallback — treat startup failure as fatal.
    systemctl is-active --quiet nginx 2>/dev/null || systemctl start nginx \
      || die "Nginx 启动失败（systemctl start 返回非零，已触发回滚）"
    mkdir -p "$MANAGER_BASE"

    _import_trap_active=0
    trap '_global_cleanup; echo -e "\n${RED}[中断] 请执行: bash $0 --uninstall${NC}"; exit 1' INT TERM ERR
    # [F1] INSTALLED_FLAG must be committed AFTER _atomic_apply_route, not before.
  fi

  # ARCH-2: 传入 uuid/pwd/pfx，meta 中持久化；generate_nodes() 读取后生成完整订阅
  _atomic_apply_route "$dom" "$ip" "$port" "$uuid" "$pwd" "$pfx"
  # Commit install marker only after route is durably applied
  [[ -f "$INSTALLED_FLAG" ]] || touch "$INSTALLED_FLAG"
  success "路由规则导入完成: SNI=${dom} → ${ip}:${port}"
  echo ""
  echo -e "${BOLD}── 导入成功——生成完整节点订阅 ─────────────────────────────────${NC}"
  generate_nodes
}

add_landing_route(){
  check_deps
  echo ""
  echo -e "${BOLD}── 增加落地机路由规则 ───────────────────────────────────────────${NC}"
  echo "  方式A（傻瓜）：直接粘贴落地机输出的 Base64 Token 或完整导入命令"
  echo "  方式B（手动）：依次输入落地机公网 IP 和域名"
  echo ""
  # v2.32: 全局写锁，防两终端并发踩踏状态
  _acquire_lock
  read -rp "  请输入落地机 IP 或直接粘贴 Token/命令: " INPUT_DATA
  # 🟠 Grok: 拒绝超长输入，防止畸形字符串绕过 validate 或制造状态分裂
  (( ${#INPUT_DATA} <= 2048 )) || { _release_lock; die "输入过长（${#INPUT_DATA} 字节），拒绝处理"; }

  local extracted_token=""
  extracted_token=$(printf '%s' "$INPUT_DATA" | grep -oE 'eyJ[a-zA-Z0-9+/=]+' | head -1) || true
  if [[ -n "$extracted_token" ]]; then
    import_token "$extracted_token"; _release_lock; return
  fi

  local LANDING_IP="$INPUT_DATA"
  validate_ip "$LANDING_IP"
  read -rp "  落地机域名(SNI): " LANDING_DOMAIN
  LANDING_DOMAIN=$(tr '[:upper:]' '[:lower:]' <<< "$LANDING_DOMAIN")
  validate_domain "$LANDING_DOMAIN"
  # v2.32 Grok: 硬截断防超长域名绕过 map 语法校验
  LANDING_DOMAIN="${LANDING_DOMAIN:0:253}"
  read -rp "  落地机监听端口（默认 8443）[8443]: " LANDING_PORT_IN
  LANDING_PORT_IN="${LANDING_PORT_IN:-8443}"
  validate_port "$LANDING_PORT_IN"

  # 🔴 Grok: safe 字符串空值守卫
  local _safe_chk; _safe_chk=$(nginx_domain_str "$LANDING_DOMAIN")
  [[ -n "$_safe_chk" ]] || { _release_lock; die "域名过滤后为空（含非法字符），拒绝写入 map: ${LANDING_DOMAIN}"; }

  local safe; safe=$(domain_to_safe "$LANDING_DOMAIN")
  if [[ -f "${SNIPPETS_DIR}/landing_${safe}.map" ]]; then
    warn "该域名已存在路由规则！"
    read -rp "  覆盖更新？[y/N]: " OW
    [[ "$OW" =~ ^[Yy]$ ]] || { info "已取消"; _release_lock; return; }
  fi

  # 五步原子变更: 快照已有 snippet（使用独立前缀避免被 _global_cleanup 误删）
  local _old_bak=""
  if [[ -f "${SNIPPETS_DIR}/landing_${safe}.map" ]]; then
    _old_bak=$(mktemp "${SNIPPETS_DIR}/.snap-recover.XXXXXX")
    cp -f "${SNIPPETS_DIR}/landing_${safe}.map" "$_old_bak" 2>/dev/null || _old_bak=""
  fi

  # v2.35 Grok: _atomic_apply_route 内部自管快照，外部 _old_bak 仍保留供 SIGINT 清理
  _atomic_apply_route "$LANDING_DOMAIN" "$LANDING_IP" "$LANDING_PORT_IN"
  rm -f "$_old_bak" 2>/dev/null || true
  _release_lock
  success "路由规则已生效: SNI=${LANDING_DOMAIN} → ${LANDING_IP}:${LANDING_PORT_IN}"
}

delete_landing_route(){
  list_landings
  local meta_count=0
  [[ -d "$CONF_DIR" ]] \
    && meta_count=$(find "$CONF_DIR" -name "*.meta" -type f 2>/dev/null | wc -l) || true
  (( meta_count > 0 )) || { warn "无可删除的落地机"; return; }

  read -rp "请输入要删除的落地机域名（或上方列表中的编号）: " DEL_DOMAIN
  # v2.32: 确认输入后才加锁，避免等待用户输入时持锁过久
  _acquire_lock

  if [[ "$DEL_DOMAIN" =~ ^[0-9]+$ ]]; then
    local n=0 matched=""
    while IFS= read -r meta; do
      (( ++n ))
      if (( n == DEL_DOMAIN )); then
        matched=$(grep '^DOMAIN=' "$meta" 2>/dev/null | cut -d= -f2-) || true; break
      fi
    done < <(find "$CONF_DIR" -name "*.meta" -type f 2>/dev/null | sort)
    [[ -n "$matched" ]] || { _release_lock; die "编号 ${DEL_DOMAIN} 不存在"; }
    DEL_DOMAIN="$matched"
    info "已选择: ${DEL_DOMAIN}"
  else
    DEL_DOMAIN=$(tr '[:upper:]' '[:lower:]' <<< "$DEL_DOMAIN")
  fi

  validate_domain "$DEL_DOMAIN"
  local safe_del; safe_del=$(domain_to_safe "$DEL_DOMAIN")

  # 五步原子变更：快照 .map + .meta，nginx_reload 失败时恢复
  local _bak_map="" _bak_meta=""
  [[ -f "${SNIPPETS_DIR}/landing_${safe_del}.map" ]] && {
    _bak_map=$(mktemp "${SNIPPETS_DIR}/.snap-recover.XXXXXX")
    cp -f "${SNIPPETS_DIR}/landing_${safe_del}.map" "$_bak_map"
  }
  [[ -f "${CONF_DIR}/${safe_del}.meta" ]] && {
    _bak_meta=$(mktemp "${CONF_DIR}/.snap-recover.XXXXXX")
    cp -f "${CONF_DIR}/${safe_del}.meta" "$_bak_meta"
  }

  remove_landing_snippet "$DEL_DOMAIN"

  if ! ( nginx_reload ); then
    warn "Nginx 热重载失败，恢复被删配置..."
    [[ -n "$_bak_map"  ]] && mv -f "$_bak_map"  "${SNIPPETS_DIR}/landing_${safe_del}.map" 2>/dev/null || true
    [[ -n "$_bak_meta" ]] && mv -f "$_bak_meta" "${CONF_DIR}/${safe_del}.meta"             2>/dev/null || true
    rm -f "$_bak_map" "$_bak_meta" 2>/dev/null || true
    _release_lock; die "删除回滚完成，Nginx 运行态未受影响"
  fi
  rm -f "$_bak_map" "$_bak_meta" 2>/dev/null || true
  _release_lock
  success "落地机路由 ${DEL_DOMAIN} 已删除并热重载生效"
}

show_status(){
  echo ""
  echo -e "${BOLD}── 中转机状态 ──────────────────────────────────────────────────${NC}"
  [[ -f "$INSTALLED_FLAG" ]] && echo "  已安装: 是" || echo "  已安装: 否"
  echo "  Nginx: $(systemctl is-active nginx 2>/dev/null || echo inactive)"
  echo "  监听端口: ${LISTEN_PORT}"
  local snippet_count=0
  [[ -d "$SNIPPETS_DIR" ]] && snippet_count=$(find "$SNIPPETS_DIR" -name "*.map" ! -name "*dummy*" -type f 2>/dev/null | wc -l)
  echo "  已配置落地机: ${snippet_count}"
  list_landings
  echo -e "  ${CYAN}错误日志: tail -f ${LOG_DIR}/transit_stream_error.log${NC}"
  echo ""
  echo -e "  ${BOLD}── 状态硬校验 ────────────────────────────────────────────────${NC}"
  local _ok=1
  systemctl is-active --quiet nginx 2>/dev/null \
    && echo "  Nginx 运行态:    ✓" \
    || { echo -e "  ${RED}Nginx 运行态:    ✗ 未运行${NC}"; _ok=0; }
  ss -tlnp 2>/dev/null | grep -q ":${LISTEN_PORT} " \
    && echo "  :443 监听:       ✓" \
    || { echo -e "  ${RED}:443 监听:       ✗ 端口未开放${NC}"; _ok=0; }
  grep -q "$STREAM_INCLUDE_MARKER" "$NGINX_MAIN_CONF" 2>/dev/null \
    && echo "  stream include:  ✓" \
    || { echo -e "  ${RED}stream include:  ✗ nginx.conf 中已丢失${NC}"; _ok=0; }
  nginx -t >/dev/null 2>&1 \
    && echo "  nginx -t:        ✓" \
    || { echo -e "  ${RED}nginx -t:        ✗ 配置校验失败${NC}"; _ok=0; }
  systemctl is-enabled --quiet "transit-manager-iptables-restore.service" 2>/dev/null \
    && echo "  iptables 恢复服务:  ✓ enabled" \
    || { echo -e "  ${RED}iptables 恢复服务:  ✗ 未 enable（重启后规则会丢失）${NC}"; _ok=0; }
  # v2.34 GPT: 恢复脚本与运行链不一致 → _ok=0 直接判红，不允许报"整体一致"
  local _fw_script="${MANAGER_BASE}/firewall-restore.sh"
  if [[ -f "$_fw_script" ]]; then
    # v2.39 GPT #9: 版本签名校验
    local _fw_ver_line; _fw_ver_line=$(grep '^# TRANSIT_FW_VERSION=' "$_fw_script" 2>/dev/null | head -1 || echo "")
    if [[ -z "$_fw_ver_line" ]]; then
      # v2.44 GPT: --status 只读，无签名只报红，不调 _persist_iptables（防巡检引入状态分裂）
      echo -e "  ${RED}恢复脚本版本:    ✗ 无版本签名（旧版/手改脚本）${NC}"; _ok=0
      echo -e "  ${CYAN}  修复: bash $0 --import <token> 重建防火墙持久化脚本${NC}"
    else
      echo -e "  恢复脚本版本:    ${GREEN}✓ ${_fw_ver_line#*=}${NC}"
    fi
    # 校验运行链中 INVALID DROP 规则是否存在
    iptables -L "$FW_CHAIN" -n 2>/dev/null | grep -q 'INVALID' \
      && echo -e "  INVALID DROP:    ${GREEN}✓${NC}" \
      || { echo -e "  ${RED}INVALID DROP:    ✗ 规则缺失（执行 --import 或重装以修复）${NC}"; _ok=0; }
    # proxy_timeout 文件态 vs nginx 运行态对比
    local _rscript_pt _live_pt
    _rscript_pt=$(grep -oP 'proxy_timeout\s+\K[0-9]+' "$NGINX_STREAM_CONF" 2>/dev/null | head -1 || echo "")
    _live_pt=$(nginx -T 2>/dev/null | grep -oP 'proxy_timeout\s+\K[0-9]+' | head -1 || echo "")
    if [[ -n "$_rscript_pt" && "$_rscript_pt" != "$_live_pt" ]]; then
      # v2.40 GPT #5: --status 是只读巡检，不执行写操作；漂移只报红，修复用独立命令
      echo -e "  ${RED}恢复脚本存在:    ✗ proxy_timeout 与运行态不一致（需手动修复）${NC}"; _ok=0
      echo -e "  ${CYAN}  修复: bash $0 --import <token> 重建防火墙和持久化脚本${NC}"
    else
      echo -e "  恢复脚本存在:    ${GREEN}✓${NC}"
    fi
  else
    echo -e "  ${RED}恢复脚本:        ✗ 不存在（重启后防火墙规则会丢失）${NC}"; _ok=0
  fi
  ((_ok)) \
    && echo -e "  ${GREEN}整体状态: 一致 ✓${NC}" \
    || { echo -e "  ${RED}整体状态: 存在分裂，请排查 ✗${NC}"; echo ""; return 1; }
  echo ""
}

purge_all(){
  echo ""
  warn "此操作清除本脚本所有内容（Nginx 服务不卸载，mack-a 不影响）"
  read -rp "确认清除？输入 'DELETE' 确认: " CONFIRM
  [[ "$CONFIRM" == "DELETE" ]] || { info "已取消"; return; }

  # 原子卸载序：先改 nginx.conf → 显式校验 include 已移除 → 再删文件 → 再次 nginx -t → reload
  local _purge_bak=""
  if [[ -f "$NGINX_MAIN_CONF" ]]; then
    _purge_bak=$(mktemp "${MANAGER_BASE}/.snap-recover.XXXXXX" 2>/dev/null) || _purge_bak=""
    [[ -n "$_purge_bak" ]] && cp -f "$NGINX_MAIN_CONF" "$_purge_bak" 2>/dev/null || true
    sed -i "\#${STREAM_INCLUDE_MARKER}#d" "$NGINX_MAIN_CONF" 2>/dev/null || true
    local esc; esc=$(printf '%s' "$NGINX_STREAM_CONF" | sed -e 's/[\/&]/\\&/g')
    sed -i "\#include ${esc};#d" "$NGINX_MAIN_CONF" 2>/dev/null || true
    sed -i '/^worker_rlimit_nofile[[:space:]]/d' "$NGINX_MAIN_CONF" 2>/dev/null || true
    sed -i '/^\s*worker_connections\s\+100000\s*;/d' "$NGINX_MAIN_CONF" 2>/dev/null || true

    # [v2.10 Grok-Doc7-🔴] Explicitly verify the include marker was removed by sed.
    # A manually-edited nginx.conf (e.g. trailing space on the include line) causes sed to
    # fail silently; without this check the script would delete the stream file and leave
    # nginx.conf referencing a now-missing path → nginx reload failure → host nginx down.
    if grep -q "$STREAM_INCLUDE_MARKER" "$NGINX_MAIN_CONF" 2>/dev/null; then
      [[ -n "$_purge_bak" && -f "$_purge_bak" ]] && mv -f "$_purge_bak" "$NGINX_MAIN_CONF" 2>/dev/null || true
      rm -f "$_purge_bak" 2>/dev/null || true
      die "卸载中止：stream include 标记仍在 nginx.conf（sed 未能匹配）。\n  请手动删除包含 '${STREAM_INCLUDE_MARKER}' 的行，然后重新运行 --uninstall"
    fi
    # Also verify the explicit include path is gone (belt-and-suspenders)
    if grep -qF "include ${NGINX_STREAM_CONF}" "$NGINX_MAIN_CONF" 2>/dev/null; then
      [[ -n "$_purge_bak" && -f "$_purge_bak" ]] && mv -f "$_purge_bak" "$NGINX_MAIN_CONF" 2>/dev/null || true
      rm -f "$_purge_bak" 2>/dev/null || true
      die "卸载中止：include 路径仍在 nginx.conf。请手动清理后重试"
    fi
    # Pre-delete nginx -t: stream file still on disk so we can validate the mutated conf
    if ! nginx -t 2>/dev/null; then
      warn "nginx.conf 校验失败（stream 文件仍存在），还原中..."
      [[ -n "$_purge_bak" && -f "$_purge_bak" ]] && mv -f "$_purge_bak" "$NGINX_MAIN_CONF" 2>/dev/null || true
      rm -f "$_purge_bak" 2>/dev/null || true
      die "卸载中止：nginx.conf 已还原，请手动检查后重试"
    fi
    rm -f "$_purge_bak" 2>/dev/null || true
  fi

  rm -rf "$SNIPPETS_DIR"
  rm -f  "$NGINX_STREAM_CONF"

  # [v2.10] Post-delete nginx -t: now that files are gone, confirm nginx.conf is still valid.
  # If this fails the fallback is restart (nginx rebuilds its config from scratch).
  if nginx -t 2>/dev/null; then
    if ! { systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null; }; then
      error "nginx reload 失败！请手动执行: nginx -s reload"
      warn "卸载完成，但 nginx 进程未刷新；建议: systemctl restart nginx"
    fi
  else
    warn "nginx -t 失败（配置已删除），尝试直接重启..."
    systemctl restart nginx 2>/dev/null || warn "nginx 重启失败，请手动处理"
  fi

  rm -f "/etc/systemd/system/nginx.service.d/transit-manager-override.conf" 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
  rm -f "${NGINX_MAIN_CONF}.transit.bak_"* 2>/dev/null || true

  # [v2.15.1] purge_all: use bulldozer to remove ALL INPUT references to FW_CHAIN regardless
  # of comment text, then flush and delete. Old comment-based while loops missed rules with
  # unexpected comments, leaving the chain referenced → iptables -X failed silently → chain
  # persisted after uninstall → next install collided with stale chain.
  _purge_bulldoze(){
    local _chain="$1" _num
    # [v2.15.2] Delete by line number: no grep/word-splitting, exact target-column match.
    while true; do
      _num=$(iptables -L INPUT --line-numbers -n 2>/dev/null \
             | awk -v c="$_chain" 'NR>2 && $2==c {print $1; exit}')
      [[ -n "$_num" ]] || break
      iptables -D INPUT "$_num" 2>/dev/null || break
    done
  }
  _purge_bulldoze6(){
    local _chain="$1" _num
    # [v2.15.2] Delete by line number: no grep/word-splitting, exact target-column match.
    while true; do
      _num=$(ip6tables -L INPUT --line-numbers -n 2>/dev/null \
             | awk -v c="$_chain" 'NR>2 && $2==c {print $1; exit}')
      [[ -n "$_num" ]] || break
      ip6tables -D INPUT "$_num" 2>/dev/null || break
    done
  }
  _purge_bulldoze  "$FW_CHAIN";  _purge_bulldoze  "${FW_CHAIN}-NEW"
  iptables -F "$FW_CHAIN"  2>/dev/null || true
  iptables -X "$FW_CHAIN"  2>/dev/null || true

  # v2.32 Gemini: 无条件盲删 ip6tables chain，不依赖 have_ipv6()——
  # 环境变更（事后禁用 IPv6）会导致 have_ipv6 返回假而跳过清理，造成内核 Netfilter 僵尸链残留
  _purge_bulldoze6 "$FW_CHAIN6"; _purge_bulldoze6 "${FW_CHAIN6}-NEW"
  ip6tables -F "$FW_CHAIN6" 2>/dev/null || true
  ip6tables -X "$FW_CHAIN6" 2>/dev/null || true

  systemctl disable --now "transit-manager-iptables-restore.service" 2>/dev/null || true
  rm -f "/etc/systemd/system/transit-manager-iptables-restore.service" 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
  # 🟠 Grok: 卸载时不写公共持久化文件，避免覆盖宿主机其他防火墙规则
  # iptables-save > /etc/iptables/rules.v4 已移除

  rm -f /etc/sysctl.d/99-transit-bbr.conf /etc/modprobe.d/nf_conntrack.conf 2>/dev/null || true
  rm -f "$LOGROTATE_FILE" 2>/dev/null || true
  # v2.32 Gemini: 卸载时清除日志目录，防止重装后僵尸日志污染
  rm -rf "$LOG_DIR" 2>/dev/null || true
  rm -rf "$MANAGER_BASE"
  # 卸载后验收
  local _clean=1
  [[ -d "$SNIPPETS_DIR" ]]   && { warn "SNIPPETS_DIR 残留"; _clean=0; } || true
  [[ -f "$NGINX_STREAM_CONF" ]] && { warn "stream conf 残留"; _clean=0; } || true
  systemctl is-active --quiet "transit-manager-iptables-restore.service" 2>/dev/null \
    && { warn "iptables 恢复服务仍活跃"; _clean=0; } || true
  iptables -L "$FW_CHAIN" >/dev/null 2>&1 \
    && { warn "iptables chain ${FW_CHAIN} 仍存在"; _clean=0; } || true
  ((_clean)) \
    && success "清除完毕（验收通过），mack-a/v2ray-agent 及 Nginx 均未受影响" \
    || warn "清除完毕，但存在残留项，重装前请手动确认（mack-a 未受影响）"
}

installed_menu(){
  echo ""
  echo -e "${BOLD}${CYAN}══ 中转机管理菜单 ══════════════════════════════════════════════${NC}"
  list_landings
  echo "  1. 增加落地机路由规则（粘贴 Token 或手动输入）"
  echo "  2. 删除指定落地机路由规则"
  echo "  3. 清除本系统所有数据（不影响 mack-a）"
  echo "  4. 退出"
  echo "  5. 显示当前所有节点及订阅链接"
  echo ""
  read -rp "请选择 [1-5]: " CHOICE
  case "$CHOICE" in
    1) add_landing_route;   installed_menu ;;
    2) delete_landing_route; installed_menu ;;
    3) purge_all ;;
    4) info "退出"; exit 0 ;;
    5) generate_nodes;      installed_menu ;;
    *) warn "无效选项: ${CHOICE}"; installed_menu ;;
  esac
}

fresh_install(){
  # v2.32 Gemini: 半安装残留检测 — .installed 不存在但 stream include 残留时，
  # 先清除 nginx.conf 中的 include 行，避免后续 443 占用检测误判为"已安装"
  if grep -q "$STREAM_INCLUDE_MARKER" "$NGINX_MAIN_CONF" 2>/dev/null && [[ ! -f "$INSTALLED_FLAG" ]]; then
    warn "检测到半安装残留（stream include 存在但 .installed 缺失），清除 nginx.conf 残留..."
    local _esc_half; _esc_half=$(printf '%s' "$NGINX_STREAM_CONF" | sed -e 's/[\/&]/\\&/g')
    sed -i "\#${STREAM_INCLUDE_MARKER}#d" "$NGINX_MAIN_CONF" 2>/dev/null || true
    sed -i "\#include ${_esc_half};#d" "$NGINX_MAIN_CONF" 2>/dev/null || true
    nginx -t 2>/dev/null && { systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null || true; } || true
  fi
  echo ""
  echo -e "${BOLD}${CYAN}══ 中转机全新安装 ${VERSION} ══════════════════════════════════════════${NC}"
  echo ""
  echo -e "  本脚本将执行："
  echo -e "  ${GREEN}①${NC} 安装 Nginx（stream 模块，TFO fastopen=256，Keepalive=3m:10s:3）"
  echo -e "  ${GREEN}②${NC} 配置 SNI 嗅探纯 TCP 透传（空/无匹配SNI→Apple CDN，有效SNI→落地机）"
  echo -e "  ${GREEN}③${NC} 优化 TCP conntrack + Nginx fd 上限"
  echo -e "  ${GREEN}④${NC} iptables: 仅开放 SSH + TCP 443 + ICMP，其余 DROP（动态双栈守卫）"
  echo -e "  ${GREEN}⑤${NC} 录入第一台落地机配对信息"
  echo ""
  read -rp "确认开始安装？[y/N]: " CONFIRM
  [[ "$CONFIRM" =~ ^[Yy]$ ]] || { info "已取消"; exit 0; }

  # FW-2 FIX: 半安装死锁：防火墙配置中断后 nginx 仍占用 443，重试时 die 导致无限死锁
  # 判断逻辑：
  #   ① nginx 占 443 + stream include 存在 → 本脚本半装，stop nginx 后继续重装
  #   ② 其他进程占 443 → 真正冲突，die 要求用户手动处理
  if ss -tlnp 2>/dev/null | grep -q ':443 '; then
    if systemctl is-active --quiet nginx 2>/dev/null \
        && grep -q "$STREAM_INCLUDE_MARKER" "$NGINX_MAIN_CONF" 2>/dev/null; then
      warn "检测到本脚本半安装状态（nginx 占 443 + stream include 存在）"
      warn "自动停止 nginx，清除残留后继续重装..."
      systemctl stop nginx 2>/dev/null || nginx -s stop 2>/dev/null || true
      sleep 1
      # 再次确认 443 已释放
      if ss -tlnp 2>/dev/null | grep -q ':443 '; then
        die "nginx 停止后 443 仍被占用（可能有其他进程），请手动执行: ss -tlnp | grep :443"
      fi
      info "443 端口已释放，继续安装..."
    else
      die "443 端口已被非本脚本进程占用！请先停止冲突服务后再安装（mack-a 等请确认其 443 用途）"
    fi
  fi

  check_deps
  optimize_kernel_network
  install_nginx
  init_nginx_stream
  setup_firewall_transit
  write_logrotate

  mkdir -p "$MANAGER_BASE"
  # [Doc3-1] 事务回滚 trap：nginx/firewall 已写入但路由导入失败时，撤销所有副作用
  # 触发条件：add_landing_route 失败 / 用户 Ctrl-C / 任何 ERR
  local _install_trap_active=1
  _fresh_install_rollback(){
    [[ "${_install_trap_active:-0}" == "1" ]] || return 0
    warn "安装中断，执行事务回滚..."
    systemctl stop nginx 2>/dev/null || true
    # [F5] Remove nginx artifacts — without this, next run finds Nginx already configured
    # and collides with existing stream config / fallback
    rm -f "$NGINX_STREAM_CONF" 2>/dev/null || true
    rm -f "$LOGROTATE_FILE" 2>/dev/null || true
    systemctl disable transit-manager-iptables-restore.service 2>/dev/null || true
    rm -f "/etc/systemd/system/transit-manager-iptables-restore.service" 2>/dev/null || true
    local _esc; _esc=$(printf '%s' "$NGINX_STREAM_CONF" | sed -e 's/[\/&]/\\&/g')
    sed -i "\#${STREAM_INCLUDE_MARKER}#d" "$NGINX_MAIN_CONF" 2>/dev/null || true
    sed -i "\#include ${_esc};#d" "$NGINX_MAIN_CONF" 2>/dev/null || true
    while iptables -D INPUT -j "$FW_CHAIN" 2>/dev/null; do :; done
    while ip6tables -D INPUT -j "$FW_CHAIN6" 2>/dev/null; do :; done
    iptables -F "$FW_CHAIN" 2>/dev/null || true; iptables -X "$FW_CHAIN" 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
    rm -f "$INSTALLED_FLAG" 2>/dev/null || true
    warn "回滚完成。如需重装请重新运行脚本。"
  }
  trap '_fresh_install_rollback' ERR INT TERM

  # nginx 启动必须在路由导入前完成（路由导入会触发 nginx reload）
  # [F2] hard-fail on enable — reboot persistence is a contract requirement
  systemctl enable nginx || die "nginx enable failed — decoy will not survive reboot"
  systemctl is-enabled --quiet nginx || die "nginx is-enabled check failed"
  # [v2.7 Architect-🟠] Remove raw `nginx` fallback: an unmanaged daemon breaks idempotent
  # stop/reload/rollback and leaves the host in a "works now, unmanaged later" state.
  # Startup failure must be fatal and trigger _fresh_install_rollback.
  systemctl start nginx 2>/dev/null || die "Nginx 启动失败（systemctl start nginx 返回非零，已触发回滚）"

  echo ""
  echo -e "${BOLD}── 录入第一台落地机配令人信息 ─────────────────────────────────────${NC}"
  add_landing_route

  # 路由导入成功，提交安装标记并解除回滚 trap
  _install_trap_active=0
  trap '_global_cleanup; echo -e "\n${RED}[中断] 请执行: bash $0 --uninstall${NC}"; exit 1' INT TERM
  touch "$INSTALLED_FLAG"

  echo ""
  success "══ 中转机安装完成！══"
  echo ""
  echo -e "  ${BOLD}错误日志：${NC}"
  # FIX-F: 原路径写死 /var/log/nginx/...，实际路径是 ${LOG_DIR}/...
  echo -e "  ${CYAN}tail -f ${LOG_DIR}/transit_stream_error.log${NC}"
  echo ""
}

_ver_gt(){ [[ "$(printf '%s\n' "$1" "$2" | sort -V | tail -1)" == "$1" && "$1" != "$2" ]]; }
_check_update(){
  local self_name="install_transit_optimized.sh"
  local cur_ver="$VERSION"
  local remote
  remote=$(curl -fsSL --connect-timeout 3 --retry 1 \
    "https://raw.githubusercontent.com/vpn3288/cn2gia-transit/main/${self_name}" \
    2>/dev/null | grep -o 'v[0-9]\+\.[0-9]\+' | head -1) || return 0
  [[ -n "$remote" ]] && _ver_gt "$remote" "$cur_ver" && warn "发现新版本 ${remote}！建议重新下载" || true
}

main(){
  echo -e "${BOLD}"
  echo "╔══════════════════════════════════════════════════════════════════╗"
  printf "║     美西 CN2 GIA 中转机安装脚本  %-32s║\n" "${VERSION}"
  echo "║     SNI嗅探 → 纯TCP盲传(TFO+KA=3m:10s:3+backlog=65535) → 落地机║"
  echo "║     空/无匹配SNI→17.253.144.10:443（苹果CDN）· proxy_timeout=315s     ║"
  echo "║     atomic_write · python validate · have_ipv6() · logrotate    ║"
  echo "║     与 mack-a/v2ray-agent 完全物理隔离                         ║"
  echo "╚══════════════════════════════════════════════════════════════════╝"
  echo -e "${NC}"

  if [[ "${1:-}" == "--uninstall" ]]; then purge_all; exit 0; fi
  if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then show_help; exit 0; fi
  if [[ "${1:-}" == "--import" ]]; then
    # v2.32: --import 直接调用时加锁；通过 add_landing_route 间接调用时锁已由调用方持有
    _acquire_lock; import_token "${2:-}"; _release_lock; exit 0
  fi
  if [[ "${1:-}" == "--status" ]]; then show_status; exit $?; fi

  _check_update &>/dev/null &
  if [[ -f "$INSTALLED_FLAG" ]]; then
    # [v2.8 Architect-🟠] Startup stale-marker reconciliation: verify the durable set
    # (nginx stream include + at least one .meta file). A SIGKILL during import_token's
    # first-time path can write INSTALLED_FLAG while nginx artifacts are incomplete.
    local _durable_transit=1
    grep -q "$STREAM_INCLUDE_MARKER" "$NGINX_MAIN_CONF" 2>/dev/null       || _durable_transit=0
    find "$CONF_DIR" -name "*.meta" -type f -maxdepth 1 2>/dev/null \
         | grep -q . 2>/dev/null                                           || _durable_transit=0
    if (( _durable_transit == 0 )); then
      warn "[v2.8] 安装标记存在但持久化集（stream include/meta）不完整，清除标记重新安装..."
      rm -f "$INSTALLED_FLAG"
      fresh_install
      return
    fi
    # 🟠 GPT: .installed 降为辅助证据，三态交叉校验（nginx/stream-include/meta文件）
    local _svc_ok=0 _inc_ok=0 _meta_ok=0
    systemctl is-active --quiet nginx 2>/dev/null && _svc_ok=1 \
      || warn "Nginx 未运行"
    grep -q "$STREAM_INCLUDE_MARKER" "$NGINX_MAIN_CONF" 2>/dev/null && _inc_ok=1 \
      || warn "stream include 已丢失"
    local _mc; _mc=$(find "$CONF_DIR" -name "*.meta" -type f 2>/dev/null | wc -l)
    (( _mc > 0 )) && _meta_ok=1
    # v2.42 GPT #1: 逐项校验 meta→map 对应关系，不只计数
    local _meta_drift=0
    while IFS= read -r _mf; do
      [[ -f "$_mf" ]] || continue
      local _mdom; _mdom=$(grep '^DOMAIN=' "$_mf" 2>/dev/null | cut -d= -f2-) || continue
      [[ -n "$_mdom" ]] || continue
      local _msafe; _msafe=$(domain_to_safe "$_mdom")
      if [[ ! -f "${SNIPPETS_DIR}/landing_${_msafe}.map" ]]; then
        warn "真相源不完整: ${_mdom} 有 .meta 但缺 .map（路由缺失）"; _meta_drift=1
      fi
    done < <(find "$CONF_DIR" -name "*.meta" -type f 2>/dev/null | sort)
    (( _meta_drift )) && _meta_ok=0 || true
    # 三态全缺 → 脏安装，清标记重装
    if (( _svc_ok == 0 && _inc_ok == 0 && _meta_ok == 0 )); then
      warn "安装标记存在但三态（nginx/stream/meta）全部缺失，清除标记重新安装..."
      rm -f "$INSTALLED_FLAG"
      fresh_install
      return
    fi
    (( _svc_ok == 0 || _inc_ok == 0 )) && warn "建议先执行 --status 排查状态分裂" || true
    # v2.33 GPT: 部分损坏时先强制 reconcile，失败则拒绝进管理菜单
    local _reconcile_ok=1
    if (( _inc_ok == 0 )); then
      warn "stream include 丢失，自动修复中..."
      # v2.42 GPT #2: reload 成功才算修复，不能只靠 nginx -t
      if init_nginx_stream 2>/dev/null; then
        if systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null; then
          nginx -t 2>/dev/null && success "stream include 已修复（reload 已生效）"             || { warn "stream include 修复后 nginx -t 失败"; _reconcile_ok=0; }
        else
          warn "stream include 修复后 nginx reload 失败（运行态未生效）"; _reconcile_ok=0
        fi
      else
        warn "stream include 修复失败"; _reconcile_ok=0
      fi
    fi
    if (( _svc_ok == 0 )); then
      warn "Nginx 未运行，尝试启动..."
      if systemctl start nginx 2>/dev/null; then
        success "Nginx 已恢复运行"
      else
        warn "Nginx 启动失败"; _reconcile_ok=0
      fi
    fi
    if (( _meta_drift )); then
      warn "路由真相源不完整（部分 meta 缺对应 .map），请 --status 排查或重新 --import"
      _reconcile_ok=0
    fi
    if (( _reconcile_ok == 0 )); then
      error "自动恢复失败，拒绝进入管理菜单（防止在分裂状态上继续写操作）"
      echo -e "  请先执行: ${CYAN}bash $0 --status${NC} 排查"
      echo -e "  若无法修复，请执行: ${CYAN}bash $0 --uninstall${NC} 清除后重装"
      exit 1
    fi
    installed_menu
  else
    fresh_install
  fi
}

main "$@"
