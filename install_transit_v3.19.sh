#!/usr/bin/env bash
# install_transit_v3.1.sh — 中转机安装脚本 v3.1
# SNI嗅探 → 纯TCP盲传(TFO+KA=3m:10s:3+backlog=65535) → 落地机 | 动态双栈兼容
# 空/无匹配SNI→17.253.144.10:443（苹果CDN，无DNS）· proxy_timeout=315s
# v3.7: [Fix] delete_landing_route 现在正确删除 .meta 文件（之前只删备份）
set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1;1m'; NC='\033[0m'
readonly VERSION="v3.20"

info()    { echo -e "${CYAN}[INFO]${NC}    $*"; }
success() { echo -e "${GREEN}[OK]${NC}     $*"; }
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
readonly TEMP_DIR="${MANAGER_BASE}/tmp"

[[ $EUID -eq 0 ]] || die "必须以 root 身份运行"

# 清理函数：清理本脚本创建的临时文件（前缀隔离）
_transit_cleanup(){
  # 清理 1 天前的临时文件（防止误删正在使用的文件）
  find "${MANAGER_BASE}" /etc/nginx /etc/systemd/system /etc/logrotate.d \
    -maxdepth 5 -type f \( -name '.transit-mgr.*' -o -name '.snap-recover.*' \) \
    -mtime +1 -delete 2>/dev/null || true
  # 清理当前会话创建的 snippet/map 文件
  find "${SNIPPETS_DIR}" -maxdepth 1 -type f -name '.transit-mgr.*' -delete 2>/dev/null || true
  find "${CONF_DIR}" -maxdepth 1 -type f -name '.transit-mgr.*' -delete 2>/dev/null || true
  # 清理 mktemp 生成的文件
  find "${TEMP_DIR}" -maxdepth 1 -type f -name '.transit-mgr.*' -delete 2>/dev/null || true
}

# 信号处理器：清理后以 130 退出（SIGINT 的标准退出码）
_transit_signal_handler(){
  local sig="$1"
  echo -e "\n${RED}[${sig}] 安装已中断，清理临时文件..." >&2
  _transit_cleanup
  echo -e "${RED}[中断] 如需清理残留，请执行: bash $0 --uninstall${NC}" >&2
  exit 130
}

# 先注册 EXIT（确保清理总执行），再注册 INT/TERM
trap '_transit_cleanup' EXIT
trap '_transit_signal_handler INT' INT
trap '_transit_signal_handler TERM' TERM


# ============================================================
# --doctor 预检模式：检查环境是否满足安装条件（不修改任何内容）
# ============================================================
_doctor(){
  echo -e "${BOLD}${CYAN}══ 中转机环境预检 ════════════════════════════════════════════${NC}"
  echo ""

  _check_deps(){
    local bin pkg missing=""
    local _deps=(
      "curl:curl" "wget:wget" "iptables:iptables" "python3:python3"
      "ip:iproute2" "nginx:nginx" "fuser:psmisc" "ss:ss" "crontab:cron"
    )
    for d in "${_deps[@]}"; do
      bin="${d%%:*}"; pkg="${d##*:}"
      if ! command -v "$bin" &>/dev/null; then
        echo -e "  ${RED}[缺失]${NC}  $bin (包: $pkg)"
        missing=1
      else
        echo -e "  ${GREEN}[  OK ]${NC}  $bin"
      fi
    done
    [[ -z "$missing" ]] && return 0 || return 1
  }

  _check_kernel(){
    echo ""
    echo -e "  ${BOLD}内核参数检查：${NC}"
    local _current issues=0

    _current=$(sysctl -n net.ipv4.tcp_fastopen 2>/dev/null || echo 0)
    [[ "$_current" == "3" ]]       && echo -e "    tcp_fastopen:    ${GREEN}${_current} ✓${NC}"       || { echo -e "    tcp_fastopen:    ${YELLOW}${_current} (推荐: 3)${NC}"; ((++issues)); }

    _current=$(sysctl -n net.ipv4.tcp_timestamps 2>/dev/null || echo 0)
    [[ "$_current" == "1" ]]       && echo -e "    tcp_timestamps:  ${GREEN}${_current} ✓${NC}"       || { echo -e "    tcp_timestamps:  ${YELLOW}${_current} (推荐: 1)${NC}"; ((++issues)); }

    _current=$(sysctl -n net.ipv4.tcp_tw_reuse 2>/dev/null || echo 0)
    [[ "$_current" == "1" ]]       && echo -e "    tcp_tw_reuse:   ${GREEN}${_current} ✓${NC}"       || { echo -e "    tcp_tw_reuse:   ${YELLOW}${_current} (推荐: 1)${NC}"; ((++issues)); }

    _current=$(sysctl -n net.core.somaxconn 2>/dev/null || echo 0)
    (( _current >= 4096 ))       && echo -e "    somaxconn:      ${GREEN}${_current} ✓${NC}"       || { echo -e "    somaxconn:      ${YELLOW}${_current} (推荐: ≥4096)${NC}"; ((++issues)); }

    _current=$(sysctl -n fs.nr_open 2>/dev/null || echo 0)
    (( _current >= 524288 ))       && echo -e "    fs.nr_open:     ${GREEN}${_current} ✓${NC}"       || { echo -e "    fs.nr_open:     ${YELLOW}${_current} (推荐: ≥524288)${NC}"; ((++issues)); }

    return $issues
  }

  _check_ports(){
    echo ""
    echo -e "  ${BOLD}端口可用性检查（无侵入）：${NC}"
    local ssh_port=""
    ssh_port=$(ss -tlnp 2>/dev/null | awk '/sshd/{for(i=1;i<=NF;i++) if($i~/:[0-9]+$/){sub(/^.*:/,"",$i);print $i;exit}}' | head -1 || true)
    [[ -z "$ssh_port" ]] && ssh_port=$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}' || true)
    if [[ "$ssh_port" =~ ^[0-9]+$ ]]; then
      echo -e "    SSH 端口:        ${GREEN}${ssh_port} (已检测)${NC}"
    else
      echo -e "    SSH 端口:        ${YELLOW}无法自动检测${NC}"
    fi

    if ss -tlnp 2>/dev/null | grep -q ':443 '; then
      echo -e "    中转监听 443:   ${RED}已被占用！${NC}"
      ss -tlnp 2>/dev/null | grep ':443 ' | head-3 | sed 's/^/      /'
    else
      echo -e "    中转监听 443:   ${GREEN}可用 ✓${NC}"
    fi

    if ss -tlnp 2>/dev/null | grep -q ':45231 '; then
      echo -e "    回退端口 45231: ${YELLOW}已被占用${NC}"
    else
      echo -e "    回退端口 45231: ${GREEN}可用 ✓${NC}"
    fi
  }

  _check_network(){
    echo ""
    echo -e "  ${BOLD}网络连通性检查：${NC}"
    local src=""
    for src in "api.ipify.org" "ifconfig.me" "api.github.com"; do
      if curl -4 -fsSL --connect-timeout 5 --max-time 10 "https://${src}" -o /dev/null 2>/dev/null; then
        echo -e "    HTTPS → ${src}:  ${GREEN}可达 ✓${NC}"
      else
        echo -e "    HTTPS → ${src}:  ${RED}不可达 ✗${NC}"
      fi
    done

    if [[ -f /proc/net/if_inet6 ]]; then
      local ipv6_disabled
      ipv6_disabled=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 1)
      if [[ "$ipv6_disabled" == "0" ]]; then
        echo -e "    IPv6 路由:       ${GREEN}已启用 ✓${NC}"
      else
        echo -e "    IPv6 路由:       ${YELLOW}已禁用（仅 IPv4）${NC}"
      fi
    fi
  }

  _check_nginx_stream(){
    echo ""
    echo -e "  ${BOLD}Nginx Stream 模块检查：${NC}"
    if nginx -V 2>&1 | grep -qE 'with-stream'; then
      echo -e "    Stream 模块:     ${GREEN}已安装 ✓${NC}"
    else
      echo -e "    Stream 模块:     ${RED}未安装 ✗${NC}"
    fi
    if dpkg -l libnginx-mod-stream 2>/dev/null | grep -q '^ii'; then
      echo -e "    libnginx-mod-stream: ${GREEN}已安装 ✓${NC}"
    else
      echo -e "    libnginx-mod-stream: ${RED}未安装 ✗${NC}"
    fi
  }

  _check_resources(){
    echo ""
    echo -e "  ${BOLD}系统资源检查：${NC}"
    local ram_mb disk_mb fd_max
    ram_mb=$(free -m 2>/dev/null | awk '/Mem:/{print $2}') || ram_mb=0
    disk_mb=$(df -m / 2>/dev/null | awk 'NR==2{print $4}') || disk_mb=0
    fd_max=$(ulimit -n 2>/dev/null) || fd_max=0

    (( ram_mb >= 512 ))       && echo -e "    内存:           ${GREEN}${ram_mb} MB ✓${NC}"       || echo -e "    内存:           ${YELLOW}${ram_mb} MB (推荐 ≥512MB)${NC}"

    (( disk_mb >= 2048 ))       && echo -e "    磁盘 / 可用:   ${GREEN}${disk_mb} MB ✓${NC}"       || echo -e "    磁盘 / 可用:   ${RED}${disk_mb} MB (推荐 ≥2GB)${NC}"

    (( fd_max >= 524288 ))       && echo -e "    fd 最大值:      ${GREEN}${fd_max} ✓${NC}"       || echo -e "    fd 最大值:      ${YELLOW}${fd_max} (推荐 ≥524288)${NC}"
  }

  _check_systemd(){
    echo ""
    echo -e "  ${BOLD}systemd 检查：${NC}"
    if command -v systemctl &>/dev/null && systemctl --version &>/dev/null; then
      echo -e "    systemd:         ${GREEN}可用 ✓${NC}"
    else
      echo -e "    systemd:         ${RED}不可用 ✗${NC}"
    fi
  }

  _check_tmp(){
    echo ""
    echo -e "  ${BOLD}临时文件写入测试：${NC}"
    local _t
    _t=$(mktemp /tmp/transit-doctor-test.XXXX 2>/dev/null) && rm -f "$_t"       && echo -e "    /tmp 写入:      ${GREEN}正常 ✓${NC}"       || echo -e "    /tmp 写入:      ${RED}失败 ✗${NC}"
    mkdir -p "${MANAGER_BASE}/tmp" 2>/dev/null
    _t=$(mktemp "${MANAGER_BASE}/tmp/transit-doctor-test.XXXX" 2>/dev/null) && rm -f "$_t"       && echo -e "    MANAGER_BASE/tmp: ${GREEN}正常 ✓${NC}"       || echo -e "    MANAGER_BASE/tmp: ${RED}失败 ✗${NC}"
  }

  local _issues=0 _total=0

  echo -e "  ${BOLD}① 依赖检查${NC}"
  _check_deps; ((++_total)) || ((++_issues))

  echo -e ""
  echo -e "  ${BOLD}② 内核参数${NC}"
  _check_kernel; ((++_total)) || ((++_issues))

  echo -e ""
  echo -e "  ${BOLD}③ 端口可用性${NC}"
  _check_ports; ((++_total)) || ((++_issues))

  echo -e ""
  echo -e "  ${BOLD}④ 网络连通性${NC}"
  _check_network; ((++_total)) || ((++_issues))

  echo -e ""
  echo -e "  ${BOLD}⑤ Nginx Stream${NC}"
  _check_nginx_stream; ((++_total)) || ((++_issues))

  echo -e ""
  echo -e "  ${BOLD}⑥ 系统资源${NC}"
  _check_resources; ((++_total)) || ((++_issues))

  echo -e ""
  echo -e "  ${BOLD}⑦ systemd${NC}"
  _check_systemd; ((++_total)) || ((++_issues))

  echo -e ""
  echo -e "  ${BOLD}⑧ 临时文件${NC}"
  _check_tmp; ((++_total)) || ((++_issues))

  echo ""
  echo -e "${BOLD}══════════════════════════════════════════════════════════════════${NC}"
  if (( _issues == 0 )); then
    echo -e "  ${GREEN}✓ 环境检查通过（$_total/$_total 项）${NC}"
    echo -e "${BOLD}══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    return 0
  else
    echo -e "  ${RED}✗ 发现 $_issues 项问题（建议修复后再安装）${NC}"
    echo -e "${BOLD}══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    return 1
  fi
}


# mktemp 带超时保护，防止 /tmp 满时死锁
# 返回：唯一的临时文件路径（已通过 touch 验证存在）
_mktemp(){
  local prefix="$1"
  local timeout_secs="${2:-5}"
  local dir="${3:-${TEMP_DIR}}"
  mkdir -p "$dir"

  # 生成随机后缀
  local random_suffix
  random_suffix=$(LC_ALL=C tr -dc 'a-zA-Z0-9' </dev/urandom 2>/dev/null | head -c 8)
  [[ -z "$random_suffix" ]] && random_suffix="$$_$(date +%N)"

  local tmp_file="${dir}/.transit-mgr.${prefix}.${random_suffix}"

  # 优先用 touch 原子创建（即使 /tmp 满也只是失败不会卡住）
  if touch "$tmp_file" 2>/dev/null; then
    printf '%s' "$tmp_file"
    return 0
  fi

  # 回退：带超时的 mktemp
  local oldopts="$-"
  set +e
  local result mkt_status=1
  result=$( timeout "$timeout_secs" mktemp "${dir}/.transit-mgr.${prefix}.XXXXXX" 2>/dev/null ) && mkt_status=0 || mkt_status=$?
  set -"$oldopts"

  if (( mkt_status == 0 )) && [[ -n "$result" && -f "$result" ]]; then
    printf '%s' "$result"
    return 0
  fi

  # [Bugfix v3.10] 移除了可预测的纳秒时间戳 fallback
  # 如果 touch + mktemp 均失败，应该报错而不是创建可预测路径
  echo "_mktemp: 所有原子创建方式均失败（/tmp 可能已满或权限异常）" >&2
  return 1
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

# 原子写入：cat stdin → 临时文件 → mv 原子替换目标
# 正确处理：mktemp 失败时使用 date fallback；mv 失败时清理临时文件
atomic_write(){
  local target="$1" mode="${2:-644}" owner_group="${3:-root:root}"
  local dir tmp

  [[ -z "$target" ]] && { echo "atomic_write: target 不能为空" >&2; return 1; }
  dir="$(dirname "$target")"
  mkdir -p "$dir"

  # _mktemp 总是返回已验证存在的唯一路径
  tmp="$(_mktemp "atomic" 3 "$dir")"

  # stdin → 临时文件
  if ! cat >"$tmp" 2>/dev/null; then
    rm -f "$tmp" 2>/dev/null
    echo "atomic_write: 无法写入临时文件 $tmp" >&2
    return 1
  fi

  chmod "$mode" "$tmp" 2>/dev/null || true
  chown "$owner_group" "$tmp" 2>/dev/null || true

  # mv 是原子操作（同一文件系统内保证原子性）
  if ! mv -f "$tmp" "$target" 2>/dev/null; then
    rm -f "$tmp" 2>/dev/null
    echo "atomic_write: 无法 mv $tmp → $target" >&2
    return 1
  fi
  return 0
}

# 全局写锁：flock 防止并发修改配置
_acquire_lock(){
  mkdir -p "$TEMP_DIR"
  if ! exec 200>"${TEMP_DIR}/transit-manager.lock" 2>/dev/null; then
    warn "无法获取锁文件描述符"
    return 1
  fi
  if ! flock -w 10 200; then
    die "配置正在被其他进程修改，请稍后重试（等待超时 10s）"
  fi
}
_release_lock(){
  flock -u 200 2>/dev/null || true
  exec 200>&- 2>/dev/null || true
}

# [Bugfix v3.1] have_ipv6: 修正拼写错误 net.ipv6.conf.all.disable_ipv6
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
    ipaddress.IPv4Address(sys.argv[1].strip())
except ValueError:
    raise SystemExit(1)
PY
}

validate_ip(){
  local ip="$1"
  [[ "$ip" =~ : ]] && die "拓扑冲突：中转机无 IPv6 路由时严禁使用 IPv6 落地机地址: $ip"
  python3 - "$ip" <<'PYEOF' || die "IP 地址属于保留/特殊范围，禁止使用: $ip"
import ipaddress, sys
ip = sys.argv[1]
try:
    a = ipaddress.IPv4Address(ip)
    if a.is_loopback or a.is_private or a.is_link_local or a.is_multicast or a.is_reserved or a.is_unspecified:
        sys.exit(1)
except:
    sys.exit(1)
PYEOF
  validate_ipv4 "$ip"
}

validate_port(){
  local p="$1"
  [[ "$p" =~ ^[0-9]+$ ]] || die "端口格式非法: $p"
  (( p >= 1 && p <= 65535 )) || die "端口超范围（1-65535）: $p"
}

domain_to_safe(){
  local raw dhash
  raw="$(printf '%s' "$1" | tr '.' '_' | tr -cd 'a-zA-Z0-9_-')"
  dhash="$(printf '%s' "$1" | sha256sum | cut -c1-8)"
  printf '%s_%s' "${raw:0:40}" "$dhash"
}

nginx_domain_str(){ printf '%s' "$1" | tr -cd 'a-zA-Z0-9._-'; }
nginx_ip_str(){ printf '%s' "$1" | tr -cd 'a-zA-Z0-9.'; }

read_meta_ip(){
  awk -F= '/^(TRANSIT_IP|IP)=/{print $2; exit}' "$1"
}

get_public_ip(){
  [[ -n "${TRANSIT_PUBLIC_IP:-}" ]] && { validate_ip "$TRANSIT_PUBLIC_IP"; printf "%s" "$TRANSIT_PUBLIC_IP"; return 0; }

  local _ip="" _src
  for _src in \
      "https://api.ipify.org" \
      "https://ifconfig.me" \
      "https://ipecho.net/plain" \
      "https://checkip.amazonaws.com"; do
    _ip=$(curl -4 -fsSL --connect-timeout 5 --max-time 10 "$_src" 2>/dev/null | tr -d '[:space:]') \
      && [[ -n "$_ip" ]] && break || true
  done

  if [[ -z "$_ip" ]]; then
    die "无法获取中转机公网 IPv4，请检查网络或手动指定: TRANSIT_PUBLIC_IP=x.x.x.x"
  fi
  validate_ip "$_ip"
  printf '%s' "$_ip"
}

show_help(){
  cat <<HELP
用法: bash install_transit_v3.1.sh [选项]
  （无参数）        交互式安装或管理菜单
  --doctor          环境预检（不修改任何内容）
  --uninstall       清除本脚本所有内容（不影响 mack-a）
  --import <token>  从落地机 Base64 token 自动导入路由规则
  --status          显示当前状态
  --help            显示此帮助
HELP
}

check_deps(){
  export DEBIAN_FRONTEND=noninteractive
  local _bin_pkg=(
    curl:curl wget:wget iptables:iptables python3:python3
    ip:iproute2 nginx:nginx fuser:psmisc crontab:cron
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
        ((_lw>60)) && die "apt 锁等待超时（另一个 apt 进程正在运行），请稍后重试"
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
  local bbr_conf="/etc/sysctl.d/99-transit-bbr.conf"

  info "优化内核并发参数..."

  local _ram_mb; _ram_mb=$(free -m 2>/dev/null | awk '/Mem:/{print $2}') || _ram_mb=1024
  local _tw_max=$(( _ram_mb * 100 ))
  (( _tw_max < 10000 ))  && _tw_max=10000
  (( _tw_max > 250000 )) && _tw_max=250000

  local _fd_max=$(( _ram_mb * 800 ))
  (( _fd_max < 524288 ))   && _fd_max=524288
  (( _fd_max > 1048576 )) && _fd_max=1048576

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
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
BBRCF

  echo "options nf_conntrack hashsize=262144" > /etc/modprobe.d/nf_conntrack.conf 2>/dev/null || true
  modprobe nf_conntrack 2>/dev/null || true

  sysctl --system &>/dev/null || true

  # [v3.9 增强] TFO 内核支持验证（防止静默失败）
  if ! sysctl -w net.ipv4.tcp_fastopen=3 &>/dev/null; then
    warn "内核不支持 TFO（或被内核命令行禁用），fastopen=256 指令将被 nginx 忽略"
  fi
  success "内核网络参数已优化"
}

install_nginx(){
  if command -v nginx &>/dev/null; then
    if nginx -V 2>&1 | grep -qE 'with-stream' \
        && dpkg -l libnginx-mod-stream 2>/dev/null | grep -q '^ii'; then
      success "Nginx 已安装且 stream 模块可用"
    else
      info "补充安装 libnginx-mod-stream..."
      export DEBIAN_FRONTEND=noninteractive
      apt-get install -y libnginx-mod-stream 2>/dev/null \
        || warn "libnginx-mod-stream 安装失败"
    fi
  else
    info "安装 Nginx（含 stream 模块）..."
    export DEBIAN_FRONTEND=noninteractive
    if command -v apt-get &>/dev/null; then
      apt-get update -qq
      apt-get install -y nginx-common libnginx-mod-stream nginx 2>/dev/null \
        || apt-get install -y nginx \
        || die "Nginx 安装失败"
    elif command -v yum &>/dev/null; then
      yum install -y epel-release 2>/dev/null || true
      yum makecache 2>/dev/null || true
      yum install -y nginx nginx-mod-stream 2>/dev/null \
        || yum install -y nginx \
        || die "Nginx 安装失败"
    else
      die "不支持的包管理器"
    fi
  fi

  nginx -V 2>&1 | grep -qE 'with-stream' \
    || die "安装的 Nginx 不含 stream 支持"

  _tune_nginx_worker_connections
  success "Nginx 安装完成"
}

_tune_nginx_worker_connections(){
  local mc="$NGINX_MAIN_CONF"

  # [Bugfix v3.1] 用 mktemp 创建备份，如果失败则跳过调优（不阻断）
  local _mc_bak; _mc_bak="$(mktemp /tmp/nginx-conf-backup.XXXXXX.conf 2>/dev/null)" && cp -a "$mc" "$_mc_bak" 2>/dev/null || { _mc_bak=""; }

  local _tune_ram_mb; _tune_ram_mb=$(free -m 2>/dev/null | awk '/Mem:/{print $2}') || _tune_ram_mb=1024
  local _tune_fd=$(( _tune_ram_mb * 800 ))
  (( _tune_fd < 524288 ))   && _tune_fd=524288
  (( _tune_fd > 1048576 )) && _tune_fd=1048576

  local _wc_ram; _wc_ram=$(free -m 2>/dev/null | awk '/Mem:/{print int($2/2*1000)}') || _wc_ram=100000
  (( _wc_ram < 10000 )) && _wc_ram=10000
  (( _wc_ram > 200000 )) && _wc_ram=200000

  # 只修改必要指令，保持原有配置不变
  if ! grep -qE "^\s*worker_connections\s+${_wc_ram}\s*;" "$mc" 2>/dev/null; then
    if grep -qE '^\s*worker_connections' "$mc" 2>/dev/null; then
      sed -i "s/^\s*worker_connections\s\+[0-9]\+;/    worker_connections ${_wc_ram};/" "$mc"
    else
      sed -i "/^events\s*{/a\    worker_connections ${_wc_ram};" "$mc"
    fi
  fi

  if ! grep -qE "^\s*worker_rlimit_nofile\s+${_tune_fd}\s*;" "$mc" 2>/dev/null; then
    if grep -qE '^\s*worker_rlimit_nofile' "$mc" 2>/dev/null; then
      sed -i "s/^.*worker_rlimit_nofile.*/worker_rlimit_nofile ${_tune_fd};/" "$mc"
    else
      sed -i "/^events\s*{/i\\worker_rlimit_nofile ${_tune_fd};" "$mc"
    fi
  fi

  if ! nginx -t 2>/dev/null; then
    warn "nginx.conf tuning validation failed — restoring snapshot"
    [[ -n "$_mc_bak" && -f "$_mc_bak" ]] && cp -f "$_mc_bak" "$mc" 2>/dev/null || true
    rm -f "$_mc_bak" 2>/dev/null || true
    die "nginx.conf 配置验证失败，原始配置已还原"
  fi

  rm -f "$_mc_bak" 2>/dev/null || true

  local override_dir="/etc/systemd/system/nginx.service.d"
  mkdir -p "$override_dir"
  atomic_write "${override_dir}/transit-manager-override.conf" 644 root:root <<SVCOV
[Unit]
StartLimitIntervalSec=600
StartLimitBurst=10

[Service]
LimitNOFILE=${_tune_fd}
TasksMax=infinity
StandardOutput=null
StandardError=null
SVCOV

  systemctl daemon-reload 2>/dev/null || true
  if systemctl is-active --quiet nginx 2>/dev/null; then
    systemctl reload nginx 2>/dev/null || warn "Nginx reload 失败"
  fi
  success "Nginx worker_connections/worker_rlimit_nofile 已优化"
}

setup_fallback_decoy_transit(){
  local fallback_conf="/etc/nginx/conf.d/transit-fallback.conf"

  if fuser -n tcp 45231 2>/dev/null; then
    die "端口 45231 已被占用"
  fi

  local need_ipv6=0; have_ipv6 && need_ipv6=1
  local ipv6_listen=""
  (( need_ipv6 )) && ipv6_listen="    listen [::1]:45231 ssl; ssl_reject_handshake on;"
    local ipv6_listen_directive=""
    (( need_ipv6 )) && ipv6_listen_directive="    listen [::]:${LISTEN_PORT} fastopen=256 so_keepalive=3m:10s:3 backlog=65535;"

  rm -f "/etc/nginx/conf.d/transit-tls-reject.conf" 2>/dev/null || true

  atomic_write "$fallback_conf" 644 root:root <<FDEOF
limit_conn_zone \$binary_remote_addr zone=transit_fb_conn:10m;
limit_req_zone  \$binary_remote_addr zone=transit_fb_req:10m rate=10r/s;
server {
    listen 127.0.0.1:45231 ssl; ssl_reject_handshake on;
${ipv6_listen}
    server_name _;
    server_tokens off;
    limit_conn transit_fb_conn 4;
    limit_req  zone=transit_fb_req burst=50 nodelay;
    error_page 400 503 = @silent_close;
    location @silent_close { return 444; }
    location / { return 444; }
    access_log off;
    error_log /dev/null;
}
FDEOF

  nginx -t 2>&1 || die "transit fallback 配置验证失败"

  # 立即 reload，使 fallback 配置生效
  if systemctl is-active --quiet nginx 2>/dev/null; then
    systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null || true
  fi
  success "fallback 防探针站已就绪"
}

write_logrotate(){
  mkdir -p "$LOG_DIR"
  atomic_write "$LOGROTATE_FILE" 644 root:root <<EOF
${LOG_DIR}/*.log
{
    su root adm
    daily
    maxsize 100M
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
    create 0640 root adm
    sharedscripts
    postrotate
        nginx -s reopen >/dev/null 2>&1 || true \
          || nginx -s reopen >/dev/null 2>&1 || true
    endscript
}
EOF

  local _jd_conf="/etc/systemd/journald.conf.d/transit-manager.conf"
  mkdir -p "/etc/systemd/journald.conf.d"
  atomic_write "$_jd_conf" 644 root:root <<'JDEOF'
[Journal]
SystemMaxUse=200M
RuntimeMaxUse=50M
JDEOF

  success "logrotate 已配置"
}

init_nginx_stream(){
  mkdir -p "$LOG_DIR" "$SNIPPETS_DIR" "$CONF_DIR"
  chmod 700 "$SNIPPETS_DIR"

  echo "    dummy.invalid  17.253.144.10:443;" > "${SNIPPETS_DIR}/landing_dummy.map"

  if grep -q "$STREAM_INCLUDE_MARKER" "$NGINX_MAIN_CONF" 2>/dev/null; then
    info "Nginx stream include 已存在"; return 0
  fi

  if grep -qE '^\s*stream\s*\{' "$NGINX_MAIN_CONF" 2>/dev/null; then
    die "nginx.conf 已存在 stream{} 块（非本脚本），请备份后手动删除"
  fi

  info "写入 Nginx stream 透传配置 ..."

  local _stream_ram_mb; _stream_ram_mb=$(free -m 2>/dev/null | awk '/Mem:/{print $2}') || _stream_ram_mb=1024
  local _stream_zone_mb=$(( _stream_ram_mb / 32 ))
  (( _stream_zone_mb < 5  )) && _stream_zone_mb=5
  (( _stream_zone_mb > 64 )) && _stream_zone_mb=64

  atomic_write "$NGINX_STREAM_CONF" 644 root:root <<NGINX_STREAM_EOF
stream {
    access_log off;
    error_log  ${LOG_DIR}/transit_stream_error.log emerg;

    limit_conn_zone \$binary_remote_addr zone=transit_stream_conn:${_stream_zone_mb}m;

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
${ipv6_listen_directive}
        ssl_preread on;
        preread_buffer_size 256k;
        preread_timeout        5s;
        proxy_pass             \$backend_upstream;
        proxy_connect_timeout  5s;
        proxy_timeout          315s;
        proxy_socket_keepalive on;
        tcp_nodelay            on;
        limit_conn transit_stream_conn 100;
    }
}
NGINX_STREAM_EOF

  # 安全追加 stream include 到 nginx.conf（先验证再替换）
  local _mc_tmp; _mc_tmp="$(_mktemp "nginx-conf" 3)"
  cp -f "$NGINX_MAIN_CONF" "$_mc_tmp"
  printf '\n# %s\ninclude %s;\n' "$STREAM_INCLUDE_MARKER" "$NGINX_STREAM_CONF" >> "$_mc_tmp"

  if ! nginx -t -c "$_mc_tmp" 2>/dev/null; then
    rm -f "$_mc_tmp" 2>/dev/null
    die "Nginx stream 配置验证失败"
  fi

  mv -f "$_mc_tmp" "$NGINX_MAIN_CONF" || die "nginx.conf 写入失败"

  if ! nginx -t 2>/dev/null; then
    die "Nginx 配置注入后验证失败"
  fi

  if systemctl is-active --quiet nginx 2>/dev/null; then
    systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null || true
  fi
  success "Nginx stream 配置写入完成"
}

generate_landing_snippet(){
  local domain="$1" ip="$2" port="${3:-443}"
  local safe; safe=$(domain_to_safe "$domain")
  [[ -n "$safe" ]] || die "域名 safe 转换后为空: ${domain}"
  (( ${#safe} > 64 )) && safe="${safe:0:64}"

  rm -f "${SNIPPETS_DIR}/landing_${safe}.upstream" 2>/dev/null || true
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
  mkdir -p "$LOG_DIR"
  info "验证 Nginx 配置 ..."
  nginx -t 2>&1 || die "Nginx 配置验证失败"
  info "热重载 Nginx ..."

  # 尝试按优先级 reload：systemctl → nginx -s reload → nginx start
  local _reloaded=0
  if systemctl is-active --quiet nginx 2>/dev/null; then
    # nginx 由 systemd 管理，优先用 systemctl
    if systemctl reload nginx 2>/dev/null; then
      _reloaded=1
    elif nginx -s reload 2>/dev/null; then
      _reloaded=1
    fi
  else
    # nginx 非 systemd 管理（或未运行）
    if nginx -s reload 2>/dev/null; then
      _reloaded=1
    elif pgrep -x nginx >/dev/null 2>&1; then
      # nginx 在运行但 reload 失败，尝试 restart
      if systemctl restart nginx 2>/dev/null; then
        _reloaded=1
      fi
    else
      # nginx 未运行
      if nginx 2>/dev/null; then
        _reloaded=1
      fi
    fi
  fi

  if (( _reloaded )); then
    sleep 1
    success "Nginx 热重载成功"
  else
    warn "Nginx 热重载失败，请手动检查: systemctl status nginx"
  fi
}

_purge_chain_atomic(){
  local chain="${1}" v="${2:-4}"
  local cmd="${v}tables"
  $cmd-save 2>/dev/null | grep -v "${chain}" | $cmd-restore --noflush 2>/dev/null || true
}

setup_firewall_transit(){
  local ssh_port; ssh_port="$(detect_ssh_port)"
  info "配置防火墙 chain ${FW_CHAIN} ..."

  local FW_TMP="${FW_CHAIN}-NEW"
  local FW_TMP6="${FW_CHAIN6}-NEW"

  _bulldoze_input_refs_t(){
    local _chain="$1" _num
    while true; do
      _num=$(iptables -L INPUT --line-numbers -n 2>/dev/null \
             | awk -v c="$_chain" 'NR>2 && $2==c {print $1; exit}')
      [[ -n "$_num" ]] || break
      iptables -w -D INPUT "$_num" 2>/dev/null || break
    done
  }
  _bulldoze_input_refs6_t(){
    local _chain="$1" _num
    while true; do
      _num=$(ip6tables -L INPUT --line-numbers -n 2>/dev/null \
             | awk -v c="$_chain" 'NR>2 && $2==c {print $1; exit}')
      [[ -n "$_num" ]] || break
      ip6tables -w -D INPUT "$_num" 2>/dev/null || break
    done
  }

  _bulldoze_input_refs_t "$FW_CHAIN";  _bulldoze_input_refs_t "$FW_TMP"
  iptables -w -F "$FW_TMP"   2>/dev/null || true; iptables -X "$FW_TMP"   2>/dev/null || true
  iptables -w -F "$FW_CHAIN" 2>/dev/null || true; iptables -X "$FW_CHAIN" 2>/dev/null || true

  if have_ipv6; then
    _bulldoze_input_refs6_t "$FW_CHAIN6"; _bulldoze_input_refs6_t "$FW_TMP6"
    ip6tables -w -F "$FW_TMP6"   2>/dev/null || true; ip6tables -X "$FW_TMP6"   2>/dev/null || true
    ip6tables -w -F "$FW_CHAIN6" 2>/dev/null || true; ip6tables -X "$FW_CHAIN6" 2>/dev/null || true
  fi

  iptables -w -N "$FW_TMP" 2>/dev/null || iptables -F "$FW_TMP"
  iptables -w -A "$FW_TMP" -i lo                                       -j ACCEPT
  iptables -w -A "$FW_TMP" -p tcp  --dport "$ssh_port"                 -j ACCEPT
  iptables -w -A "$FW_TMP" -m conntrack --ctstate INVALID,UNTRACKED    -j DROP
  iptables -w -A "$FW_TMP" -m conntrack --ctstate ESTABLISHED,RELATED  -j ACCEPT
  iptables -w -A "$FW_TMP" -p icmp --icmp-type echo-request -m limit --limit 10/second --limit-burst 20 -j ACCEPT
  iptables -w -A "$FW_TMP" -p icmp --icmp-type echo-request            -j DROP
  iptables -w -A "$FW_TMP" -p tcp  --dport "$LISTEN_PORT" \
    -m connlimit --connlimit-above 2000 --connlimit-mask 24        -j DROP
  iptables -w -A "$FW_TMP" -p tcp  --dport "$LISTEN_PORT" \
    -m connlimit --connlimit-above 20000 --connlimit-mask 0        -j DROP
  iptables -w -A "$FW_TMP" -p tcp  --dport "$LISTEN_PORT" \
    -m hashlimit --hashlimit-upto 8000/sec --hashlimit-burst 9999 --hashlimit-mode srcip --hashlimit-name transit_443_limit -j ACCEPT
  iptables -w -A "$FW_TMP" -p tcp  --dport "$LISTEN_PORT"            -j DROP
  iptables -w -A "$FW_TMP"                                              -j DROP

  iptables -w -I INPUT 1 -m comment --comment "transit-manager-swap" -j "$FW_TMP"
  _bulldoze_input_refs_t "$FW_CHAIN"
  iptables -w -F "$FW_CHAIN" 2>/dev/null || true; iptables -X "$FW_CHAIN" 2>/dev/null || true
  iptables -E "$FW_TMP" "$FW_CHAIN"
  iptables -w -I INPUT 1 -m comment --comment "transit-manager-rule" -j "$FW_CHAIN"
  while iptables -D INPUT -m comment --comment "transit-manager-swap" 2>/dev/null; do :; done

  if have_ipv6; then
    ip6tables -w -N "$FW_TMP6" 2>/dev/null || ip6tables -F "$FW_TMP6"
    ip6tables -w -A "$FW_TMP6" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ip6tables -w -A "$FW_TMP6" -i lo -j ACCEPT
    ip6tables -w -A "$FW_TMP6" -p tcp      --dport "$ssh_port"    -j ACCEPT
    ip6tables -w -A "$FW_TMP6" -p ipv6-icmp                        -j ACCEPT
    ip6tables -w -A "$FW_TMP6" -p tcp --dport "$LISTEN_PORT" \
      -m connlimit --connlimit-above 2000 --connlimit-mask 64  -j DROP
    ip6tables -w -A "$FW_TMP6" -p tcp --dport "$LISTEN_PORT" \
      -m connlimit --connlimit-above 20000 --connlimit-mask 0  -j DROP
    ip6tables -w -A "$FW_TMP6" -p tcp --dport "$LISTEN_PORT" \
      -m hashlimit --hashlimit-upto 8000/sec --hashlimit-burst 9999 --hashlimit-mode srcip --hashlimit-name transit_443_limit -j ACCEPT
    ip6tables -w -A "$FW_TMP6" -p tcp --dport "$LISTEN_PORT"      -j DROP
    ip6tables -w -A "$FW_TMP6" -j DROP
    ip6tables -w -I INPUT 1 -m comment --comment "transit-manager-v6-swap" -j "$FW_TMP6"
    _bulldoze_input_refs6_t "$FW_CHAIN6"
    ip6tables -w -F "$FW_CHAIN6" 2>/dev/null || true; ip6tables -X "$FW_CHAIN6" 2>/dev/null || true
    ip6tables -E "$FW_TMP6" "$FW_CHAIN6"
    ip6tables -w -I INPUT 1 -m comment --comment "transit-manager-v6-jump" -j "$FW_CHAIN6"
    while ip6tables -D INPUT -m comment --comment "transit-manager-v6-swap" 2>/dev/null; do :; done
  fi

  _persist_iptables "$ssh_port"
  success "防火墙配置完成（SSH:${ssh_port} + 443 + ICMP）"
}

_persist_iptables(){
  local ssh_port="${1:-22}"
  mkdir -p "$MANAGER_BASE"
  local fw_script="${MANAGER_BASE}/firewall-restore.sh"

  atomic_write "$fw_script" 700 root:root <<FWEOF
#!/bin/sh
# TRANSIT_FW_VERSION=${VERSION}_\$(date +%Y%m%d)
# [Bugfix v3.19] SSH 端口在脚本生成时硬编码
# 注意: network-pre.target 阶段 sshd 未启动，动态检测必失败
# 如需更改 SSH 端口，请重新运行 install_transit_v3.1.sh
SSH_PORT="${ssh_port}"
while iptables  -D INPUT -m comment --comment "transit-manager-rule" 2>/dev/null; do :; done
while iptables  -D INPUT -m comment --comment "transit-manager-swap" 2>/dev/null; do :; done
iptables -w -F ${FW_CHAIN}  2>/dev/null || true; iptables -X ${FW_CHAIN}  2>/dev/null || true
iptables -w -N ${FW_CHAIN}  2>/dev/null || true
iptables -w -A ${FW_CHAIN} -i lo                                       -j ACCEPT
iptables -w -A ${FW_CHAIN} -p tcp  --dport \${SSH_PORT}                -j ACCEPT
iptables -w -A ${FW_CHAIN} -m conntrack --ctstate INVALID,UNTRACKED    -j DROP
iptables -w -A ${FW_CHAIN} -m conntrack --ctstate ESTABLISHED,RELATED  -j ACCEPT
iptables -w -A ${FW_CHAIN} -p icmp --icmp-type echo-request -m limit --limit 10/second --limit-burst 20 -j ACCEPT
iptables -w -A ${FW_CHAIN} -p icmp --icmp-type echo-request            -j DROP
iptables -w -A ${FW_CHAIN} -p tcp  --dport ${LISTEN_PORT} -m connlimit --connlimit-above 2000 --connlimit-mask 24 -j DROP
iptables -w -A ${FW_CHAIN} -p tcp  --dport ${LISTEN_PORT} -m connlimit --connlimit-above 20000 --connlimit-mask 0  -j DROP
iptables -w -A ${FW_CHAIN} -p tcp  --dport ${LISTEN_PORT} -m hashlimit --hashlimit-upto 8000/sec --hashlimit-burst 9999 --hashlimit-mode srcip --hashlimit-name transit_443_limit -j ACCEPT
iptables -w -A ${FW_CHAIN} -p tcp  --dport ${LISTEN_PORT}                                                        -j DROP
iptables -w -A ${FW_CHAIN}                                              -j DROP
iptables -w -I INPUT 1 -m comment --comment "transit-manager-rule" -j ${FW_CHAIN}
if [ -f /proc/net/if_inet6 ] && ip6tables -L >/dev/null 2>&1 && [ "\$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 1)" != "1" ]; then
  while ip6tables -D INPUT -m comment --comment "transit-manager-v6-jump" 2>/dev/null; do :; done
  while ip6tables -D INPUT -m comment --comment "transit-manager-v6-swap" 2>/dev/null; do :; done
  ip6tables -w -F ${FW_CHAIN6} 2>/dev/null || true; ip6tables -X ${FW_CHAIN6} 2>/dev/null || true
  ip6tables -w -N ${FW_CHAIN6} 2>/dev/null || true
  ip6tables -w -A ${FW_CHAIN6} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ip6tables -w -A ${FW_CHAIN6} -i lo -j ACCEPT
  ip6tables -w -A ${FW_CHAIN6} -p tcp      --dport \${SSH_PORT}      -j ACCEPT
  ip6tables -w -A ${FW_CHAIN6} -p ipv6-icmp                          -j ACCEPT
  ip6tables -w -A ${FW_CHAIN6} -p tcp --dport ${LISTEN_PORT} -m connlimit --connlimit-above 2000 --connlimit-mask 64 -j DROP
  ip6tables -w -A ${FW_CHAIN6} -p tcp --dport ${LISTEN_PORT} -m connlimit --connlimit-above 20000 --connlimit-mask 0  -j DROP
  ip6tables -w -A ${FW_CHAIN6} -p tcp --dport ${LISTEN_PORT} -m hashlimit --hashlimit-upto 8000/sec --hashlimit-burst 9999 --hashlimit-mode srcip --hashlimit-name transit_443_limit -j ACCEPT
  ip6tables -w -A ${FW_CHAIN6} -p tcp --dport ${LISTEN_PORT} -j DROP
  ip6tables -w -A ${FW_CHAIN6} -j DROP
  ip6tables -w -I INPUT 1 -m comment --comment "transit-manager-v6-jump" -j ${FW_CHAIN6}
fi
FWEOF

  local rsvc="/etc/systemd/system/transit-manager-iptables-restore.service"
  atomic_write "$rsvc" 644 root:root <<RSTO
[Unit]
Description=Restore iptables rules for transit-manager
DefaultDependencies=no
After=network-online.target netfilter-persistent.service
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=${fw_script}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
RSTO

  systemctl daemon-reload
  systemctl enable transit-manager-iptables-restore.service \
    || die "iptables 持久化服务 enable 失败"
  info "防火墙规则已写入: ${fw_script}"
}

save_landing_meta(){
  local domain="$1" ip="$2" port="${3:-443}" rollback_map="${4:-}"
  local safe; safe=$(domain_to_safe "$domain")
  mkdir -p "$CONF_DIR"

  if ! atomic_write "${CONF_DIR}/${safe}.meta" 600 root:root <<MEOF; then
DOMAIN=${domain}
TRANSIT_IP=${ip}
PORT=${port}
CREATED=$(date +%Y%m%d_%H%M%S)
MEOF
    [[ -n "$rollback_map" && -f "$rollback_map" ]] && mv -f "$rollback_map" "${SNIPPETS_DIR}/landing_${safe}.map" 2>/dev/null || true
    nginx -t 2>/dev/null && nginx -s reload 2>/dev/null || true
    die "meta 写入失败"
  fi
  rm -f "$rollback_map" 2>/dev/null || true
}

_atomic_apply_route(){
  local domain="$1" ip="$2" port="$3"
  local uuid="${4:-}" pwd="${5:-}" pfx="${6:-}"
  local safe; safe=$(domain_to_safe "$domain")
  [[ -n "$safe" ]] || die "域名 safe 转换后为空: ${domain}"
  (( ${#safe} > 64 )) && safe="${safe:0:64}"

  local map_target="${SNIPPETS_DIR}/landing_${safe}.map"
  local meta_target="${CONF_DIR}/${safe}.meta"

  mkdir -p "$SNIPPETS_DIR" "$CONF_DIR"

  # [Bugfix v3.1] 使用 _mktemp 直接创建，atomic_write 内部处理失败回退
  local tmp_map; tmp_map="$(_mktemp "atomic-map" 3)"
  local _map_key; _map_key=$(nginx_domain_str "$domain")
  [[ -n "$_map_key" && ${#_map_key} -le 200 ]] \
    || { rm -f "$tmp_map" 2>/dev/null; die "域名过滤后为空或超长: ${domain}"; }
  printf '    %s    %s:%s;\n' "$_map_key" "$(nginx_ip_str "$ip")" "$port" > "$tmp_map"
  chmod 600 "$tmp_map"

  if ! mv -f "$tmp_map" "$map_target" 2>/dev/null; then
    rm -f "$tmp_map" 2>/dev/null
    die "map 文件写入失败"
  fi
  chmod 600 "$map_target" 2>/dev/null || true

  if ! nginx -t 2>/dev/null; then
    rm -f "$map_target" 2>/dev/null || true
    die "Nginx 语法校验失败"
  fi

  local tmp_meta; tmp_meta="$(_mktemp "atomic-meta" 3)"
  printf 'DOMAIN=%s\nTRANSIT_IP=%s\nPORT=%s\nUUID=%s\nPWD=%s\nPFX=%s\nCREATED=%s\n' \
    "$domain" "$ip" "$port" "$uuid" "$pwd" "$pfx" "$(date +%Y%m%d_%H%M%S)" > "$tmp_meta"
  chmod 600 "$tmp_meta"

  if ! mv -f "$tmp_meta" "$meta_target" 2>/dev/null; then
    rm -f "$tmp_meta" "$map_target" 2>/dev/null || true
    die "meta 原子提交失败"
  fi
  chmod 600 "$meta_target" 2>/dev/null || true

  nginx_reload
  # [Bugfix v3.12] 删除节点后刷新防火墙，清除该 IP 的 ACCEPT 规则
  setup_firewall_transit
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

generate_nodes(){
  local transit_ip="${1:-}"
  [[ -z "$transit_ip" ]] && transit_ip=$(get_public_ip)

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

    # [Bugfix v3.7] 旧版 Token 没有 uuid/pwd/pfx 时仍生成简化订阅（不跳过）
    local sub_b64="" _sub_err=""
    if [[ -n "$uuid" && -n "$pwd" && -n "$pfx" ]]; then
      sub_b64=$(python3 -c "
import base64, urllib.parse, sys
transit_ip, domain, vless_uuid, trojan_pass, pfx = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
port = 443
lbl_vision = '[禁Mux]VLESS-Vision-'
lbl_vgrpc  = 'VLESS-gRPC-'
lbl_vws    = 'VLESS-WS-'
lbl_ttcp   = 'Trojan-TCP-'
uris = [
    (f'vless://{vless_uuid}@{transit_ip}:{port}?encryption=none&flow=xtls-rprx-vision&security=tls&sni={domain}&fp=chrome&type=tcp&mux=0#{urllib.parse.quote(lbl_vision+domain)}'),
    (f'vless://{vless_uuid}@{transit_ip}:{port}?encryption=none&security=tls&sni={domain}&fp=edge&type=grpc&serviceName={pfx}-vg&alpn=h2&mode=multi#{urllib.parse.quote(lbl_vgrpc+domain)}'),
    (f'vless://{vless_uuid}@{transit_ip}:{port}?encryption=none&security=tls&sni={domain}&fp=firefox&type=ws&path=%2F{pfx}-vw&host={domain}&alpn=http/1.1#{urllib.parse.quote(lbl_vws+domain)}'),
    (f'trojan://{urllib.parse.quote(trojan_pass)}@{transit_ip}:{port}?security=tls&sni={domain}&fp=safari&type=tcp#{urllib.parse.quote(lbl_ttcp+domain)}'),
]
print(base64.b64encode('\n'.join(uris).encode()).decode())
" "$transit_ip" "$dom" "$uuid" "$pwd" "$pfx" 2>&1) \
      || { _sub_err="$sub_b64"; sub_b64=""; }
    fi

    echo ""
    echo -e "${BOLD}${GREEN}── 节点订阅: ${dom} ──────────────────────────────────────────${NC}"

    if [[ -n "$sub_b64" ]]; then
      echo -e "  ${BOLD}Base64 订阅:${NC}"
      echo "  $sub_b64"
      echo -e "  ${RED}${BOLD}⚠  VLESS-Vision 节点【严禁开启 Mux】！${NC}"
    else
      warn "节点 ${dom} 订阅生成失败: ${_sub_err:-Token 字段不完整（旧版）}"
    fi
    (( ++any )) || true
  done < <(find "$CONF_DIR" -name "*.meta" -type f 2>/dev/null | sort)

  (( any == 0 )) && warn "无可用节点" || true
}

import_token(){
  local raw="$1"
  [[ -n "$raw" ]] || die "需要 token 参数"
  raw=$(printf '%s' "$raw" | tr -d ' \n\r\t')
  (( ${#raw} <= 2048 )) || die "token 过长"

  local extracted_token=""
  extracted_token=$(printf '%s' "$raw" | grep -oE 'eyJ[a-zA-Z0-9+/=]+' | head -1) || true
  [[ -n "$extracted_token" ]] || die "无法提取 Base64 token"

  local json=""
  json=$(printf '%s' "$extracted_token" | base64 -d 2>/dev/null) \
    || die "Base64 解码失败"

  local ip="" dom="" port="" uuid="" pwd="" pfx=""
  ip=$(python3  -c "import json,sys; d=json.loads(sys.stdin.read()); print(d['ip'])"  <<< "$json" 2>/dev/null) \
    || die "token 解析失败（ip 字段缺失）"
  dom=$(python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d['dom'])" <<< "$json" 2>/dev/null) \
    || die "token 解析失败（dom 字段缺失）"
  port=$(python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('port',443))" <<< "$json" 2>/dev/null) || port=443
  [[ "$port" =~ ^[0-9]+$ ]] || port=443
  validate_port "$port"
  validate_ip   "$ip"
  validate_domain "$dom"
  dom="${dom:0:253}"

  uuid=$(python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('uuid',''))"  <<< "$json" 2>/dev/null) || uuid=""
  pwd=$(python3  -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('pwd',''))"   <<< "$json" 2>/dev/null) || pwd=""
  pfx=$(python3  -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('pfx',''))"   <<< "$json" 2>/dev/null) || pfx=""

  if [[ -z "$uuid" || -z "$pwd" || -z "$pfx" ]]; then
    warn "Token 中缺少 uuid/pwd/pfx（旧版 Token）"
  fi

  info "导入路由规则: ${dom} → ${ip}:${port}"

  if [[ ! -f "$INSTALLED_FLAG" ]]; then
    info "--import 触发首次安装初始化 ..."
    ss -tlnp 2>/dev/null | grep -q ':443 ' && die "443 端口已被占用！"

    check_deps
    optimize_kernel_network
    install_nginx
    setup_fallback_decoy_transit
    init_nginx_stream
    setup_firewall_transit
    write_logrotate

    systemctl enable nginx || die "nginx enable failed"
    systemctl is-active --quiet nginx 2>/dev/null || systemctl start nginx \
      || die "Nginx 启动失败"
    mkdir -p "$MANAGER_BASE"
    touch "$INSTALLED_FLAG"
  fi

  _atomic_apply_route "$dom" "$ip" "$port" "$uuid" "$pwd" "$pfx"
  success "路由规则导入完成"
  echo ""
  echo -e "${BOLD}── 生成节点订阅 ───────────────────────────────────────────────${NC}"
  generate_nodes
}

add_landing_route(){
  echo ""
  echo -e "${BOLD}── 增加落地机路由规则 ───────────────────────────────────────────${NC}"
  echo "  方式A（傻瓜）：直接粘贴落地机输出的 Base64 Token"
  echo "  方式B（手动）：依次输入落地机公网 IP 和域名"
  echo ""

  _acquire_lock
  read -rp "  请输入落地机 IP 或直接粘贴 Token: " INPUT_DATA
  (( ${#INPUT_DATA} <= 2048 )) || { _release_lock; die "输入过长"; }

  local extracted_token=""
  extracted_token=$(printf '%s' "$INPUT_DATA" | grep -oE 'eyJ[a-zA-Z0-9+/=]+' | head -1) || true
  if [[ -n "$extracted_token" ]]; then
    import_token "$extracted_token"
    _release_lock
    return
  fi

  local LANDING_IP="$INPUT_DATA"
  validate_ip "$LANDING_IP"
  read -rp "  落地机域名(SNI): " LANDING_DOMAIN
  LANDING_DOMAIN=$(tr '[:upper:]' '[:lower:]' <<< "$LANDING_DOMAIN")
  validate_domain "$LANDING_DOMAIN"
  LANDING_DOMAIN="${LANDING_DOMAIN:0:253}"
  read -rp "  落地机监听端口（默认 8443）[8443]: " LANDING_PORT_IN
  LANDING_PORT_IN="${LANDING_PORT_IN:-8443}"
  validate_port "$LANDING_PORT_IN"

  local safe; safe=$(domain_to_safe "$LANDING_DOMAIN")
  if [[ -f "${SNIPPETS_DIR}/landing_${safe}.map" ]]; then
    warn "该域名已存在路由规则！"
    read -rp "  覆盖更新？[y/N]: " OW
    [[ "$OW" =~ ^[Yy]$ ]] || { info "已取消"; _release_lock; return; }
  fi

  _atomic_apply_route "$LANDING_DOMAIN" "$LANDING_IP" "$LANDING_PORT_IN"
  _release_lock
  success "路由规则已生效: SNI=${LANDING_DOMAIN} → ${LANDING_IP}:${LANDING_PORT_IN}"
}

delete_landing_route(){
  list_landings
  local meta_count=0
  [[ -d "$CONF_DIR" ]] \
    && meta_count=$(find "$CONF_DIR" -name "*.meta" -type f 2>/dev/null | wc -l) || true
  (( meta_count > 0 )) || { warn "无可删除的落地机"; return; }

  read -rp "请输入要删除的落地机域名: " DEL_DOMAIN
  _acquire_lock

  if [[ "$DEL_DOMAIN" =~ ^[0-9]+$ ]]; then
    local n=0 matched=""
    while IFS= read -r meta; do
      (( ++n ))
      (( n == DEL_DOMAIN )) && matched=$(grep '^DOMAIN=' "$meta" 2>/dev/null | cut -d= -f2-) || true; break
    done < <(find "$CONF_DIR" -name "*.meta" -type f 2>/dev/null | sort)
    [[ -n "$matched" ]] || { _release_lock; die "编号 ${DEL_DOMAIN} 不存在"; }
    DEL_DOMAIN="$matched"
  else
    DEL_DOMAIN=$(tr '[:upper:]' '[:lower:]' <<< "$DEL_DOMAIN")
  fi

  validate_domain "$DEL_DOMAIN"
  local safe_del; safe_del=$(domain_to_safe "$DEL_DOMAIN")

  # [Bugfix v3.7] 正确删除 .meta 文件（v3.6 只删了备份，未删实际文件）
  # 1. 删除 map 文件（nginx 配置）
  remove_landing_snippet "$DEL_DOMAIN"
  # 2. 删除 .meta 文件（真相源），这是真正的节点删除
  # 3. 重载 nginx 使路由彻底失效
  nginx_reload
  # [Bugfix v3.12] 删除节点后刷新防火墙，清除该 IP 的 ACCEPT 规则
  setup_firewall_transit
  _release_lock
  success "落地机路由 ${DEL_DOMAIN} 已彻底删除"
}

show_status(){
  echo ""
  echo -e "${BOLD}── 中转机状态 ──────────────────────────────────────────────────${NC}"
  [[ -f "$INSTALLED_FLAG" ]] && echo "  已安装: 是" || echo "  已安装: 否"
  echo "  Nginx: $(systemctl is-active nginx 2>/dev/null || echo inactive)"
  echo "  监听端口: ${LISTEN_PORT}"
  list_landings
}

purge_all(){
  echo ""
  warn "此操作清除本脚本所有内容（不影响 mack-a）"
  read -rp "确认清除？输入 'DELETE' 确认: " CONFIRM
  [[ "$CONFIRM" == "DELETE" ]] || { info "已取消"; return; }

  if grep -q "$STREAM_INCLUDE_MARKER" "$NGINX_MAIN_CONF" 2>/dev/null; then
    sed -i "\#${STREAM_INCLUDE_MARKER}#d" "$NGINX_MAIN_CONF" 2>/dev/null || true
    local esc; esc=$(printf '%s' "$NGINX_STREAM_CONF" | sed -e 's/[\/&]/\\&/g')
    sed -i "\#include ${esc};#d" "$NGINX_MAIN_CONF" 2>/dev/null || true
  fi

  rm -rf "$SNIPPETS_DIR"
  rm -f  "$NGINX_STREAM_CONF" "/etc/nginx/conf.d/transit-fallback.conf" 2>/dev/null || true

  if nginx -t 2>/dev/null; then
    systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null || true
  fi

  rm -f "/etc/systemd/system/nginx.service.d/transit-manager-override.conf" 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true

  _purge_chain_atomic "$FW_CHAIN"
  _purge_chain_atomic "$FW_CHAIN6" 6
  systemctl disable --now "transit-manager-iptables-restore.service" 2>/dev/null || true
  rm -f "/etc/systemd/system/transit-manager-iptables-restore.service" 2>/dev/null || true

  rm -f /etc/sysctl.d/99-transit-bbr.conf /etc/modprobe.d/nf_conntrack.conf 2>/dev/null || true
  rm -f "$LOGROTATE_FILE" "$INSTALLED_FLAG" 2>/dev/null || true
  rm -rf "$LOG_DIR" "$MANAGER_BASE"

  success "清除完毕，mack-a/v2ray-agent 及 Nginx 均未受影响"
}

installed_menu(){
  echo ""
  echo -e "${BOLD}${CYAN}══ 中转机管理菜单 ══════════════════════════════════════════════${NC}"
  list_landings
  echo "  1. 增加落地机路由规则"
  echo "  2. 删除指定落地机路由规则"
  echo "  3. 清除本系统所有数据"
  echo "  4. 显示当前所有节点订阅"
  echo "  5. 退出"
  echo ""
  read -rp "请选择 [1-5]: " CHOICE
  case "$CHOICE" in
    1) add_landing_route;   installed_menu ;;
    2) delete_landing_route; installed_menu ;;
    3) purge_all ;;
    4) generate_nodes;      installed_menu ;;
    5) info "退出"; exit 0 ;;
    *) warn "无效选项"; installed_menu ;;
  esac
}

fresh_install(){
  echo ""
  echo -e "${BOLD}${CYAN}══ 中转机全新安装 ${VERSION} ══════════════════════════════════════════${NC}"
  echo ""
  echo -e "  本脚本将执行："
  echo -e "  ${GREEN}①${NC} 安装 Nginx（stream 模块，TFO fastopen=256）"
  echo -e "  ${GREEN}②${NC} 配置 SNI 嗅探纯 TCP 透传"
  echo -e "  ${GREEN}③${NC} iptables: 仅开放 SSH + TCP 443 + ICMP"
  echo -e "  ${GREEN}④${NC} 录入第一台落地机配对信息"
  echo ""
  read -rp "确认开始安装？[y/N]: " CONFIRM
  [[ "$CONFIRM" =~ ^[Yy]$ ]] || { info "已取消"; exit 0; }

  check_deps
  optimize_kernel_network
  install_nginx
  setup_fallback_decoy_transit
  init_nginx_stream
  setup_firewall_transit
  write_logrotate

  mkdir -p "$MANAGER_BASE"
  touch "$INSTALLED_FLAG"

  echo ""
  echo -e "${BOLD}── 录入第一台落地机配对信息 ─────────────────────────────────────${NC}"
  add_landing_route

  echo ""
  success "══ 中转机安装完成！══"
  echo ""
  echo -e "  ${BOLD}错误日志：${NC} tail -f ${LOG_DIR}/transit_stream_error.log"
}

main(){
  echo -e "${BOLD}"
  echo "╔══════════════════════════════════════════════════════════════════╗"
  printf "║     美西 CN2 GIA 中转机安装脚本  %-32s║\n" "${VERSION}"
  echo "║     SNI嗅探 → 纯TCP盲传(TFO+KA=3m:10s:3+backlog=65535) → 落地机║"
  echo "╚══════════════════════════════════════════════════════════════════╝"
  echo -e "${NC}"

  if [[ "${1:-}" == "--uninstall" ]]; then purge_all; exit 0; fi
  if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then show_help; exit 0; fi
  if [[ "${1:-}" == "--import" ]]; then
    _acquire_lock; import_token "${2:-}"; _release_lock; exit 0
  fi
  if [[ "${1:-}" == "--status" ]]; then show_status; exit $?; fi
  if [[ "${1:-}" == "--doctor" ]]; then _doctor; exit $?; fi

  if [[ -f "$INSTALLED_FLAG" ]]; then
    installed_menu
  else
    fresh_install
  fi
}

main "$@"
