#!/usr/bin/env bash
# install_landing_v3.1.sh — 落地机安装脚本 v3.1
# 5协议单端口回落 · routeOnly嗅探 · AsIs出站 · CAP_NET_BIND_SERVICE
# v3.2: 修复 have_ipv6 拼写、BASE export 缺失、atomic_write 逻辑、mktemp 退出码
set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1;1m'; NC='\033[0m'
readonly VERSION="v3.25"

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

# 清理函数：清理本脚本创建的临时文件（前缀隔离）
_landing_cleanup(){
  # 清理 1 天前的临时文件
  find "${MANAGER_BASE}" /etc/xray-landing /etc/nginx \
    /etc/systemd/system /etc/logrotate.d \
    -maxdepth 5 -type f \
    \( -name '.xray-landing.*' -o -name '.landing-mgr.*' -o -name '.snap-recover.*' \) \
    -delete 2>/dev/null || true
  # 清理 staging 文件
  find "${MANAGER_BASE}/nodes" -maxdepth 1 -type f -name 'tmp-*.conf' -delete 2>/dev/null || true
  # 清理 xray tmp dirs
  rm -rf "${MANAGER_BASE}/tmp/xray_tmp_"* 2>/dev/null || true
  # 清理 tmp 目录中的残留
  find "${TEMP_DIR}" -maxdepth 1 -type f \
    \( -name '.landing-mgr.*' -o -name '.xray-landing.*' -o -name '.nginx-conf-snap.*' \) \
    -delete 2>/dev/null || true
}

# 信号处理器
_landing_signal_handler(){
  local sig="$1"
  echo -e "\n${RED}[${sig}] 安装已中断，清理临时文件..." >&2
  _landing_cleanup
  echo -e "${RED}[中断] 请执行: bash $0 --uninstall${NC}" >&2
  exit 130
}

# 先注册 EXIT，再注册 INT/TERM
trap '_landing_cleanup' EXIT
trap '_landing_signal_handler INT' INT
trap '_landing_signal_handler TERM' TERM


# ============================================================
# --doctor 预检模式：检查环境是否满足安装条件（不修改任何内容）
# ============================================================
_doctor(){
  echo -e "${BOLD}${CYAN}══ 落地机环境预检 ════════════════════════════════════════════${NC}"
  echo ""

  _check_deps(){
    local bin pkg missing=""
    local _deps=(
      "curl:curl" "wget:wget" "unzip:unzip" "iptables:iptables" "python3:python3"
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

    _current=$(sysctl -n net.core.somaxconn 2>/dev/null || echo 0)
    (( _current >= 4096 ))       && echo -e "    somaxconn:       ${GREEN}${_current} ✓${NC}"       || { echo -e "    somaxconn:       ${YELLOW}${_current} (推荐: ≥4096)${NC}"; ((++issues)); }

    _current=$(sysctl -n fs.nr_open 2>/dev/null || echo 0)
    (( _current >= 524288 ))       && echo -e "    fs.nr_open:      ${GREEN}${_current} ✓${NC}"       || { echo -e "    fs.nr_open:      ${YELLOW}${_current} (推荐: ≥524288)${NC}"; ((++issues)); }

    return $issues
  }

  _check_xray(){
    echo ""
    echo -e "  ${BOLD}Xray 二进制检查：${NC}"
    if [[ -f "${LANDING_BIN}" ]]; then
      local ver
      ver=$("${LANDING_BIN}" version 2>/dev/null | head -1 || true)
      echo -e "    ${LANDING_BIN}: ${GREEN}已安装 ${ver:-✓}${NC}"
    else
      echo -e "    ${LANDING_BIN}: ${RED}未安装 ✗${NC}"
    fi
    if [[ -f /usr/local/share/xray-landing/geoip.dat ]]; then
      echo -e "    geoip.dat:       ${GREEN}存在 ✓${NC}"
    else
      echo -e "    geoip.dat:       ${YELLOW}缺失（首次安装会自动下载）${NC}"
    fi
    if [[ -f /usr/local/share/xray-landing/geosite.dat ]]; then
      echo -e "    geosite.dat:     ${GREEN}存在 ✓${NC}"
    else
      echo -e "    geosite.dat:     ${YELLOW}缺失（首次安装会自动下载）${NC}"
    fi
  }

  _check_ports(){
    echo ""
    echo -e "  ${BOLD}端口可用性检查（无侵入）：${NC}"
    local ssh_port=""
    ssh_port=$(ss -tlnp 2>/dev/null | awk '/sshd/{for(i=1;i<=NF;i++) if($i~/:[0-9]+$/){sub(/^.*:/,"",$i);print $i;exit}}' | head -1 || true)
    [[ -z "$ssh_port" ]] && ssh_port=$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}' || true)
    if [[ "$ssh_port" =~ ^[0-9]+$ ]]; then
      echo -e "    SSH 端口:         ${GREEN}${ssh_port} (已检测)${NC}"
    else
      echo -e "    SSH 端口:         ${YELLOW}无法自动检测${NC}"
    fi

    # Load current landing port if installed
    load_manager_config 2>/dev/null || true
    if [[ "${LANDING_PORT:-}" =~ ^[0-9]+$ ]]; then
      if ss -tlnp 2>/dev/null | grep -q ":${LANDING_PORT} "; then
        echo -e "    落地监听 ${LANDING_PORT}: ${YELLOW}已被占用${NC}"
      else
        echo -e "    落地监听 ${LANDING_PORT}: ${GREEN}可用 ✓${NC}"
      fi
      # Check internal ports
      for p in "${VLESS_GRPC_PORT:-0}" "${TROJAN_GRPC_PORT:-0}" "${VLESS_WS_PORT:-0}" "${TROJAN_TCP_PORT:-0}"; do
        [[ "$p" =~ ^[0-9]+$ && "$p" -gt 0 ]] || continue
        if ss -tlnp 2>/dev/null | grep -q ":${p} "; then
          echo -e "    内部端口 ${p}:      ${YELLOW}已被占用${NC}"
        else
          echo -e "    内部端口 ${p}:      ${GREEN}可用 ✓${NC}"
        fi
      done
    else
      echo -e "    落地监听端口:     ${YELLOW}未配置（首次安装时设置）${NC}"
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

    # Cloudflare API check
    if curl -4 -fsSL --connect-timeout 10 --max-time 15        "https://api.cloudflare.com/client/v4/user/tokens/verify"        -H "Authorization: Bearer $(grep '^CF_TOKEN=' "${MANAGER_CONFIG}" 2>/dev/null | cut -d= -f2-)"        -H "Content-Type: application/json" 2>/dev/null | grep -q '"success"'; then
      echo -e "    Cloudflare API:    ${GREEN}可用 ✓${NC}"
    else
      echo -e "    Cloudflare API:   ${YELLOW}未配置或不可达${NC}"
    fi

    if [[ -f /proc/net/if_inet6 ]]; then
      local ipv6_disabled
      ipv6_disabled=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 1)
      if [[ "$ipv6_disabled" == "0" ]]; then
        echo -e "    IPv6 路由:        ${GREEN}已启用 ✓${NC}"
      else
        echo -e "    IPv6 路由:        ${YELLOW}已禁用（仅 IPv4）${NC}"
      fi
    fi
  }

  _check_cert(){
    echo ""
    echo -e "  ${BOLD}证书状态检查：${NC}"
    if [[ ! -d "${MANAGER_BASE}/nodes" ]]; then
      echo -e "    节点配置:        ${YELLOW}未配置${NC}"
    else
      local n=0; n=$(find "${MANAGER_BASE}/nodes" -name "*.conf" -type f 2>/dev/null | wc -l)
      echo -e "    节点配置:        ${GREEN}${n} 个节点${NC}"
      local dom
      for cert_dir in "${CERT_BASE}"/*/fullchain.pem; do
        [[ -f "$cert_dir" ]] || continue
        dom="${cert_dir%%/fullchain.pem}"; dom="${dom##*/}"
        local days
        days=$(openssl x509 -in "$cert_dir" -noout -days 2>/dev/null | awk -F= '{print $2}' || echo 0)
        if [[ "$days" =~ ^[0-9]+$ ]]; then
          if (( days > 30 )); then
            echo -e "    ${dom}:            ${GREEN}${days} 天${NC}"
          elif (( days > 0 )); then
            echo -e "    ${dom}:            ${YELLOW}${days} 天（快到期）${NC}"
          else
            echo -e "    ${dom}:            ${RED}已过期${NC}"
          fi
        fi
      done
    fi
  }

  _check_service(){
    echo ""
    echo -e "  ${BOLD}systemd 服务检查：${NC}"
    if systemctl list-units --type=service --all 2>/dev/null | grep -q "xray-landing"; then
      if systemctl is-active --quiet "${LANDING_SVC}" 2>/dev/null; then
        echo -e "    ${LANDING_SVC}:  ${GREEN}运行中 ✓${NC}"
      elif systemctl is-enabled --quiet "${LANDING_SVC}" 2>/dev/null; then
        echo -e "    ${LANDING_SVC}:  ${YELLOW}未运行但已启用${NC}"
      else
        echo -e "    ${LANDING_SVC}:  ${RED}未安装 ✗${NC}"
      fi
    else
      echo -e "    ${LANDING_SVC}:  ${YELLOW}未安装（首次运行会创建）${NC}"
    fi
    if systemctl is-enabled --quiet xray-landing-iptables-restore.service 2>/dev/null; then
      echo -e "    iptables 持久化:   ${GREEN}已启用 ✓${NC}"
    else
      echo -e "    iptables 持久化: ${YELLOW}未启用${NC}"
    fi
  }

  _check_acme(){
    echo ""
    echo -e "  ${BOLD}ACME/证书申请检查：${NC}"
    if [[ -f "${ACME_HOME}/acme.sh" ]]; then
      echo -e "    acme.sh:          ${GREEN}已安装 ✓${NC}"
      if crontab -l 2>/dev/null | grep -qE 'acme\.sh.*(--cron|cron)'; then
        echo -e "    acme cron:        ${GREEN}已配置 ✓${NC}"
      else
        echo -e "    acme cron:        ${YELLOW}未配置${NC}"
      fi
    else
      echo -e "    acme.sh:          ${YELLOW}未安装（首次申请会自动安装）${NC}"
    fi
  }

  _check_resources(){
    echo ""
    echo -e "  ${BOLD}系统资源检查：${NC}"
    local ram_mb disk_mb fd_max
    ram_mb=$(free -m 2>/dev/null | awk '/Mem:/{print $2}') || ram_mb=0
    disk_mb=$(df -m / 2>/dev/null | awk 'NR==2{print $4}') || disk_mb=0
    fd_max=$(ulimit -n 2>/dev/null) || fd_max=0

    (( ram_mb >= 512 ))       && echo -e "    内存:            ${GREEN}${ram_mb} MB ✓${NC}"       || echo -e "    内存:            ${YELLOW}${ram_mb} MB (推荐 ≥512MB)${NC}"

    (( disk_mb >= 2048 ))       && echo -e "    磁盘 / 可用:     ${GREEN}${disk_mb} MB ✓${NC}"       || echo -e "    磁盘 / 可用:     ${RED}${disk_mb} MB (推荐 ≥2GB)${NC}"

    (( fd_max >= 524288 ))       && echo -e "    fd 最大值:       ${GREEN}${fd_max} ✓${NC}"       || echo -e "    fd 最大值:       ${YELLOW}${fd_max} (推荐 ≥524288)${NC}"
  }

  _check_tmp(){
    echo ""
    echo -e "  ${BOLD}临时文件写入测试：${NC}"
    local _t
    _t=$(mktemp /tmp/landing-doctor-test.XXXX 2>/dev/null) && rm -f "$_t"       && echo -e "    /tmp 写入:        ${GREEN}正常 ✓${NC}"       || echo -e "    /tmp 写入:        ${RED}失败 ✗${NC}"
    mkdir -p "${MANAGER_BASE}/tmp" 2>/dev/null
    _t=$(mktemp "${MANAGER_BASE}/tmp/landing-doctor-test.XXXX" 2>/dev/null) && rm -f "$_t"       && echo -e "    MANAGER_BASE/tmp:  ${GREEN}正常 ✓${NC}"       || echo -e "    MANAGER_BASE/tmp:  ${RED}失败 ✗${NC}"
  }

  local _issues=0 _total=0

  echo -e "  ${BOLD}① 依赖检查${NC}"
  _check_deps; ((++_total)) || ((++_issues))

  echo -e ""
  echo -e "  ${BOLD}② 内核参数${NC}"
  _check_kernel; ((++_total)) || ((++_issues))

  echo -e ""
  echo -e "  ${BOLD}③ Xray 二进制${NC}"
  _check_xray; ((++_total)) || ((++_issues))

  echo -e ""
  echo -e "  ${BOLD}④ 端口可用性${NC}"
  _check_ports; ((++_total)) || ((++_issues))

  echo -e ""
  echo -e "  ${BOLD}⑤ 网络连通性${NC}"
  _check_network; ((++_total)) || ((++_issues))

  echo -e ""
  echo -e "  ${BOLD}⑥ 证书状态${NC}"
  _check_cert; ((++_total)) || ((++_issues))

  echo -e ""
  echo -e "  ${BOLD}⑦ systemd 服务${NC}"
  _check_service; ((++_total)) || ((++_issues))

  echo -e ""
  echo -e "  ${BOLD}⑧ ACME 证书申请${NC}"
  _check_acme; ((++_total)) || ((++_issues))

  echo -e ""
  echo -e "  ${BOLD}⑨ 系统资源${NC}"
  _check_resources; ((++_total)) || ((++_issues))

  echo -e ""
  echo -e "  ${BOLD}⑩ 临时文件${NC}"
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


# [Bugfix v3.1] mktemp: 正确获取 mktemp 命令的退出状态
# 修复: mktemp_result=$? 只捕获 "result=$(mktemp ...)" 赋值的退出码（总是0）
# 正确做法: 在子进程中单独运行 mktemp 并捕获其退出码
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
  
  # 尝试直接 touch 创建
  if touch "$tmp_file" 2>/dev/null; then
    printf '%s' "$tmp_file"
    return 0
  fi
  
  # 回退: 在独立子进程中运行 mktemp，正确捕获其退出码
  local oldopts="$-"
  set +e
  local result mkt_status=1
  result=$( timeout "$timeout_secs" mktemp "${dir}/.landing-mgr.${prefix}.XXXXXX" 2>/dev/null ) && mkt_status=0 || mkt_status=$?
  set -"$oldopts"
  
  if (( mkt_status == 0 )) && [[ -n "$result" && -f "$result" ]]; then
    printf '%s' "$result"
    return 0
  fi
  
  # 最终回退: date+pid+纳秒（低概率碰撞，可接受）
  # [Bugfix v3.10] 移除了可预测的纳秒 fallback, 失败时直接报错
  echo "_mktemp: 所有原子创建方式均失败（/tmp 可能已满）" >&2
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

# [Bugfix v3.1] atomic_write: 直接使用 _mktemp 的返回值，不做二次修改
# _mktemp 保证返回有效且已存在的唯一路径，无需额外处理
atomic_write(){
  local target="$1" mode="${2:-644}" owner_group="${3:-root:root}"
  local dir tmp
  
  [[ -z "$target" ]] && { echo "atomic_write: target 为空" >&2; return 1; }
  dir="$(dirname "$target")"
  mkdir -p "$dir"
  
  # _mktemp 总是返回已验证存在的唯一路径
  tmp="$(_mktemp "atomic" 3 "$dir")"
  
  # stdin → 临时文件
  if ! cat >"$tmp" 2>/dev/null; then
    rm -f "$tmp" 2>/dev/null
    echo "atomic_write: 无法写入 $tmp" >&2
    return 1
  fi
  
  chmod "$mode" "$tmp" 2>/dev/null || true
  chown "$owner_group" "$tmp" 2>/dev/null || true
  
  # mv 是原子操作
  if ! mv -f "$tmp" "$target" 2>/dev/null; then
    rm -f "$tmp" 2>/dev/null
    echo "atomic_write: mv 失败 $tmp → $target" >&2
    return 1
  fi
  return 0
}

# 全局写锁
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
}

# [Bugfix v3.1] have_ipv6: 修正拼写错误 disable_ipvjsjs_ipv6 → disable_ipv6
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
用法: bash install_landing_v3.1.sh [选项]
  （无参数）        交互式安装或管理菜单
  --doctor          环境预检（不修改任何内容）
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

  echo "options nf_conntrack hashsize=262144" > /etc/modprobe.d/99-landing-conntrack.conf 2>/dev/null || true
  modprobe nf_conntrack 2>/dev/null || true
  sysctl --system &>/dev/null || true

  # [v3.9 增强] TFO 内核支持验证（防止静默失败）
  if ! sysctl -w net.ipv4.tcp_fastopen=3 &>/dev/null; then
    warn "内核不支持 TFO（或被内核命令行禁用），fastopen=256 指令将被 nginx 忽略"
  fi
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
  local tmp_dir; tmp_dir="$(mktemp -d /tmp/xray-dl.XXXXXX)"
  mkdir -p "$tmp_dir"

  # 下载 Xray + SHA256 完整性校验（失败自动重试）
  local _dl_ok=0
  for _try in 1 2 3; do
    [[ $_try -gt 1 ]] && info "第 ${_try} 次尝试下载 Xray ..."

    wget -q --timeout=60 --tries=2 -O "${tmp_dir}/xray.zip"       "https://github.com/XTLS/Xray-core/releases/download/${ver}/${zip_name}"       && _dl_ok=1 && break
    sleep 5
  done
  [[ $_dl_ok -eq 1 ]] || die "下载 Xray 失败"

  # SHA256 校验（从官方 sha256sums.txt 验证）
  if wget -q -O "${tmp_dir}/sha256sums.txt"       "https://github.com/XTLS/Xray-core/releases/download/${ver}/sha256sums.txt" 2>/dev/null       && grep -qF "$zip_name" "${tmp_dir}/sha256sums.txt" 2>/dev/null; then
    if ! ( cd "$tmp_dir" && grep -F "$zip_name" sha256sums.txt | sha256sum -c - ) 2>/dev/null; then
      warn "SHA256 校验失败，删除并重新下载..."
      rm -f "${tmp_dir}/xray.zip"
      wget -q --timeout=60 --tries=3 -O "${tmp_dir}/xray.zip"         "https://github.com/XTLS/Xray-core/releases/download/${ver}/${zip_name}"         || die "重新下载 Xray 失败"
      ( cd "$tmp_dir" && grep -F "$zip_name" sha256sums.txt | sha256sum -c - ) 2>/dev/null         || warn "SHA256 仍不匹配（网络问题可能），继续安装"
    fi
  else
    warn "无法获取 SHA256 校验文件，跳过完整性验证"
  fi

  unzip -q "${tmp_dir}/xray.zip" xray geoip.dat geosite.dat -d "${tmp_dir}/" || die "解压 Xray 失败"

  # 二次校验：验证解压后的二进制是否为有效 ELF
  if ! file "${tmp_dir}/xray" 2>/dev/null | grep -qE 'ELF.*executable|ELF.*setuid'; then
    rm -f "${tmp_dir}/xray.zip"
    die "解压后的 xray 不是有效的 ELF 可执行文件（下载被劫持）"
  fi
  install -m 755 "${tmp_dir}/xray" "$LANDING_BIN"
  chown root:"$LANDING_USER" "$LANDING_BIN" 2>/dev/null || true
  
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
  
  # [Bugfix v3.1] 用 mktemp 创建备份，失败则跳过调优（不阻断）
  local _mc_bak; _mc_bak="$(mktemp /tmp/nginx-conf-backup.XXXXXX.conf 2>/dev/null)" && cp -a "$mc" "$_mc_bak" 2>/dev/null || { _mc_bak=""; }

  local _tmc_ram_mb; _tmc_ram_mb=$(free -m 2>/dev/null | awk '/Mem:/{print $2}') || _tmc_ram_mb=1024
  local _tmc_fd=$(( _tmc_ram_mb * 800 ))
  (( _tmc_fd < 524288 ))   && _tmc_fd=524288
  (( _tmc_fd > 1048576 )) && _tmc_fd=1048576

  if ! grep -qE '^\s*worker_connections\s+100000\s*;' "$mc" 2>/dev/null; then
    if grep -qE '^\s*worker_connections' "$mc" 2>/dev/null; then
      sed -i 's/^\s*worker_connections\s\+[0-9]\+;/    worker_connections 100000;/' "$mc"
    else
      sed -i '/^events\s*{/a\    worker_connections 100000;' "$mc"
    fi
  fi

  if ! grep -qE "^\s*worker_rlimit_nofile\s+${_tmc_fd}\s*;" "$mc" 2>/dev/null; then
    if grep -qE '^\s*worker_rlimit_nofile' "$mc" 2>/dev/null; then
      sed -i "s/^.*worker_rlimit_nofile.*/worker_rlimit_nofile ${_tmc_fd};/" "$mc"
    else
      sed -i "/^events\s*{/i\\worker_rlimit_nofile ${_tmc_fd};" "$mc"
    fi
  fi

  if ! nginx -t 2>/dev/null; then
    [[ -n "$_mc_bak" && -f "$_mc_bak" ]] && cp -f "$_mc_bak" "$mc" 2>/dev/null || true
    rm -f "$_mc_bak" 2>/dev/null || true
    die "nginx.conf tuning failed"
  fi
  rm -f "$_mc_bak" 2>/dev/null || true

  local od="/etc/systemd/system/nginx.service.d"
  mkdir -p "$od"
  atomic_write "${od}/landing-override.conf" 644 root:root <<SVCOV
[Service]
LimitNOFILE=${_tmc_fd}
TasksMax=infinity
SVCOV
  systemctl daemon-reload 2>/dev/null || true
}


_write_cert_reload_script(){
  atomic_write "$CERT_RELOAD_SCRIPT" 755 root:root <<'RELOAD_EOF'
#!/bin/sh
# v3.2: [Bugfix] 使用 flock 替代 ps 检查，实现进程级互斥
set -eu
CERT_DIR="${1:-}"
[ -n "$CERT_DIR" ] || exit 0
LOCKFILE="${CERT_DIR}/.reload.lock"

# 文件锁：防止并发 reload（acme.sh 续期可能同时触发多个 reload）
(
  flock -w 30 9 || { echo "$(date '+%Y-%m-%d %H:%M:%S') WARN: reload locked, skipping" >> /var/log/acme-xray-landing-renew.log 2>/dev/null; exit 0; }
  
  # 严格权限设置（失败则报警，不静默忽略）
  chown -R root:xray-landing "$CERT_DIR" || { echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: chown 失败" >> /var/log/acme-xray-landing-renew.log 2>/dev/null; exit 1; }
  chmod 750 "$CERT_DIR" || { echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: chmod 750 失败" >> /var/log/acme-xray-landing-renew.log 2>/dev/null; exit 1; }
  chmod 644 "$CERT_DIR/cert.pem" "$CERT_DIR/fullchain.pem" || { echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: chmod 644 失败" >> /var/log/acme-xray-landing-renew.log 2>/dev/null; exit 1; }
  chmod 640 "$CERT_DIR/key.pem" || { echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: chmod 640 失败" >> /var/log/acme-xray-landing-renew.log 2>/dev/null; exit 1; }

  # 权限验证：确认 xray-landing 用户能读证书（防止 chmod 被 ACL/SELinux 阻止）
  if ! runuser -u xray-landing -- test -r "$CERT_DIR/fullchain.pem" 2>/dev/null; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: xray-landing 无法读取证书，权限异常" >> /var/log/acme-xray-landing-renew.log 2>/dev/null; exit 1
  fi
  if ! runuser -u xray-landing -- test -r "$CERT_DIR/key.pem" 2>/dev/null; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: xray-landing 无法读取私钥，权限异常" >> /var/log/acme-xray-landing-renew.log 2>/dev/null; exit 1
  fi

  if ! /bin/systemctl is-active --quiet xray-landing.service 2>/dev/null; then
    exit 0
  fi

  # 【关键】强制同步文件系统缓存，确保证书完全写入磁盘后再 reload
  # 否则 nginx 可能在 acme.sh 写盘过程中 reload，导致读取不完整的 PEM
  sync "$CERT_DIR" 2>/dev/null || true
  sync "$CERT_DIR/cert.pem" 2>/dev/null || true
  sync "$CERT_DIR/key.pem" 2>/dev/null || true
  sync "$CERT_DIR/fullchain.pem" 2>/dev/null || true

  # reload 前额外校验证书内容完整性（防止磁盘写入不完整）
  if ! openssl x509 -noout -in "$CERT_DIR/fullchain.pem" 2>/dev/null      || ! openssl rsa -check -in "$CERT_DIR/key.pem" 2>/dev/null; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: 证书文件损坏，终止 reload" >> /var/log/acme-xray-landing-renew.log 2>/dev/null
    exit 1
  fi

  # 检查证书剩余有效期（>24小时才 reload，否则保留旧进程）
  if openssl x509 -checkend 86400 -noout -in "$CERT_DIR/fullchain.pem" 2>/dev/null; then
    # restart > reload（restart 确保 nginx 重新读取证书，reload 可能用缓存）
    /bin/systemctl restart xray-landing.service 2>/dev/null       || { echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: 服务 restart 失败" >> /var/log/acme-xray-landing-renew.log 2>/dev/null; exit 1; }
  else
    echo "$(date '+%Y-%m-%d %H:%M:%S') WARN: 证书续期后校验失败，保留旧进程态" >> /var/log/acme-xray-landing-renew.log 2>/dev/null || true
  fi
) 9>"$LOCKFILE"
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
        # [Bugfix v3.1] 修正路径拼接错误: $ACME_HOME}/ → $ACME_HOME/
        cp -rp "${_home_acme}/." "${ACME_HOME}/" 2>/dev/null || cp -rp "${_home_acme}/." "${ACME_HOME}/" || true
        rm -rf "${_home_acme}"
      fi
    fi
    
    [[ -f "${ACME_HOME}/dnsapi/dns_cf.sh" ]] \
      || die "acme.sh 缺少 dns_cf.sh 插件"
    
    env ACME_HOME="$ACME_HOME" "${ACME_HOME}/acme.sh" \
      --set-default-ca 2>/dev/null || true
    "${ACME_HOME}/acme.sh" --upgrade --auto-upgrade 2>/dev/null || true
  fi
  
  export PATH="${ACME_HOME}:${PATH}"

  info "申请证书（DNS-01/Cloudflare）: ${domain} ..."

  local issued=0
  for try in 1 2; do
    CF_Token="$cf_token" env ACME_HOME="$ACME_HOME" "${ACME_HOME}/acme.sh" \
      --issue --dns dns_cf --server https://acme-v02.api.letsencrypt.org/directory --domain "$domain" --keylength ec-256 \
      --dnssleep 40 --force \
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

# [Bugfix v3.1] sync_xray_config: 添加 LANDING_BASE 到 export 列表
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
    # [Bugfix v3.1] 添加 LANDING_BASE 到 export
    export _LANDING_BASE="$LANDING_BASE"
    
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
cert_base = os.environ.get('_CERT_BASE', '')
landing_base = os.environ.get('_LANDING_BASE', '/etc/xray-landing')

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
PORT_VLESS_WS    = _vw
PORT_TROJAN_TCP  = _tt
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
                    {"alpn": "http/1.1", "path": f"/{PFX}-vw", "dest": PORT_VLESS_WS, "xver": 0},
                    {"dest": PORT_TROJAN_TCP, "xver": 0}
                ]
            },
            "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": tls_settings},
            "sniffing": {"enabled": True, "routeOnly": True, "destOverride": ["http", "tls"]}
        },
        {
            "listen": "127.0.0.1", "port": PORT_VLESS_GRPC, "protocol": "vless",
            "settings": {"clients": [{"id": vless_uuid, "level": 0, "email": "vless-grpc@inner"}], "decryption": "none"},
            "streamSettings": {"network": "grpc", "grpcSettings": {"serviceName": f"{PFX}-vg"}},
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
            "settings": {"clients": trojan_clients},
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
        {"protocol": "freedom", "tag": "direct", "settings": {"domainStrategy": "AsIs"}},
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
        "levels": {"0": {"handshakeTimeout": 4, "connIdle": 300, "uplinkOnly": 2, "downlinkOnly": 5, "bufferSize": 64}},
        "system": {"statsInboundUplink": False, "statsInboundDownlink": False}
    }
}

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
    maxsize 100M
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

  # [v3.8 增强] SSH 登录时证书濒死红色告警（当 acme.sh 静默失败时救命）
  local _cert_alert="/etc/profile.d/xray-cert-alert.sh"
  mkdir -p /etc/profile.d
  atomic_write "$_cert_alert" 755 root:root <<'CERTEOF'
#!/bin/bash
# v3.11: 当证书剩余 ≤7 天时 SSH 登录显示红色警告（仅检查当天有更新的证书）
CERT_BASE="${CERT_BASE:-/etc/xray-landing/certs}"
_alert_days=7
# [Bugfix v3.11] 使用 find -mtime 0 而非 glob expansion（避免 arg list too long）
if [[ -d "$CERT_BASE" ]]; then
  while IFS= read -r cert; do
    [[ -f "$cert" ]] || continue
    days=$(openssl x509 -in "$cert" -noout -days 2>/dev/null | awk -F'"'"'= '"'"' '"'"'{print $2}'"'"') || continue
    [[ "$days" =~ ^[0-9]+$ ]] || continue
    if (( days <= _alert_days )); then
      domain="${cert%/*}"; domain="${domain##*/}"
      printf '\033[0;31m\n'
      echo "═══════════════════════════════════════════════════"
      echo "  ⚠  证书濒死警告  ⚠"
      echo "  域名: $domain"
      echo "  剩余: ${days} 天（≤${_alert_days} 天告警阈值）"
      echo "  建议: 手动执行: bash install_landing_v3.1.sh --doctor"
      echo "═══════════════════════════════════════════════════"
      printf '\033[0m\n'
    fi
  done < <(find "$CERT_BASE" -name "fullchain.pem" -mtime 0 2>/dev/null)
fi
CERTEOF
  success "logrotate 已配置"
}

create_systemd_service(){
  local _svc_ram_mb; _svc_ram_mb=$(free -m 2>/dev/null | awk '/Mem:/{print $2}') || _svc_ram_mb=1024
  local _svc_fd=$(( _svc_ram_mb * 800 ))
  (( _svc_fd < 524288 ))   && _svc_fd=524288
  (( _svc_fd > 1048576 )) && _svc_fd=1048576

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
LimitNOFILE=${_svc_fd}:${_svc_fd}
LimitNPROC=65535
TasksMax=infinity
ProtectSystem=strict
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
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
LimitNOFILE=${_svc_fd}:${_svc_fd}
TasksMax=infinity
XRAYLIMITS

  # [Bugfix v3.1] recovery service: 使用 flock -E 避免子 shell 退出码干扰
  atomic_write /etc/systemd/system/xray-landing-recovery.service 644 root:root <<'RECEOF'
[Unit]
Description=Xray Landing Recovery
DefaultDependencies=no

[Service]
Type=oneshot
ExecStart=/bin/sh -c '
  # [Bugfix v3.18] 在 shell 子环境中定义路径变量（systemd service 不继承 bash readonly 变量）
  LANDING_BASE="/etc/xray-landing";
  LANDING_SVC="xray-landing.service";
  LANDING_CONF="${LANDING_BASE}/config.json";
  CERT_BASE="${LANDING_BASE}/certs";
  mkdir -p /run/lock 2>/dev/null;
  lockfile="/run/lock/xray-landing-recovery.lock";
  tsfile="/run/lock/xray-landing-recovery.last";
  (
    flock -w 60 -E 0 9 || exit 0;
    now=$(date +%s);
    # [Bugfix v3.14] force-recovery 文件存在时跳过 rate-limit（允许管理员手动重置）
    if [ -f /etc/xray-landing/.recovery-force ]; then
      logger -t xray-landing-recovery "force-recovery file present, skipping rate-limit";
    elif [ -f "$tsfile" ]; then
      last=$(cat "$tsfile" 2>/dev/null || echo 0);
      delta=$((now - last));
      if [ "$delta" -lt 1800 ]; then
        logger -t xray-landing-recovery "Recovery rate-limited (delta=${delta}s < 1800s)";
        exit 0;
      fi;
    fi;
    echo "$now" > "$tsfile";
    cert_ok=0; cfg_ok=0;
    for d in ${CERT_BASE}/*/fullchain.pem; do [ -f "$d" ] && cert_ok=1 && break; done;
    python3 -c "import json,sys; json.load(open(sys.argv[1]))" ${LANDING_CONF} 2>/dev/null && cfg_ok=1 || true;
    if [ "$cert_ok" = "1" ] && [ "$cfg_ok" = "1" ]; then
      systemctl reset-failed ${LANDING_SVC} 2>/dev/null || true;
      systemctl start ${LANDING_SVC} 2>/dev/null || true;
    fi
  ) 9>"$lockfile"
'
RECEOF

  mkdir -p "$LANDING_LOG"
  chown "$LANDING_USER:$LANDING_USER" "$LANDING_LOG"
  chmod 750 "$LANDING_LOG"
  write_logrotate

  systemctl daemon-reload \
    || die "daemon-reload 失败"
  systemctl enable "$LANDING_SVC"
  # [Bugfix] 全新安装时不立即启动服务，等 add_node 生成 config.json 后再启动
  if [[ -f "${LANDING_CONF}" ]]; then
    systemctl restart "$LANDING_SVC"
    sleep 2
    if systemctl is-active --quiet "$LANDING_SVC"; then
      success "服务 ${LANDING_SVC} 已启动"
    else
      journalctl -u "$LANDING_SVC" --no-pager -n 30
      die "服务启动失败"
    fi
  else
    info "服务已注册，配置将在添加节点后启动"
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
      iptables -w -D INPUT "$_num" 2>/dev/null || break
    done
  }
  _bulldoze_input_refs6(){
    local _chain="$1" _num
    while true; do
      _num=$(ip6tables -L INPUT --line-numbers -n 2>/dev/null \
             | awk -v c="$_chain" 'NR>2 && $2==c {print $1; exit}')
      [[ -n "$_num" ]] || break
      ip6tables -w -D INPUT "$_num" 2>/dev/null || break
    done
  }

  _bulldoze_input_refs  "$FW_CHAIN";  _bulldoze_input_refs  "$FW_TMP"
  iptables -w -F "$FW_TMP"   2>/dev/null || true; iptables -X "$FW_TMP"   2>/dev/null || true
  iptables -w -F "$FW_CHAIN" 2>/dev/null || true; iptables -X "$FW_CHAIN" 2>/dev/null || true
  if have_ipv6; then
    _bulldoze_input_refs6 "$FW_CHAIN6"; _bulldoze_input_refs6 "$FW_TMP6"
    ip6tables -w -F "$FW_TMP6"   2>/dev/null || true; ip6tables -X "$FW_TMP6"   2>/dev/null || true
    ip6tables -w -F "$FW_CHAIN6" 2>/dev/null || true; ip6tables -X "$FW_CHAIN6" 2>/dev/null || true
  fi

  iptables -w -N "$FW_TMP" 2>/dev/null || iptables -F "$FW_TMP"
  iptables -w -A "$FW_TMP" -i lo                                       -j ACCEPT
  iptables -w -A "$FW_TMP" -p tcp  --dport "$ssh_port"                 -j ACCEPT
  iptables -w -A "$FW_TMP" -m conntrack --ctstate INVALID,UNTRACKED    -j DROP
  iptables -w -A "$FW_TMP" -m conntrack --ctstate ESTABLISHED,RELATED  -j ACCEPT
  iptables -w -A "$FW_TMP" -p icmp --icmp-type echo-request -m limit --limit 10/second --limit-burst 20 -j ACCEPT || true
  iptables -w -A "$FW_TMP" -p icmp --icmp-type echo-request            -j DROP

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
    iptables -w -A "$FW_TMP" -s "${tip}/32" -p tcp --dport "$LANDING_PORT" -j ACCEPT
    info "  ACCEPT ← ${tip}/32:${LANDING_PORT}"; (( ++count )) || true
  done < <(printf '%s\n' "${tips[@]+${tips[@]}}" | sort -u)

  # [Bugfix v3.1] 如果没有中转 IP（初始状态），给出警告但不阻断
  if (( count == 0 )); then
    warn "无中转 IP：防火墙将只允许 SSH + 落地端口自身"
    info "添加第一个节点后防火墙规则会自动更新"
  fi

  iptables -w -A "$FW_TMP" -j DROP
  iptables -w -I INPUT 1 -m comment --comment "xray-landing-swap" -j "$FW_TMP"
  _bulldoze_input_refs "$FW_CHAIN"
  iptables -w -F "$FW_CHAIN" 2>/dev/null || true; iptables -X "$FW_CHAIN" 2>/dev/null || true
  iptables -E "$FW_TMP" "$FW_CHAIN"
  iptables -w -I INPUT 1 -m comment --comment "xray-landing-jump" -j "$FW_CHAIN"
  while iptables -D INPUT -m comment --comment "xray-landing-swap" 2>/dev/null; do :; done

  if have_ipv6; then
    ip6tables -w -N "$FW_TMP6" 2>/dev/null || ip6tables -F "$FW_TMP6"
    ip6tables -w -A "$FW_TMP6" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ip6tables -w -A "$FW_TMP6" -i lo -j ACCEPT
    ip6tables -w -A "$FW_TMP6" -p tcp --dport "$ssh_port" -j ACCEPT
    ip6tables -w -A "$FW_TMP6" -m conntrack --ctstate INVALID,UNTRACKED -j DROP
    ip6tables -w -A "$FW_TMP6" -p ipv6-icmp -j ACCEPT
    ip6tables -w -A "$FW_TMP6" -p tcp --dport "$LANDING_PORT" -j DROP
    ip6tables -w -A "$FW_TMP6" -j DROP
    ip6tables -w -I INPUT 1 -m comment --comment "xray-landing-v6-swap" -j "$FW_TMP6"
    _bulldoze_input_refs6 "$FW_CHAIN6"
    ip6tables -w -F "$FW_CHAIN6" 2>/dev/null || true; ip6tables -X "$FW_CHAIN6" 2>/dev/null || true
    ip6tables -E "$FW_TMP6" "$FW_CHAIN6"
    ip6tables -w -I INPUT 1 -m comment --comment "xray-landing-v6-jump" -j "$FW_CHAIN6"
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
  
  # 动态收集当前所有落地节点 IP（运行时读取，不依赖生成时刻快照）
  _load_transit_ips(){
    local _meta _tip
    for _meta in "${MANAGER_BASE}/nodes"/*.conf; do
      [ -f "$_meta" ] || continue
      _tip=$(grep '^TRANSIT_IP=' "$_meta" 2>/dev/null | cut -d= -f2- || true)
      [ -n "$_tip" ] || continue
      # 验证 IP 格式有效性
      python3 -c "import ipaddress,sys; ipaddress.IPv4Address(sys.argv[1])" "$_tip" 2>/dev/null || continue
      printf '%s\n' "$_tip"
    done
  }
  transit_ips=( $(_load_transit_ips | sort -u) )

  atomic_write "$fw_script" 700 root:root <<FWEOF
#!/bin/sh
# LANDING_FW_VERSION=${VERSION}_\$(date +%Y%m%d)

# 运行时读取 LANDING_PORT（支持端口变更后热生效）
MANAGER_CONF="${MANAGER_BASE}/manager.conf"
if [ -f "$MANAGER_CONF" ]; then
  _lp=$(grep '^LANDING_PORT=' "$MANAGER_CONF" 2>/dev/null | cut -d= -f2- || echo "8443")
  case "$_lp" in
    [0-9]*) LANDING_PORT="$_lp" ;;
    *) LANDING_PORT="8443" ;;
  esac
else
  LANDING_PORT="8443"
fi
_detect_ssh(){
  local p="\$(sshd -T 2>/dev/null | awk '/^port /{print \$2; exit}' || true)"
  [ -z "\$p" ] && p="\$(ss -tlnp 2>/dev/null | awk '/sshd/{for(i=1;i<=NF;i++) if(\$i~/:[0-9]+\$/){sub(/^.*:/,\"\",\$i);print \$i;exit}}' | head -1 || true)"
  if echo "\$p" | grep -qE '^[0-9]+\$' && [ "\$p" -ge 1 ] && [ "\$p" -le 65535 ]; then echo "\$p"; else echo "${ssh_port}"; fi
}
SSH_PORT="\$( _detect_ssh )"
while iptables  -D INPUT -m comment --comment 'xray-landing-jump' 2>/dev/null; do :; done
while iptables  -D INPUT -m comment --comment 'xray-landing-swap' 2>/dev/null; do :; done
iptables -w  -F ${FW_CHAIN}  2>/dev/null || true; iptables  -X ${FW_CHAIN}  2>/dev/null || true
iptables -w  -N ${FW_CHAIN}  2>/dev/null || true
iptables -w -A ${FW_CHAIN} -i lo                                       -j ACCEPT
iptables -w -A ${FW_CHAIN} -p tcp  --dport \${SSH_PORT}                -j ACCEPT
iptables -w -A ${FW_CHAIN} -m conntrack --ctstate INVALID,UNTRACKED    -j DROP
iptables -w -A ${FW_CHAIN} -m conntrack --ctstate ESTABLISHED,RELATED  -j ACCEPT
iptables -w -A ${FW_CHAIN} -p icmp --icmp-type echo-request -m limit --limit 10/second --limit-burst 20 -j ACCEPT
iptables -w -A ${FW_CHAIN} -p icmp --icmp-type echo-request             -j DROP
$(while IFS= read -r u; do
  [[ -n "$u" ]] && echo "iptables -A ${FW_CHAIN} -s ${u}/32 -p tcp --dport ${LANDING_PORT} -j ACCEPT"
done < <(printf '%s\n' "${transit_ips[@]+${transit_ips[@]}}" | sort -u))
iptables -w -A ${FW_CHAIN} -j DROP
iptables -w -I INPUT 1 -m comment --comment 'xray-landing-jump' -j ${FW_CHAIN}
if [ -f /proc/net/if_inet6 ] && ip6tables -L >/dev/null 2>&1 && [ "\$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 1)" != "1" ]; then
  while ip6tables -D INPUT -m comment --comment 'xray-landing-v6-jump' 2>/dev/null; do :; done
  while ip6tables -D INPUT -m comment --comment 'xray-landing-v6-swap' 2>/dev/null; do :; done
  ip6tables -w -F ${FW_CHAIN6} 2>/dev/null || true; ip6tables -X ${FW_CHAIN6} 2>/dev/null || true
  ip6tables -w -N ${FW_CHAIN6} 2>/dev/null || true
  ip6tables -w -A ${FW_CHAIN6} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ip6tables -w -A ${FW_CHAIN6} -i lo -j ACCEPT
  ip6tables -w -A ${FW_CHAIN6} -p tcp      --dport \${SSH_PORT}     -j ACCEPT
  ip6tables -w -A ${FW_CHAIN6} -p ipv6-icmp                          -j ACCEPT
  ip6tables -w -A ${FW_CHAIN6} -j DROP
  ip6tables -w -I INPUT 1 -m comment --comment 'xray-landing-v6-jump' -j ${FW_CHAIN6}
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

  # [Bugfix] 先移动节点文件到正式位置，再同步配置
  mv -f "$_tmp_node" "$_node_conf"

  if ! ( sync_xray_config ); then
    rm -f "$_node_conf" "${_staged_mgr:-}" 2>/dev/null
    _release_lock; die "Xray配置同步失败"
  fi

  if ! ( setup_firewall ); then
    rm -f "$_node_conf"
    ( sync_xray_config ) 2>/dev/null || true
    _release_lock; die "防火墙配置失败"
  fi
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

  local _bak_conf="${DEL_CONF}.bak.$(date +%s)"
  cp -f "$DEL_CONF" "$_bak_conf" 2>/dev/null || true

  if ! ( sync_xray_config ); then
    mv -f "$_bak_conf" "$DEL_CONF" 2>/dev/null || true
    _release_lock; die "Xray配置同步失败"
  fi

  if ! ( setup_firewall ); then
    mv -f "$_bak_conf" "$DEL_CONF" 2>/dev/null || true
    ( sync_xray_config ) 2>/dev/null || true
    _release_lock; die "防火墙更新失败"
  fi

  rm -f "$_bak_conf" 2>/dev/null || true
  systemctl restart "$LANDING_SVC"
  sleep 1

  # [Bugfix v3.7] 真正删除节点文件（v3.6 只删备份，从未删过实际文件）
  rm -f "${DEL_CONF}" 2>/dev/null || true
  rm -f "${DEL_CONF}.deleting" 2>/dev/null || true
  _release_lock
  success "节点已彻底删除（文件 + 防火墙规则）"
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
print(base64.b64encode(json.dumps(d, separators=(',',':')).encode()).decode())
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
    && echo -e "  ${BOLD}${CYAN}bash install_transit_v3.1.sh --import ${token}${NC}" \
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

  # [Bugfix v3.25] 清理 Xray 二进制、数据文件、用户
  rm -f "$LANDING_BIN"
  rm -rf /usr/local/share/xray-landing
  if id "$LANDING_USER" &>/dev/null; then
    userdel "$LANDING_USER" 2>/dev/null || true
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
  if [[ "${1:-}" == "--doctor" ]]; then _doctor; exit $?; fi

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
    # [Bugfix] 在 add_node 之前先创建默认 manager.conf
    mkdir -p "$MANAGER_BASE"
    cat > "$MANAGER_CONFIG" <<MCEOF
LANDING_PORT=${LANDING_PORT:-8443}
VLESS_UUID=$(python3 -c 'import uuid; print(uuid.uuid4())')
VLESS_GRPC_PORT=27580
TROJAN_GRPC_PORT=27581
VLESS_WS_PORT=27582
TROJAN_TCP_PORT=27583
CF_TOKEN=${CF_TOKEN:-}
CREATED_USER=${LANDING_USER}
MCEOF

    touch "$INSTALLED_FLAG"
    echo ""
    success "══ 落地机安装完成！══"
    add_node
  fi
}

main "$@"
