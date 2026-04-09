# CN2 GIA 中转 + 落地机 一键安装脚本

> **版本：** 中转机 `v2.50-Optimized` · 落地机 `v2.50`  
> **架构：** 美西 CN2 GIA 中转机 → SNI 嗅探纯 TCP 盲传 → 美西/美东落地机  
> **协议：** VLESS-Vision · VLESS-gRPC · VLESS-WS · Trojan-TCP（四协议单端口，443 对外）  
> **隔离：** 与 mack-a / v2ray-agent 完全物理隔离，互不干扰

---

## 目录

- [架构说明](#架构说明)
- [准备工作（必读）](#准备工作必读)
- [安装步骤](#安装步骤)
  - [第一步：安装落地机](#第一步安装落地机)
  - [第二步：安装中转机](#第二步安装中转机)
- [管理菜单](#管理菜单)
  - [落地机管理](#落地机管理)
  - [中转机管理](#中转机管理)
- [命令速查](#命令速查)
- [客户端使用](#客户端使用)
- [常见问题](#常见问题)
- [卸载](#卸载)

---

## 架构说明

```
你的客户端
    │  VLESS-Vision / VLESS-gRPC / VLESS-WS / Trojan-TCP
    ▼  TCP 443
┌─────────────────────────┐
│   中转机（美西 CN2 GIA） │  ← 仅有 IPv4，密码登录
│   Nginx Stream           │
│   SNI 嗅探 → 纯 TCP 盲传 │  无证书，不解密，CPU 近零
│   无匹配 SNI → 苹果 CDN  │  ← 防主动探测 Fallback
└───────────┬─────────────┘
            │  TCP（落地机 8443 或自定义端口）
            ▼
┌─────────────────────────┐
│   落地机（美西/美东）    │  ← 普通线路，可双栈
│   Xray-core             │
│   Trojan + VLESS 协议   │
│   Let's Encrypt 真实证书│
│   iptables 仅允许中转IP │
└─────────────────────────┘
            │
            ▼  普通 HTTPS 出站
         目标网站
```

**设计特点：**

- 中转机极度轻量，只做 TCP 透传，不持有任何证书，不解密任何内容
- 落地机承担全部 TLS 终止、协议处理、DNS 解析
- iptables 白名单：落地机只接受来自中转机 IP 的连接，其余全部丢弃
- 证书通过 Cloudflare DNS API 自动申请和续期，无需开放 80 端口

---

## 准备工作（必读）

### 落地机须具备

| 项目 | 要求 |
|------|------|
| 操作系统 | Debian 10+ / Ubuntu 20.04+ / CentOS 7+（推荐 Debian/Ubuntu） |
| 权限 | root |
| 域名 | 在 **Cloudflare** 托管，**必须设为灰云（仅DNS）**，严禁开启小黄云代理 |
| CF API Token | 权限：`Zone → DNS → Edit`（仅需 DNS 编辑权限） |
| 中转机公网 IP | 安装前需提前知道中转机的公网 IPv4 |

> ⚠️ **重要：域名必须是 Cloudflare 灰云！**  
> SNI 盲传 + XTLS-Vision 架构下，开启 CF 代理（小黄云）= 节点 100% 断流，且无法恢复。

### 中转机须具备

| 项目 | 要求 |
|------|------|
| 操作系统 | Debian 10+ / Ubuntu 20.04+（推荐） |
| 权限 | root |
| 线路 | CN2 GIA，仅 IPv4 |
| 端口 | TCP 443 未被其他程序占用 |

> 脚本会自动安装所有依赖（nginx、iptables、python3 等），无需手动预装任何软件。

---

## 安装步骤

> **必须先装落地机，再装中转机。**  
> 落地机安装完成后会自动生成一条**一键导入命令**，复制到中转机执行即可完成对接。

---

### 第一步：安装落地机

在**落地机**上执行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/vpn3288/cn2gia-transit/main/install_landing_v2.50.sh)
```

脚本会依次询问以下信息：

| 提示 | 填写内容 | 示例 |
|------|---------|------|
| 落地机域名 | 在 Cloudflare 灰云的域名 | `landing.example.com` |
| Cloudflare API Token | Zone:DNS:Edit 权限的 CF Token | `abc123xyz...` |
| Trojan 密码 | 直接回车自动生成（推荐），或自填 16 位以上字母数字 | （回车） |
| 中转机公网 IP | 中转机的公网 IPv4 地址 | `1.2.3.4` |
| 落地机监听端口 | 直接回车使用默认 8443，或自定义 | （回车） |

**安装过程会自动完成：**
- 安装 Xray-core（自动下载最新版，sha256 校验）
- 通过 Cloudflare DNS API 申请 Let's Encrypt TLS 证书
- 配置 xray-landing 系统服务（独立用户、最小权限）
- 配置 iptables：仅允许中转机 IP 连入落地端口，其余全部丢弃
- 配置 acme.sh 自动续期，证书到期前自动重载 Xray

**安装完成后，终端会打印类似以下内容：**

```
╔══════════════════════════════════════════════════════════════════╗
║       请将以下信息复制至中转机脚本                               ║
╠══════════════════════════════════════════════════════════════════╣
║  落地机公网 IP     : 5.6.7.8                                     ║
║  落地机域名(SNI)   : landing.example.com                         ║
║  落地机后端端口    : 8443                                         ║
║  Trojan密码        : AbCdEf1234567890Xx                          ║
║  VLESS UUID        : xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx        ║
╠══════════════════════════════════════════════════════════════════╣
║  中转机一键导入命令：                                            ║
╚══════════════════════════════════════════════════════════════════╝

  bash install_transit_v2.50.sh --import eyJpcCI6IjUuNi43LjgiLCJ...（长串Base64）
```

> 📋 **将最后那行 `--import` 命令完整复制，备用**。

---

### 第二步：安装中转机

在**中转机**上执行（无参数，全新安装）：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/vpn3288/cn2gia-transit/main/install_transit_optimized.sh)
```

按提示确认安装后，脚本会询问：

- 录入第一台落地机配对信息（两种方式二选一）：

**方式 A：粘贴 Token（推荐，一键完成）**

当提示"增加落地机路由规则"时，选择粘贴 Token，然后粘贴第一步得到的那串 Base64 Token。

**方式 B：如果已经在中转机上，直接用 `--import` 命令**

把第一步复制的命令直接在中转机上运行：

```bash
bash install_transit_optimized.sh --import eyJpcCI6IjUuNi43LjgiLCJ...（你的Token）
```

**安装完成后，中转机会自动完成：**
- 安装 Nginx（含 stream 模块，TFO + Keepalive 优化）
- 配置 SNI 嗅探 TCP 透传：有效 SNI → 落地机，空/未匹配 SNI → 苹果 CDN（防探测）
- iptables：仅开放 SSH + TCP 443 + ICMP，其余全部 DROP
- 内核参数优化（conntrack、fd 上限、BBR 检测）

---

### 验证安装

**落地机：**
```bash
systemctl status xray-landing
tail -f /var/log/xray-landing/error.log
```

**中转机：**
```bash
bash install_transit_optimized.sh --status
tail -f /var/log/transit-manager/transit_stream_error.log
```

---

## 管理菜单

安装完成后，重新运行脚本即可进入管理菜单。

### 落地机管理

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/vpn3288/cn2gia-transit/main/install_landing_v2.50.sh)
```

菜单选项：

```
══ 落地机管理菜单 ══════════════════════════════════════════════
  1. 增加新节点（新域名 + 对应的中转机 IP）
  2. 删除指定节点
  3. 修改落地机监听端口
  4. 清除本系统所有数据（不影响 mack-a）
  5. 退出
  6. 显示所有节点 Token 与订阅链接
```

> 选择「6」可以重新查看所有节点的 Token 和订阅链接，每次换机器或需要重新导入时使用。

### 中转机管理

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/vpn3288/cn2gia-transit/main/install_transit_optimized.sh)
```

菜单选项：

```
══ 中转机管理菜单 ══════════════════════════════════════════════
  1. 增加落地机路由规则（粘贴 Token 或手动输入）
  2. 删除指定落地机路由规则
  3. 清除本系统所有数据（不影响 mack-a）
  4. 退出
  5. 显示当前所有节点及订阅链接
```

---

## 命令速查

### 落地机

| 操作 | 命令 |
|------|------|
| 安装 / 进入管理菜单 | `bash install_landing_v2.50.sh` |
| 查看运行状态 | `bash install_landing_v2.50.sh --status` |
| 修改监听端口 | `bash install_landing_v2.50.sh set-port 9443` |
| 完整卸载 | `bash install_landing_v2.50.sh --uninstall` |
| 查看错误日志 | `tail -f /var/log/xray-landing/error.log` |
| 重启服务 | `systemctl restart xray-landing` |
| 手动强制续签证书 | 进入管理菜单 → 选项 6 查看，或参考常见问题 |

### 中转机

| 操作 | 命令 |
|------|------|
| 安装 / 进入管理菜单 | `bash install_transit_optimized.sh` |
| 导入落地机（Token） | `bash install_transit_optimized.sh --import <Token>` |
| 查看运行状态 | `bash install_transit_optimized.sh --status` |
| 完整卸载 | `bash install_transit_optimized.sh --uninstall` |
| 查看错误日志 | `tail -f /var/log/transit-manager/transit_stream_error.log` |
| 查看帮助 | `bash install_transit_optimized.sh --help` |

---

## 客户端使用

### 支持的客户端

- **Windows / macOS / Linux：** v2rayN、Clash Meta（Mihomo）、NekoRay / NekoBox
- **Android：** NekoBox、v2rayNG、Clash Meta
- **iOS / macOS：** Shadowrocket、Sing-box

### 导入订阅

落地机安装完成后，终端会同时输出：

1. **逐条明文链接**（可单独复制验证）
2. **Base64 整体订阅**（一串以字母数字组成的长字符串）

将 Base64 整体订阅字符串粘贴到客户端的「添加订阅」功能即可一键导入全部协议节点。

### 协议选择建议

| 协议 | 特点 | 推荐场景 |
|------|------|---------|
| VLESS-Vision | 最强伪装，流量特征最接近真实 HTTPS | 日常使用首选，**严禁开启 Mux** |
| VLESS-gRPC | 多路复用，高并发稳定 | 多标签、下载场景 |
| VLESS-WS | WebSocket，兼容性最佳 | 特殊网络环境备用 |
| Trojan-TCP | 轻量，TLS 伪装 | 老设备或低版本客户端 |

> ⚠️ **VLESS-Vision 节点必须关闭 Mux（多路复用）！** 开启必断流。  
> 其余三个协议完全兼容 Mux，高并发场景推荐使用 VLESS-gRPC。

---

## 常见问题

### Q：安装被中断了，再次运行会怎样？

脚本内置事务回滚机制。安装中断后，脚本会自动清理半成品（停止服务、清理 iptables、删除临时文件），重新运行脚本即可从头安装，不会遇到端口冲突或配置残留问题。

---

### Q：中转机提示"443 端口已被占用"

检查是否有其他服务占用了 443：

```bash
ss -tlnp | grep :443
```

如果是 mack-a 等其他代理程序占用了 443，需要先确认该服务的 443 用途，再决定是否停用。  
本脚本与 mack-a 完全物理隔离，同一台机器不能两套同时监听 443。

---

### Q：落地机证书申请失败

常见原因及解决方法：

1. **域名 DNS 还未生效** — 等待 5~10 分钟后重试
2. **CF API Token 填写错误** — 确认 Token 权限为 `Zone → DNS → Edit`，且 Token 未过期
3. **域名开启了 CF 代理（小黄云）** — 必须切换为灰云（仅 DNS）
4. **CF Token 没有该域名的权限** — 确认 Token 的 Zone 资源包含你的域名

---

### Q：落地机服务运行正常，但无法连接

检查中转机防火墙白名单是否包含正确的落地机 IP：

```bash
# 在落地机上
bash install_landing_v2.50.sh --status
```

检查 iptables 白名单（应该包含中转机 IP）：

```bash
iptables -L XRAY-LANDING -n -v
```

---

### Q：如何给中转机新增一台落地机？

在落地机的管理菜单中选「1. 增加新节点」，填写新的域名和中转机 IP。  
安装完成后，将生成的 Token 粘贴到中转机管理菜单的「1. 增加落地机路由规则」即可。

---

### Q：如何查看已有节点的订阅链接（Token 遗忘了）？

在落地机上运行管理菜单，选择「6. 显示所有节点 Token 与订阅链接」，会重新打印所有节点的 Token 和订阅。

---

### Q：SSH 端口自动探测失败怎么办？

如果脚本提示无法探测 SSH 端口，可以通过环境变量手动指定：

```bash
detect_ssh_port_override=22 bash install_landing_v2.50.sh
# 或
detect_ssh_port_override=22 bash install_transit_optimized.sh
```

---

### Q：中转机公网 IP 无法自动获取

通过环境变量手动指定：

```bash
TRANSIT_PUBLIC_IP=1.2.3.4 bash install_transit_optimized.sh --import <Token>
```

---

### Q：脚本会影响已有的 mack-a 节点吗？

**不会。** 本套脚本与 mack-a / v2ray-agent 完全物理隔离：

- 使用独立的系统用户（`xray-landing`）
- 使用独立的安装目录（`/etc/xray-landing`、`/etc/landing_manager`）
- 使用独立的 iptables 链（`XRAY-LANDING`、`TRANSIT-MANAGER`）
- 卸载时也不影响 mack-a 的任何文件和配置

---

## 卸载

### 卸载落地机

```bash
bash install_landing_v2.50.sh --uninstall
```

输入 `DELETE` 确认后，脚本会完整清除：Xray 二进制、配置文件、证书、acme.sh 续期任务、iptables 规则、系统服务、日志文件。mack-a 不受影响。

### 卸载中转机

```bash
bash install_transit_optimized.sh --uninstall
```

输入 `DELETE` 确认后，脚本会完整清除：Nginx stream 配置、SNI 路由规则、iptables 规则、内核参数配置、日志文件。Nginx 程序本身不卸载，mack-a 不受影响。

---

## 目录结构参考

```
落地机：
/etc/xray-landing/          # 主配置目录
    config.json             # Xray 配置（自动生成，勿手动修改）
    certs/<domain>/         # TLS 证书
    acme/                   # acme.sh 证书管理
/etc/landing_manager/       # 脚本状态目录
    manager.conf            # 核心参数（UUID、端口等）真相源
    nodes/*.conf            # 各节点配对信息
/usr/local/bin/xray-landing # Xray 二进制
/var/log/xray-landing/      # 运行日志

中转机：
/etc/transit_manager/       # 脚本状态目录
    conf/*.meta             # 各落地机配对信息
/etc/nginx/stream-transit.conf  # Nginx stream 主配置
/etc/nginx/stream-snippets/ # 各落地机 SNI 路由片段
/var/log/transit-manager/   # 运行日志
```

---

## 文件命名说明

本仓库脚本文件名格式：

- 中转机：`install_transit_optimized.sh`（当前版本 v2.50-Optimized）
- 落地机：`install_landing_v2.50.sh`（当前版本 v2.50）

版本号以脚本内 `VERSION` 变量为准。脚本启动时会自动检测 GitHub 最新版本，若有更新会提示重新下载。
