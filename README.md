# OpenClaw-Proxy / Chained-Proxy

美西 CN2 GIA 纯净透传分发系统。

## 脚本版本

| 文件 | 版本 | 说明 |
|------|------|------|
| `install_transit_v3.1.sh` | v3.20 | 中转机安装脚本（Transit） |
| `install_landing_v3.1.sh` | v3.20 | 落地机安装脚本（Landing） |
| `original/zhongzhuan.sh` | v2.50-Optimized | 原始中转机脚本 |
| `original/luodi.sh` | v2.50 | 原始落地机脚本 |

## v3.20 修复（Gemini 外部审查第二轮）

| # | 问题 | 严重性 | 说明 |
|---|------|--------|------|
| 8 | worker_rlimit_nofile 上限过高 | 中危 | 10M→1M，与 fs.nr_open 默认值对齐 |
| 9 | delete_landing_route 冗余 .meta 删除 | 低 | remove_landing_snippet 已处理 |

## v3.19 修复（Gemini 外部审查第一轮）

| # | 问题 | 严重性 | 说明 |
|---|------|--------|------|
| 1 | freedom Mux 致命错误 | ⚡致命 | Mux 只适用代理节点间，直接连接网站会 RST |
| 2 | SSH 端口 network-pre.target 动态检测 | 🔴高危 | sshd 未启动时检测必失败→改端口后重启=永久锁机 |
| 4 | iptables 高并发竞态 | 🔴高危 | 60+47 条命令全部加 -w |
| 5 | IPv6 Nginx stream 未监听 | 🟡中危 | 添加 listen [::]:PORT |
| 7 | logrotate 无大小限制 | 🟡中危 | 添加 maxsize 100M |

## v2.50 → v3.20 累计修复：30 个 bug（含 3 个致命）

## 使用方法

```bash
bash install_transit_v3.1.sh --doctor
bash install_transit_v3.1.sh --uninstall
bash install_landing_v3.1.sh --doctor
bash install_landing_v3.1.sh --uninstall
```
