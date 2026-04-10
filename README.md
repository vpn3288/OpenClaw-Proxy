# OpenClaw-Proxy / Chained-Proxy

美西 CN2 GIA 纯净透传分发系统。

## 脚本版本

| 文件 | 版本 | 说明 |
|------|------|------|
| `install_transit_v3.1.sh` | v3.19 | 中转机安装脚本（Transit） |
| `install_landing_v3.1.sh` | v3.19 | 落地机安装脚本（Landing） |
| `original/zhongzhuan.sh` | v2.50-Optimized | 原始中转机脚本 |
| `original/luodi.sh` | v2.50 | 原始落地机脚本 |

## v3.19 修复（Gemini 外部审查）

| # | 问题 | 严重性 | 说明 |
|---|------|--------|------|
| 1 | freedom Mux 致命错误 | 致命 | Mux 只适用于代理节点间，直接连接不应启用 smux |
| 2 | SSH 端口 network-pre.target 动态检测 | 高危 | sshd 未启动时检测必失败，回退到旧端口导致锁机 |
| 4 | iptables 高并发竞态 | 高危 | 所有防火墙命令添加 -w（等锁防竞态） |
| 5 | IPv6 Nginx stream 未监听 | 中危 | 双栈 VPS 可添加 `listen [::]:PORT` |
| 7 | logrotate 无大小限制 | 中危 | 添加 maxsize 100M 防日志炸弹 |

**rejectUnknownSni + fallbacks 架构评估**：两者作用于不同层（前者 TLS 层拒绝未知 SNI，后者在 SNI 有效时路由不同协议），互补非冗余，保留。

**transit 45231 fallback 不是死代码**：处理有效 SNI 但不匹配主服务的流量，与 rejectUnknownSni 各司其职。

## v3.18 致命修复

recovery service 环境变量未传递（${CERT_BASE} 等在 bash readonly 中定义，systemd service 完全未获取）

## v2.50 → v3.19 累计修复：28 个 bug（含 3 个致命）

## 使用方法

```bash
bash install_transit_v3.1.sh --doctor
bash install_transit_v3.1.sh --uninstall
bash install_landing_v3.1.sh --doctor
bash install_landing_v3.1.sh --uninstall
```
