# OpenClaw-Proxy / Chained-Proxy

美西 CN2 GIA 纯净透传分发系统。

## 脚本版本

| 文件 | 版本 | 说明 |
|------|------|------|
| `install_transit_v3.1.sh` | v3.12 | 中转机安装脚本（Transit） |
| `install_landing_v3.1.sh` | v3.12 | 落地机安装脚本（Landing） |
| `original/zhongzhuan.sh` | v2.50-Optimized | 原始中转机脚本 |
| `original/luodi.sh` | v2.50 | 原始落地机脚本 |

## v3.12 修复

| # | 问题 | 说明 |
|---|------|------|
| 22 | `purge_all` 卸载后 profile.d 未清理 | landing 已有清理；transit 无此文件无需处理 |
| 24 | delete_node 后 iptables 未刷新 | 节点删除后调用 `setup_firewall_transit` 立即重刷防火墙 |

## v3.11 修复

| # | 问题 | 说明 |
|---|------|------|
| 21 | xray-cert-alert.sh 每次登录遍历所有证书 | 改用 `find -mtime 0` 仅检查当天更新的证书 |

## v3.10 修复

| # | 问题 | 说明 |
|---|------|------|
| 18 | `_mktemp` 可预测纳秒 fallback | 移除 fallback，失败直接报错 |

## v3.9 修复

| # | 问题 | 说明 |
|---|------|------|
| — | TFO 内核支持验证 | sysctl 后验证 TFO 生效 |

## v3.8

BBR 强制原生 + SSH 证书濒死告警 + systemd CAP_NET_BIND_SERVICE

## v3.7

12. `delete_node()` 只删备份不删实际文件
13. `generate_nodes()` 旧版 Token 静默跳过
14. `sync_xray_config` LANDING_BASE export 缺失

## v3.6（原始 11 个 bug）

1. trap INT/TERM 覆盖 EXIT | 2. `_release_lock` fd 泄漏 | 3. `atomic_write` 子 shell mktemp | 4. recovery `$$` PID 展开（致命）| 5. cert-reload chmod 忽略 | 6. cert-reload 无 sync | 7. cert-reload 无 flock | 8. boot LANDING_PORT hardcoded | 9. boot transit_ips hardcoded | 10. Xray 无重试+无 ELF 验证 | 11. nginx_reload 无 fallback

## 使用方法

```bash
bash install_transit_v3.1.sh --doctor     # 中转机预检
bash install_transit_v3.1.sh --uninstall
bash install_landing_v3.1.sh --doctor     # 落地机预检
bash install_landing_v3.1.sh --uninstall
```
