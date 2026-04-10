# OpenClaw-Proxy / Chained-Proxy

美西 CN2 GIA 纯净透传分发系统。

## 脚本版本

| 文件 | 版本 | 说明 |
|------|------|------|
| `install_transit_v3.1.sh` | v3.13 | 中转机安装脚本（Transit） |
| `install_landing_v3.1.sh` | v3.13 | 落地机安装脚本（Landing） |
| `original/zhongzhuan.sh` | v2.50-Optimized | 原始中转机脚本 |
| `original/luodi.sh` | v2.50 | 原始落地机脚本 |

## v3.13 审查（无新增 bug）

经第十五轮扫描，以下问题均已防御：
- `delete_landing_route` 持有锁时调用 `setup_firewall_transit` ✓
- `do_set_port` 已验证服务启动失败并回滚 ✓
- boot 脚本检查 `disable_ipv6`，禁用时跳过 IPv6 链创建 ✓

## v3.12 修复

| # | 问题 | 说明 |
|---|------|------|
| 24 | 节点删除后 iptables 未刷新 | `delete_landing_route` 后调用 `setup_firewall_transit` |

## v3.11 修复

| # | 问题 | 说明 |
|---|------|------|
| 21 | xray-cert-alert.sh 每次登录遍历所有证书 | 改用 `find -mtime 0` |

## v3.10 修复

| # | 问题 | 说明 |
|---|------|------|
| 18 | `_mktemp` 可预测纳秒 fallback | 移除 fallback |

## v3.9

TFO 内核支持验证

## v3.8

BBR 强制原生 + SSH 证书濒死告警 + systemd CAP_NET_BIND_SERVICE

## v3.7

12. `delete_node()` 只删备份不删实际文件 | 13. `generate_nodes()` 旧版 Token 跳过 | 14. LANDING_BASE export 缺失

## v3.6（原始 11 个 bug）

1-11: trap/fd/atomic_write/recovery $$/cert-reload×3/boot hardcoded×2/Xray/nginx_reload

## 使用方法

```bash
bash install_transit_v3.1.sh --doctor     # 预检
bash install_transit_v3.1.sh --uninstall
bash install_landing_v3.1.sh --doctor
bash install_landing_v3.1.sh --uninstall
```
