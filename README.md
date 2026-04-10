# OpenClaw-Proxy / Chained-Proxy

美西 CN2 GIA 纯净透传分发系统。

## 脚本版本

| 文件 | 版本 | 说明 |
|------|------|------|
| `install_transit_v3.1.sh` | v3.9 | 中转机安装脚本（Transit） |
| `install_landing_v3.1.sh` | v3.9 | 落地机安装脚本（Landing） |
| `original/zhongzhuan.sh` | v2.50-Optimized | 原始中转机脚本 |
| `original/luodi.sh` | v2.50 | 原始落地机脚本 |

## v3.9 修复

| # | 问题 | 说明 |
|---|------|------|
| — | TFO 内核支持验证 | sysctl 写入后验证 TFO 是否真正生效，防止静默失败 |

## v3.8（基于 Gemini 建议）

| # | 优化 | 说明 |
|---|------|------|
| 1 | BBR 强制原生 | 去掉 bbrplus 追逐，添加 `default_qdisc=fq` + `tcp_congestion_control=bbr` |
| 2 | SSH 登录证书濒死告警 | `/etc/profile.d/xray-cert-alert.sh`，≤7 天红色告警 |
| 3 | systemd 限制强化 | `LimitNOFILE=soft:hard` 格式 + `CAP_NET_BIND_SERVICE` |

## v3.7 修复

12. `delete_node()` 只删备份不删实际文件
13. `generate_nodes()` 旧版 Token 静默跳过
14. `sync_xray_config` LANDING_BASE export 缺失

## v3.6 修复（原始 11 个 bug）

1. trap INT/TERM 覆盖 EXIT
2. `_release_lock` fd 泄漏
3. `atomic_write` 子 shell + mktemp 无保护
4. recovery service `$$` PID 展开（致命）
5. cert-reload chmod 静默忽略
6. cert-reload 无 sync/验证
7. cert-reload 无 flock 并发
8. boot LANDING_PORT hardcoded
9. boot transit_ips hardcoded
10. Xray 下载无重试+无 ELF 验证
11. nginx_reload 无 fallback

## 使用方法

### 中转机（Transit）

```bash
bash install_transit_v3.1.sh
bash install_transit_v3.1.sh --doctor    # 预检
bash install_transit_v3.1.sh --uninstall # 卸载
```

### 落地机（Landing）

```bash
bash install_landing_v3.1.sh
bash install_landing_v3.1.sh --doctor    # 预检
bash install_landing_v3.1.sh --uninstall # 卸载
```
