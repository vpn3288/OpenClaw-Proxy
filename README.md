# OpenClaw-Proxy / Chained-Proxy

美西 CN2 GIA 纯净透传分发系统。

## 脚本版本

| 文件 | 版本 | 说明 |
|------|------|------|
| `install_transit_v3.1.sh` | v3.6 | 中转机安装脚本（Transit） |
| `install_landing_v3.1.sh` | v3.6 | 落地机安装脚本（Landing） |
| `zhongzhuan.sh` | v2.50-Optimized | 原始中转机脚本 |
| `luodi.sh` | v2.50 | 原始落地机脚本 |

## 版本差异（v2.50 → v3.6）

### 修复的 Bug

| # | 问题 | 严重程度 |
|---|------|---------|
| 1 | trap INT/TERM 覆盖 EXIT，正常结束不清理 | 🔴 高 |
| 2 | `_release_lock` 不关闭 fd，长期运行泄漏 | 🟡 中 |
| 3 | `atomic_write` 子 shell + mktemp 无保护 | 🔴 高 |
| 4 | recovery service `$$` PID 展开，锁永远失败 | 🔴 致命 |
| 5 | cert-reload chmod 静默忽略 | 🟡 中 |
| 6 | cert-reload 无 sync/验证 | 🟡 中 |
| 7 | cert-reload 无 flock 并发保护 | 🟡 中 |
| 8 | boot 脚本 LANDING_PORT hardcoded | 🟡 中 |
| 9 | boot 脚本 transit_ips hardcoded | 🟡 中 |
| 10 | Xray 下载无重试+无 ELF 验证 | 🟡 中 |
| 11 | nginx_reload 无 4 层 fallback | 🟡 低 |

### 新增功能

- `--doctor` 预检模式（10 类 20 项诊断）
- `_mktemp` 超时+回退保护
- `atomic_write()` 函数抽象
- `LANDING_PORT` / `transit_ips` 运行时动态读取
- cert-reload sync + 完整性校验
- Xray SHA256 重试 + ELF 验证

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
