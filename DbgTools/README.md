# DbgTools — GeptHooks 调试工具集

崩溃取证与离线分析工具。配合 [README_AGENT.md](../README_AGENT.md) §10-11（验证协议与判例速查）使用。

## 工具索引

| 工具 | 运行环境 | 用途 |
|---|---|---|
| `gept_bb_parse.ps1` | Windows PowerShell 5.1+（实机） | **主力**：深度解析 MEMORY.DMP——黑匣子（GEPTBB01/02）+ 事件环全局 seq 重组（免疫 DMP 物理散列）+ 行环重组 + bugcheck 头/EXCEPTION_RECORD + 崩溃时 CR3 取证。输出人类可读报告到桌面 |
| `gept_bb_parse.py` | python3（跨平台） | 同类黑匣子解析（沙箱/Linux 侧；只解黑匣子段，不做环重组） |
| `ntkit.py` | python3 + capstone | 离线分析 ntoskrnl.exe（须与崩溃机器同构建）：RVA→函数识别（.pdata 边界+导出表）、反汇编窗口、直接调用方扫描、KeBugCheckEx(码) raise 站点分析 |
| `make_test_dmp.py` | python3 | 合成 DMP 回归测试：`gept_bb_parse` 改动后 `python3 make_test_dmp.py t.dmp && python3 gept_bb_parse.py t.dmp` 应全绿 |

## 典型工作流

1. **崩溃了**（Debug 构建）：拿 `C:\Windows\MEMORY.DMP`
2. 实机跑 `powershell -ExecutionPolicy Bypass -File gept_bb_parse.ps1` → 桌面 `gept_bb.txt` 报告
3. 报告末尾事件 = 死亡点附近；对照 [README_AGENT.md](../README_AGENT.md) §2 红线铁律与 §8 判例表定位根因
4. 需要 nt 符号级分析时：`ntkit.py -m <同构建ntoskrnl.exe> at <nt+RVA>` / `callers` / `bugcheck 0x50`
5. **环是真相**：文件日志最后一行 ≠ 真实死亡点（异步落盘滞后）

## 依赖

- `gept_bb_parse.ps1`：零依赖（纯 ASCII，PS5.1 兼容）
- `gept_bb_parse.py` / `make_test_dmp.py`：纯标准库
- `ntkit.py`：`pip install capstone`

## 维护契约

- **环事件 tag 语义与 `GeptHooks/common.h` 的环 tag 注释逐条同步**——新增/退役 tag 时必须同改两个解析器的 tag 表（v7 已对齐，退役 tag 保留判读旧 DMP）
- 黑匣子布局（`GEPT_BLACKBOX`）变更时同步两个解析器的偏移常量
- `ntkit.py` 分析的 ntoskrnl 必须与崩溃机同构建（对照 DMP 模块清单的 SizeOfImage）
