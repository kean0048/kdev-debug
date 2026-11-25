# dmesg-agent

类 [sashiko](https://sashiko.dev) 的内核日志 AI 诊断 agent。喂入 dmesg,由 LLM **三段式定位问题**(确认 / 待验证 / 已排除),对"待验证"问题**自动深度采集对应数据再核验**(需要 root 时弹密码框),每条证据与原始数据**逐字比对**,防止幻觉。

流水线(v2):

```
采集 → triage 预过滤 → 确定性预采集(prefetch) → LLM 三段分析
     → inconclusive 逐条:playbook 白名单采集(sudo 弹窗)→ LLM verdict 再核验
     → 证据逐字校验 → Markdown 报告
```

## 安装

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[ssh]"     # 需要 SSH 远程诊断时
```

## 使用

```bash
# 1) 分析离线日志(无执行器:不预采集、不深度核验)
dmesg-agent --file dmesg.txt --kernel 6.12.11+ --distro "Debian 13" -o report.md
sudo dmesg -T --color=never | dmesg-agent --file -

# 2) 本机(完整流水线:预采集 + 深度核验;读 dmesg 需 root)
sudo .venv/bin/dmesg-agent
dmesg-agent --boot previous

# 3) 远程 SSH(同样支持完整流水线,深度核验在远端 sudo)
dmesg-agent --ssh user@10.0.0.5 --key ~/.ssh/id_ed25519
```

深度核验遇到需要 root 的采集命令时:终端内隐藏输入密码;无终端且在桌面环境下自动回退 `zenity`/`kdialog` 密码框;`--askpass none` 禁用(相关命令跳过)。密码只存进程内存。

常用选项:`--no-deep`(跳过深度核验)、`--no-prefetch`、`--max-verify N`、`--no-triage`、`--json`、`--askpass auto|terminal|gui|none`、`--max-tokens`。

### 源码关联(v3)

有内核源码树(git)时,日志里的调用栈会被**确定性**解析为函数源码:

```bash
export DMESG_AGENT_KERNEL_SRC=/path/to/linux-src   # 或 --kernel-src
dmesg-agent --file dmesg.txt --kernel-src /works/Linux-debugs/linux-src
```

流程:提取 `func+0x…[module]` 符号 → 函数定义索引(首次构建后缓存于 `~/.cache/dmesg-agent/`,随树 HEAD 失效)→ 函数体(≤120 行)+ 文件近期提交 → 注入模型上下文并附在报告。源码树版本与运行内核不一致时报告会标注"可能有偏移"。

## LLM 后端

任意 OpenAI 兼容 API。默认 `http://192.168.1.70:8080`,可用环境变量 `OPENAI_BASE_URL`、`OPENAI_MODEL`、`OPENAI_API_KEY` 覆盖,或直接 `--base-url http://host:port`。

## 设计(借鉴 sashiko 工程思路)

- **三段式路由**:模型必须把判断分成 `findings`(证据充分)/ `inconclusive_concerns`(带 `verification_question`,写明还缺什么数据)/ `dismissed_concerns`(必须给逐字反证,无证据不许排除)
- **prefetch**:初始分析前按 triage 命中的签名**确定性地**采集系统状态(无 sudo、限 20K 字符),消除模型盲猜
- **深度核验**:对每条待验证问题,按子系统的**声明式白名单 playbook**(`playbooks.py`)采集专业数据(SMART、网卡错包、历史 journal、hwmon……),模型用新数据下 confirmed/dismissed/inconclusive 最终判决;`--max-verify` 限总量
- **模型不可执行命令**:日志/模型输出的任何"命令建议"都不执行,只跑 playbook 白名单(防日志注入)
- **校验回灌重试**:JSON 不合法或证据引用找不到时,把精确违规列表回灌给模型重试一次(带预算,不无限循环)
- **verify 防幻觉**:每条证据与语料(原始日志 + 采集输出)归一化逐字比对,行号偏差自动纠正,通过率写进报告头
- 模型未返回合法 JSON 时:剥围栏、截大括号、修复截断,全部失败则呈现原始输出(退出码 4)

## 开发

```bash
.venv/bin/python -m pytest tests/ -q
```

## 调研结论(本地项目与外部工具)

**本地(评估后不自动集成)**:
- `/works/Develop/AI/KernelDebugger`(funchook 式内核 inline hook 框架):原型级、改写内核代码段、有崩机风险、内核版本窗口窄。只适合作为**隔离复现 VM** 里的"假设验证器"(LLM 生成 hook 模板→加载→带值日志回流本工具),不进生产 playbook。
- `/works/Develop/AI/kprobe_inspect`(指令级 kprobe 批量注册脚手架):无 LICENSE/module_init、多处错误分支 bug,定位是内核开发者手动调试工具,与"白名单命令采集"模型不匹配,不集成。

**外部(已借鉴)**:syzkaller `pkg/report`(triage 签名扩充)、sashiko designs/(prefetch/guardrails/三段路由/反馈重试)。
**外部(后续候选)**:drgn(活内核数据结构取证,需安装)、bpftrace/perf-tools(动态探针,需安装)、crash+mcp-crash(vmcore 分支)、intel/linux-kernel-oops(What/How/Where 协议)、live-kbench(syzbot 回归评测集)、semcode/LKML lore 检索(已知修复查询,需联网)、hotkdump debuginfod(vmlinux 自动获取,需先 `make` 出 vmlinux 才能接 `scripts/faddr2line`)。

## 已知限制 / 后续方向

- 本机模式在无 root 环境拿不到 dmesg(可 `sudo dmesg | dmesg-agent --file -`)
- `--file` 离线模式无执行器:无 prefetch、无深度核验
- 后续:call trace ↔ 内核源码关联、多轮追问、playbook 随 issue 扩充
- 本地小模型偶尔把行号偏移 1,verify 已自动纠正并标注
