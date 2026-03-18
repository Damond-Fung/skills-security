# skills-security

skills-security 是一个本地优先（Local-First）的 Skill 安全评估工具，用于扫描 Skills 目录中的潜在风险模式，适配 Trae、OpenClaw、Claude Code（cc）、Cursor 等生态。

## 拉取后能否直接用

可以。只要仓库根目录包含 `main.py`、`SKILL.md`、`skill.json`，拉取后即可直接运行，无需额外依赖包。

## 快速开始

1. 拉取仓库

```bash
git clone <你的仓库地址>
cd <仓库目录>
```

2. 扫描目标 Skills 目录

```bash
py -3 main.py <skills_dir>
```

示例：

```bash
py -3 main.py d:\path\to\skills
```

3. 指定报告输出目录（可选）

```bash
py -3 main.py <skills_dir> <output_dir>
```

示例：

```bash
py -3 main.py d:\path\to\skills d:\path\to\output
```

## 项目结构

```text
skills-security/
├── main.py
├── SKILL.md
├── skill.json
├── README.md
├── LICENSE.txt
├── checklists/
├── docs/
├── examples/
└── templates/
```

## 输出说明

- `skill_basic_info`：被评估 Skill 基本信息（名称/类型/路径）
- `skill_basic_info[].platforms`：每个 Skill 的平台兼容列表
- `detection_items`：命中的检测项目清单
- `risk_counts`：高/中/低风险统计
- `scanned_files`：扫描文件数
- `findings`：风险发现列表
- `summary`：结果摘要
- `report_files.json`：JSON 报告路径
- `report_files.md`：Markdown 报告路径
- `report_files.summary`：汇总文本路径

Markdown 报告包含：

- 被评估 Skill 基本信息
- 检测项目
- 中高低风险明细
- 整改建议

## 规则范围（当前版本）

- 高风险：`rm -rf`、`eval(...)`、硬编码密钥模式
- 中风险：`child_process.exec/execSync(...)`
- 低风险：`http://` 明文链接

## 发布建议

- 保持仓库根目录即 Skill 根目录
- 不提交本地产物：`auto_reports/`、`.history/`、`__pycache__/`
- 如需在平台导入，直接使用仓库目录或打包 zip（根目录需保持为 `skills-security/`）
