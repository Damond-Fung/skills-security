import json
import re
import sys
from datetime import datetime
from pathlib import Path


CHECK_ITEMS = [
    {
        "code": "CMD_RM_RF",
        "name": "危险删除命令检测",
        "severity": "high",
        "regex": re.compile(r"\brm\s+-rf\b"),
        "message": "检测到潜在破坏性删除命令",
        "remediation": "限制删除范围并加入路径白名单校验"
    },
    {
        "code": "DYN_EVAL",
        "name": "动态执行检测",
        "severity": "high",
        "regex": re.compile(r"\beval\s*\("),
        "message": "检测到动态执行代码模式",
        "remediation": "替换为显式分支逻辑，禁止直接 eval"
    },
    {
        "code": "SHELL_EXEC",
        "name": "Shell执行调用检测",
        "severity": "medium",
        "regex": re.compile(r"child_process\.(exec|execSync)\s*\("),
        "message": "检测到 shell 执行调用",
        "remediation": "改用参数化调用并增加命令白名单"
    },
    {
        "code": "HARDCODED_SECRET",
        "name": "硬编码密钥检测",
        "severity": "high",
        "regex": re.compile(r"(api[_-]?key|token|secret|password)\s*[:=]\s*['\"`].{8,}['\"`]?", re.I),
        "message": "检测到疑似硬编码密钥",
        "remediation": "改为环境变量或密钥管理服务注入"
    },
    {
        "code": "HTTP_INSECURE",
        "name": "明文HTTP调用检测",
        "severity": "low",
        "regex": re.compile(r"http://", re.I),
        "message": "检测到明文 HTTP 链接",
        "remediation": "替换为 HTTPS 并校验证书"
    }
]

TEXT_FILE_EXTS = {".md", ".txt", ".json", ".js", ".ts", ".py", ".sh", ".ps1", ".yaml", ".yml"}
IGNORE_DIRS = {"node_modules", ".git", "dist", "build", "coverage", "__pycache__"}
COMMON_PLATFORM_SET = [
    "trae",
    "claude-code",
    "cc",
    "openclaw",
    "cursor",
    "codex",
    "gemini-cli",
    "aider",
    "windsurf",
    "kilo-code",
    "augment",
    "antigravity",
    "opencode",
    "universal",
    "amp",
    "cline",
    "github-copilot",
    "kimi-code-cli",
    "warp"
]

TYPE_NAME_ZH = {
    "trae-skill": "Trae 技能",
    "claude-skill": "SKILL.md 技能",
    "json-skill": "JSON 技能",
    "node-skill": "Node 技能",
    "unknown": "未知类型"
}

PLATFORM_NAME_ZH = {
    "trae": "Trae",
    "claude-code": "Claude Code",
    "cc": "Claude Code（cc）",
    "cursor": "Cursor",
    "openclaw": "OpenClaw",
    "codex": "OpenAI Codex",
    "gemini-cli": "Gemini CLI",
    "aider": "Aider",
    "windsurf": "Windsurf",
    "kilo-code": "Kilo Code",
    "opencode": "OpenCode",
    "augment": "Augment",
    "antigravity": "Antigravity",
    "github-copilot": "GitHub Copilot",
    "kimi-code-cli": "Kimi Code CLI",
    "cline": "Cline",
    "amp": "AMP",
    "warp": "Warp",
    "universal": "通用（跨平台）"
}

SEVERITY_ZH = {"high": "高", "medium": "中", "low": "低"}


def iter_files(root: Path):
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if any(part in IGNORE_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in TEXT_FILE_EXTS:
            yield path


def parse_frontmatter_name(content: str):
    block = re.match(r"^\s*---\s*\n([\s\S]*?)\n---", content)
    if not block:
        return ""
    match = re.search(r"^name:\s*['\"]?([^\r\n'\"]+)['\"]?\s*$", block.group(1), re.M)
    return match.group(1).strip() if match else ""


def classify_skill_type(skill_dir: Path):
    if (skill_dir / "SKILL.md").exists():
        normalized_path = str(skill_dir).replace("\\", "/").lower()
        if "/.trae/skills/" in normalized_path:
            return "trae-skill"
        return "claude-skill"
    if (skill_dir / "skill.json").exists():
        return "json-skill"
    if (skill_dir / "package.json").exists():
        return "node-skill"
    return "unknown"


def infer_platforms_from_skill_md(skill_dir: Path):
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.exists():
        return set()
    content = skill_md.read_text(encoding="utf-8", errors="ignore").lower()
    keyword_map = {
        "trae": "trae",
        "claude code": "claude-code",
        "(cc)": "cc",
        " cursor ": "cursor",
        "openclaw": "openclaw",
        "codex": "codex",
        "gemini cli": "gemini-cli",
        "aider": "aider",
        "windsurf": "windsurf",
        "kilo code": "kilo-code",
        "opencode": "opencode",
        "augment": "augment",
        "antigravity": "antigravity",
        "github copilot": "github-copilot",
        "kimi code cli": "kimi-code-cli",
        "cline": "cline",
        "amp": "amp",
        "warp": "warp",
        "skill.md-style": "universal",
        "跨平台": "universal"
    }
    detected = set()
    normalized = f" {content} "
    for keyword, platform_code in keyword_map.items():
        if keyword in normalized:
            detected.add(platform_code)
    return detected


def infer_platforms(skill_dir: Path, skill_type: str):
    platforms = set()
    normalized_path = str(skill_dir).replace("\\", "/").lower()
    if "/.trae/skills/" in normalized_path:
        platforms.add("trae")
    if "/.agents/skills/" in normalized_path:
        platforms.add("universal")
    skill_json = skill_dir / "skill.json"
    if skill_json.exists():
        try:
            payload = json.loads(skill_json.read_text(encoding="utf-8"))
            for item in payload.get("platforms", []):
                value = str(item).strip().lower()
                if value:
                    platforms.add(value)
        except Exception:
            pass
    platforms.update(infer_platforms_from_skill_md(skill_dir))
    if skill_type == "trae-skill":
        platforms.add("trae")
    elif skill_type == "claude-skill":
        platforms.update(COMMON_PLATFORM_SET)
    elif skill_type == "node-skill":
        platforms.add("universal")
    if "claude-code" in platforms and "cc" in platforms:
        platforms.remove("cc")
    if not platforms:
        platforms.add("universal")
    return sorted(platforms)


def to_type_name_zh(skill_type: str):
    return TYPE_NAME_ZH.get(skill_type, skill_type)


def to_platform_name_zh(platform_code: str):
    return PLATFORM_NAME_ZH.get(platform_code, platform_code)


def format_platforms_zh(platforms):
    if not platforms:
        return "通用（跨平台）"
    return "、".join(to_platform_name_zh(item) for item in platforms)


def to_severity_zh(severity: str):
    return SEVERITY_ZH.get(severity, severity)


def read_skill_name(skill_dir: Path):
    skill_md = skill_dir / "SKILL.md"
    if skill_md.exists():
        content = skill_md.read_text(encoding="utf-8", errors="ignore")
        parsed = parse_frontmatter_name(content)
        if parsed:
            return parsed
    skill_json = skill_dir / "skill.json"
    if skill_json.exists():
        try:
            return json.loads(skill_json.read_text(encoding="utf-8")).get("name", skill_dir.name)
        except Exception:
            return skill_dir.name
    package_json = skill_dir / "package.json"
    if package_json.exists():
        try:
            return json.loads(package_json.read_text(encoding="utf-8")).get("name", skill_dir.name)
        except Exception:
            return skill_dir.name
    return skill_dir.name


def detect_skills(skills_dir: Path):
    candidates = []
    for child in skills_dir.iterdir():
        if not child.is_dir() or child.name in IGNORE_DIRS:
            continue
        if (child / "SKILL.md").exists() or (child / "skill.json").exists() or (child / "package.json").exists():
            candidates.append(child)
    if (skills_dir / "SKILL.md").exists() or (skills_dir / "skill.json").exists() or (skills_dir / "package.json").exists():
        candidates.append(skills_dir)
    normalized = sorted({item.resolve() for item in candidates})
    skills = []
    for item in normalized:
        skill_type = classify_skill_type(item)
        platforms = infer_platforms(item, skill_type)
        skills.append(
            {
                "name": read_skill_name(item),
                "path": str(item),
                "type": skill_type,
                "type_zh": to_type_name_zh(skill_type),
                "platforms": platforms,
                "platforms_zh": [
                    to_platform_name_zh(platform)
                    for platform in platforms
                ]
            }
        )
    return skills


def assess(skills_dir: Path):
    findings = []
    scanned = 0
    for file_path in iter_files(skills_dir):
        scanned += 1
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for item in CHECK_ITEMS:
            if item["regex"].search(content):
                findings.append(
                    {
                        "file": str(file_path),
                        "risk": item["severity"],
                        "check_code": item["code"],
                        "check_name": item["name"],
                        "message": item["message"],
                        "remediation": item["remediation"]
                    }
                )
    risk_counts = {"high": 0, "medium": 0, "low": 0}
    for item in findings:
        risk_counts[item["risk"]] += 1
    triggered_codes = {item["check_code"] for item in findings}
    detection_items = [
        {"code": item["code"], "name": item["name"], "severity": item["severity"]}
        for item in CHECK_ITEMS
        if item["code"] in triggered_codes
    ]
    remediation_map = {}
    severity_rank = {"high": 0, "medium": 1, "low": 2}
    for item in findings:
        key = item["check_code"]
        if key not in remediation_map:
            remediation_map[key] = {
                "severity": item["risk"],
                "check_name": item["check_name"],
                "advice": item["remediation"]
            }
    remediation = sorted(remediation_map.values(), key=lambda x: severity_rank[x["severity"]])
    return {
        "scanned_files": scanned,
        "findings": findings,
        "risk_counts": risk_counts,
        "detection_items": detection_items,
        "remediation": remediation
    }


def to_safe_filename(value: str):
    return re.sub(r'[<>:"/\\|?*]+', "_", value).strip("_") or "skills-security"


def build_markdown_report(result, skills_dir: Path):
    risk = result["risk_counts"]
    skills = result["skill_basic_info"]
    lines = [
        "# skills-security 评估报告",
        "",
        f"- 扫描目录：`{skills_dir}`",
        f"- 扫描时间：`{datetime.now().isoformat()}`",
        f"- 扫描文件：`{result['scanned_files']}`",
        f"- 高风险：`{risk['high']}`",
        f"- 中风险：`{risk['medium']}`",
        f"- 低风险：`{risk['low']}`",
        "",
        "## 被评估Skill基本信息",
        ""
    ]
    if not skills:
        lines.append("- 未识别到标准技能目录")
    else:
        lines.extend(["| 名称 | 类型 | 平台 | 路径 |", "|---|---|---|---|"])
        for item in skills:
            platform_text = format_platforms_zh(item.get("platforms", []))
            lines.append(f"| {item['name']} | {to_type_name_zh(item['type'])} | {platform_text} | `{item['path']}` |")
    lines.extend(["", "## 检测项目", ""])
    if not result["detection_items"]:
        lines.append("- 本次扫描未命中已配置检测项")
    else:
        lines.extend(["| 编码 | 项目 | 风险级别 |", "|---|---|---|"])
        for item in result["detection_items"]:
            lines.append(f"| {item['code']} | {item['name']} | {to_severity_zh(item['severity'])} |")
    lines.extend(["", "## 风险明细（中高低）", ""])
    if not result["findings"]:
        lines.append("- 未发现风险项")
    else:
        lines.extend(["| 风险级别 | 检测项目 | 问题 | 文件 |", "|---|---|---|---|"])
        for item in result["findings"]:
            file_cell = str(item["file"]).replace("|", "\\|")
            msg_cell = str(item["message"]).replace("|", "\\|")
            risk_cell = str(to_severity_zh(item["risk"])).replace("|", "\\|")
            check_cell = str(item["check_name"]).replace("|", "\\|")
            lines.append(f"| {risk_cell} | {check_cell} | {msg_cell} | `{file_cell}` |")
    lines.extend(["", "## 整改意见", ""])
    if not result["remediation"]:
        lines.append("- 当前无需整改")
    else:
        for idx, item in enumerate(result["remediation"], start=1):
            lines.append(f"{idx}. [{to_severity_zh(item['severity'])}] {item['check_name']}：{item['advice']}")
    lines.extend(["", "## 结论", "", result["summary"]])
    return "\n".join(lines)


def write_reports(result, skills_dir: Path, output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    target_name = to_safe_filename(skills_dir.name)
    json_path = output_dir / f"{target_name}_security_report.json"
    md_path = output_dir / f"{target_name}_security_report.md"
    summary_path = output_dir / "assessment_summary.txt"
    result_with_meta = {
        "generated_at": datetime.now().isoformat(),
        "skills_dir": str(skills_dir),
        **result,
        "summary": (
            f"扫描文件 {result['scanned_files']} 个，"
            f"高风险 {result['risk_counts']['high']} 个，"
            f"中风险 {result['risk_counts']['medium']} 个，"
            f"低风险 {result['risk_counts']['low']} 个"
        )
    }
    json_path.write_text(json.dumps(result_with_meta, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(build_markdown_report(result_with_meta, skills_dir), encoding="utf-8")
    summary_lines = [
        f"评估时间: {result_with_meta['generated_at']}",
        f"目标目录: {skills_dir}",
        f"扫描文件: {result_with_meta['scanned_files']}",
        f"高风险: {result_with_meta['risk_counts']['high']}",
        f"中风险: {result_with_meta['risk_counts']['medium']}",
        f"低风险: {result_with_meta['risk_counts']['low']}",
        f"JSON报告: {json_path}",
        f"Markdown报告: {md_path}"
    ]
    summary_path.write_text("\n".join(summary_lines), encoding="utf-8")
    return result_with_meta, json_path, md_path, summary_path


def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <skills_dir> [output_dir]")
        sys.exit(1)
    skills_dir = Path(sys.argv[1]).resolve()
    output_dir = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else (Path.cwd() / "auto_reports")
    if not skills_dir.exists() or not skills_dir.is_dir():
        print(json.dumps({"error": f"Invalid skills_dir: {skills_dir}"}, ensure_ascii=False))
        sys.exit(1)
    result = assess(skills_dir)
    result["skill_basic_info"] = detect_skills(skills_dir)
    result_with_meta, json_path, md_path, summary_path = write_reports(result, skills_dir, output_dir)
    result_with_meta["report_files"] = {
        "json": str(json_path),
        "md": str(md_path),
        "summary": str(summary_path)
    }
    print(json.dumps(result_with_meta, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
