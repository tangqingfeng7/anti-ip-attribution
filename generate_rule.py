import os
import re
import yaml

# 读取文件
with open("./rules.yaml", "r", encoding="utf-8") as file:
    rules = file.read()

# 创建文件夹
os.makedirs("./rules", exist_ok=True)


def read_cloudmusic_payload():
    """读取网易云音乐独立规则"""
    with open("./CloudMusic.yaml", "r", encoding="utf-8") as file:
        config = yaml.safe_load(file)
    payload = config.get("payload", [])
    rules = []
    for rule in payload:
        if not isinstance(rule, str):
            continue
        rule = rule.strip()
        if not rule:
            continue
        if rule.startswith(("IP-CIDR,", "IP-CIDR6,")) and rule.endswith(",no-resolve"):
            rule = rule[: -len(",no-resolve")]
        rules.append(rule)
    return rules

# 正则
regex = r"# ======= (.*?) ======= #"
result = re.split(regex, rules)

# 拆分 yaml文件
for i in range(1, len(result), 2):
    ruleName = result[i]
    ruleContent = result[i + 1]

    # 创建对应名称的文件
    filePath = f"./rules/{ruleName}.yaml"

    # 添加原始文件内容
    splitYAML = f"{result[0]}\n# ======= {ruleName} ======= #\n{ruleContent}"

    # 写入文件
    with open(filePath, "w", encoding="utf-8") as file:
        file.write(splitYAML)


# 额外同步网易云音乐独立规则，避免 rules.yaml 中重复维护
cloudmusic_rules = read_cloudmusic_payload()
cloudmusic_content = "        # 本节规则来源于 CloudMusic.yaml，由脚本自动同步。\n"
for rule in cloudmusic_rules:
    cloudmusic_content += f"        - {rule}\n"

cloudmusic_yaml = (
    f"{result[0]}\n# ======= 网易云音乐 ======= #\n{cloudmusic_content}"
)
with open("./rules/网易云音乐.yaml", "w", encoding="utf-8") as file:
    file.write(cloudmusic_yaml)
