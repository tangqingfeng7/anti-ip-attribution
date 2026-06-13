# anti-ip-attribution

针对部分网站显示 IP 归属地的流量分流规则

项目作者无法保证配置文件一定能起到作用，有可能会触发账号风控。

## 使用之前

请在使用前详细阅读`rules.yaml`与`CloudMusic.yaml`内容，内部注释包含部分可选规则，请酌情参考。

强烈建议 Fork 自己的一份配置文件，不要直接使用最新的。

## 自动生成的配置文件

|                                     文件                                     |                                                                              用途                                                                              |
| :--------------------------------------------------------------------------: | :------------------------------------------------------------------------------------------------------------------------------------------------------------: |
|                   ~~[parser.yaml](generated/parser.yaml)~~                   | ~~适用于 Clash for Windows 的配置文件预处理功能，详见[文档备份](https://web.archive.org/web/20231015024315/https://docs.cfw.lbyczf.com/contents/parser.html)~~ |
|              [rule-provider.yaml](generated/rule-provider.yaml)              |                            适用于 Clash 的 Rule Provider 功能，详见[mihomo 文档](https://wiki.metacubex.one/config/rule-providers/)                            |
|       [rule-provider-direct.yaml](generated/rule-provider-direct.yaml)       |                  仅包含 DIRECT 规则，适用于 Clash 的 Rule Provider 功能，详见[mihomo 文档](https://wiki.metacubex.one/config/rule-providers/)                  |
|        [rule-provider-proxy.yaml](generated/rule-provider-proxy.yaml)        |                 仅包含需要代理的规则，适用于 Clash 的 Rule Provider 功能，详见[mihomo 文档](https://wiki.metacubex.one/config/rule-providers/)                 |
|       [rule-provider-reject.yaml](generated/rule-provider-reject.yaml)       |                  仅包含 REJECT 规则，适用于 Clash 的 Rule Provider 功能，详见[mihomo 文档](https://wiki.metacubex.one/config/rule-providers/)                  |
|                      [surge.list](generated/surge.list)                      |                                                                         Surge 分流规则                                                                         |
|                [quantumultx.list](generated/quantumultx.list)                |                                                                      QuantumultX 分流规则                                                                      |
| [quantumultx-domesticsocial.list](generated/quantumultx-domesticsocial.list) |                                                       QuantumultX 分流规则，策略组名称为 DomesticSocial                                                        |

## 关于 Clash for Windows

Clash for Windows 已于 2023.11.2 (UTC+8) 删库，将不再积极支持`parser.yaml`（适用于 Clash for Windows 的配置文件预处理功能）。

如有需要，您仍可通过 [Internet Archive 的镜像](https://web.archive.org/web/20231030023222/https://github.com/Fndroid/clash_for_windows_pkg/releases)下载 Clash for Windows。若无此类特殊需求，您也可将使用的 Clash GUI 替换为[clash-verge-rev](https://github.com/clash-verge-rev/clash-verge-rev)。

## 关于自动生成

本仓库使用 GitHub Actions 从`rules.yaml`与`CloudMusic.yaml`中生成配置文件，详见`generate.py`。

## MRS 规则修改工具

`.mrs` 是 mihomo 的二进制规则集，不适合直接手写修改。仓库提供了一个小工具，用来修改可读的 YAML/text 源文件，再调用 mihomo 重新生成 `.mrs`。

启动可视化页面：

```powershell
python .\tools\mrs_server.py
```

然后打开：

```text
http://127.0.0.1:8765/
```

查看和修改已有 `.mrs`：

1. 选择 `Games.mrs`。
2. 规则类型选 `domain`。
3. 点 `导出 MRS 为文本`，会生成 `Games.mrs.txt`。
4. 在页面里编辑 `Games.mrs.txt`。
5. 输出 MRS 文件填 `Games.mrs`。
6. 点 `生成 MRS`，会重新生成并覆盖 `Games.mrs`。

示例：

```powershell
# 添加域名规则
python .\tools\mrs_tool.py add .\my-domain.yaml example.com +.example.org --behavior domain

# 删除域名规则
python .\tools\mrs_tool.py remove .\my-domain.yaml old.example --behavior domain

# 从 YAML 源文件生成 MRS
python .\tools\mrs_tool.py build .\my-domain.yaml .\my-domain.mrs --behavior domain --mihomo C:\path\to\mihomo.exe

# 添加后立即生成 MRS
python .\tools\mrs_tool.py add .\my-ip.yaml 1.1.1.0/24 --behavior ipcidr --compile .\my-ip.mrs --mihomo C:\path\to\mihomo.exe

# 把已有 MRS 导出成可编辑文本
python .\tools\mrs_tool.py dump .\Games.mrs .\Games.mrs.txt --behavior domain --mihomo C:\path\to\mihomo.exe
```

YAML 源文件格式：

```yaml
payload:
  - example.com
  - +.example.org
```

## PR & 贡献

仓库所有者和开发者的能力不能保证持续、高效维护地此仓库。如若发现改进或更好的方案，欢迎 PR。

大部分规则维护在`rules.yaml`，网易云音乐规则维护在`CloudMusic.yaml`，其余配置文件会自动生成。

如果您对项目改进有兴趣，欢迎 Email 联系我获取 Collaborator 权限。

## 使用提示

不建议使用手机客户端访问这些网站，应用可能会包含难以寻找的 API 地址获取信息。

## 免责声明

本项目仅用于学习交流，请在遵守所在地法律法规的前提下使用。

本项目记录的 API 域名地址信息可以被任何人通过开发人员工具获取，没有经过逆向工程或网络攻击，不构成入侵计算机系统。

请不要在中华人民共和国境内使用此项目。

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=SunsetMkt/anti-ip-attribution&type=Date)](https://star-history.com/#SunsetMkt/anti-ip-attribution&Date)

## Thanks to

[![Powered by DartNode](https://dartnode.com/branding/DN-Open-Source-sm.png)](https://dartnode.com "Powered by DartNode - Free VPS for Open Source")
