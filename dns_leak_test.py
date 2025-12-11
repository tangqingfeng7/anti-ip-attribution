#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DNS 泄露检测脚本
检测你的 DNS 请求是否通过代理，还是直接暴露给 ISP
"""

import socket
import requests
import json
import random
import string
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed

# 禁用 SSL 警告
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
requests.packages.urllib3.disable_warnings()

# 颜色输出
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_banner():
    """打印横幅"""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════╗
║                   DNS 泄露检测工具                         ║
║              DNS Leak Test Script v1.0                    ║
╚═══════════════════════════════════════════════════════════╝
{Colors.RESET}"""
    print(banner)

def get_public_ip():
    """获取公网 IP"""
    services = [
        'https://api.ipify.org?format=json',
        'https://ipinfo.io/json',
        'https://api.ip.sb/jsonip',
        'https://httpbin.org/ip',
        'https://myip.ipip.net/json',
        'https://ip.useragentinfo.com/json',
        'https://api.myip.la/cn?json',
        'http://ip-api.com/json/',
    ]
    
    for service in services:
        try:
            resp = requests.get(service, timeout=5, verify=False)
            data = resp.json()
            ip = data.get('ip') or data.get('origin') or data.get('query')
            if ip:
                return ip.split(',')[0].strip()
        except:
            continue
    return None

def get_ip_info(ip):
    """获取 IP 地理位置信息"""
    try:
        resp = requests.get(f'https://ipinfo.io/{ip}/json', timeout=5, verify=False)
        return resp.json()
    except:
        try:
            resp = requests.get(f'https://ip-api.com/json/{ip}', timeout=5, verify=False)
            data = resp.json()
            return {
                'ip': data.get('query'),
                'city': data.get('city'),
                'region': data.get('regionName'),
                'country': data.get('country'),
                'org': data.get('isp'),
            }
        except:
            return {'ip': ip}

def test_dns_leak_bash():
    """使用 bash.ws API 检测 DNS 泄露"""
    print(f"\n{Colors.BLUE}[*] 使用 bash.ws 检测 DNS 服务器...{Colors.RESET}")
    
    try:
        # 获取测试 ID
        resp = requests.get('https://bash.ws/dnsleak/test/id', timeout=10, verify=False)
        test_id = resp.text.strip()
        
        if not test_id:
            return None
        
        # 生成随机子域名并查询，触发 DNS 请求
        for i in range(10):
            domain = f"{i}.{test_id}.bash.ws"
            try:
                socket.gethostbyname(domain)
            except:
                pass
            time.sleep(0.1)
        
        # 等待服务器记录
        time.sleep(2)
        
        # 获取结果
        resp = requests.get(f'https://bash.ws/dnsleak/test/{test_id}?json', timeout=10, verify=False)
        return resp.json()
    except Exception as e:
        print(f"{Colors.RED}[!] bash.ws 检测失败: {e}{Colors.RESET}")
        return None

def test_dns_leak_dnsleaktest():
    """使用 dnsleaktest.com 检测"""
    print(f"\n{Colors.BLUE}[*] 使用 dnsleaktest.com 检测 DNS 服务器...{Colors.RESET}")
    
    try:
        # 生成随机 ID
        random_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
        
        # 触发 DNS 查询
        for i in range(1, 6):
            domain = f"{random_id}-{i}.dnsleaktest.com"
            try:
                socket.gethostbyname(domain)
            except:
                pass
            time.sleep(0.2)
        
        time.sleep(2)
        
        # 获取结果
        resp = requests.get(f'https://dnsleaktest.com/api/results/{random_id}', timeout=10, verify=False)
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        print(f"{Colors.RED}[!] dnsleaktest.com 检测失败: {e}{Colors.RESET}")
    return None

def is_fake_ip(ip):
    """检查是否是 Clash fake-ip"""
    # 常见的 fake-ip 范围
    fake_ip_ranges = [
        ('198.18.', '198.19.'),      # 198.18.0.0/15
        ('28.', ),                    # 28.0.0.0/8 (部分配置使用)
        ('10.', ),                    # 部分使用私有 IP 段
    ]
    
    for prefixes in fake_ip_ranges:
        if any(ip.startswith(prefix) for prefix in prefixes):
            return True
    return False

def is_private_ip(ip):
    """检查是否是私有 IP"""
    private_prefixes = ['10.', '172.16.', '172.17.', '172.18.', '172.19.',
                        '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                        '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                        '172.30.', '172.31.', '192.168.', '127.', '0.']
    return any(ip.startswith(prefix) for prefix in private_prefixes)

def test_dns_via_known_resolvers():
    """通过解析已知 DNS 服务的域名来推断使用的 DNS"""
    print(f"\n{Colors.BLUE}[*] 分析 DNS 解析结果...{Colors.RESET}")
    
    # 这些域名的 IP 如果被污染会返回错误的地址
    test_cases = [
        ('google.com', ['142.', '172.217.', '216.58.', '74.125.', '173.194.', '64.233.', '108.177.', '142.250.']),
        ('facebook.com', ['31.13.', '157.240.', '179.60.', '185.60.']),
        ('twitter.com', ['104.244.', '192.133.']),
        ('youtube.com', ['142.250.', '172.217.', '216.58.', '74.125.']),
    ]
    
    dns_info = {
        'fake_ip': [],
        'possibly_clean': [],
        'possibly_polluted': [],
    }
    
    for domain, expected_prefixes in test_cases:
        try:
            ip = socket.gethostbyname(domain)
            
            # 检查是否是 fake-ip
            if is_fake_ip(ip):
                dns_info['fake_ip'].append({
                    'domain': domain,
                    'ip': ip,
                    'status': 'fake-ip',
                    'note': 'Clash fake-ip 模式正常'
                })
            # 检查是否是预期的真实 IP
            elif any(ip.startswith(prefix) for prefix in expected_prefixes):
                dns_info['possibly_clean'].append({
                    'domain': domain,
                    'ip': ip,
                    'status': 'clean'
                })
            # 检查是否是私有 IP（可能是其他代理）
            elif is_private_ip(ip):
                dns_info['fake_ip'].append({
                    'domain': domain,
                    'ip': ip,
                    'status': 'private',
                    'note': '私有 IP，可能是代理返回'
                })
            else:
                dns_info['possibly_polluted'].append({
                    'domain': domain,
                    'ip': ip,
                    'expected': expected_prefixes,
                    'status': 'polluted'
                })
        except Exception as e:
            dns_info['possibly_polluted'].append({
                'domain': domain,
                'error': str(e),
                'status': 'error'
            })
    
    return dns_info

def test_dns_leak_ipleak():
    """使用 ipleak.net API 检测"""
    print(f"\n{Colors.BLUE}[*] 使用 ipleak.net 检测 DNS 服务器...{Colors.RESET}")
    
    try:
        resp = requests.get('https://ipleak.net/json/', timeout=10, verify=False)
        return resp.json()
    except Exception as e:
        print(f"{Colors.RED}[!] ipleak.net 检测失败: {e}{Colors.RESET}")
        return None

def test_dns_leak_mullvad():
    """使用 mullvad.net 检测"""
    print(f"\n{Colors.BLUE}[*] 使用 mullvad.net 检测 DNS 服务器...{Colors.RESET}")
    
    try:
        resp = requests.get('https://am.i.mullvad.net/json', timeout=10, verify=False)
        data = resp.json()
        if data:
            return {
                'ip': data.get('ip'),
                'country': data.get('country'),
                'city': data.get('city'),
                'org': data.get('organization'),
                'mullvad_exit': data.get('mullvad_exit_ip', False),
                'blacklisted': data.get('blacklisted', {})
            }
    except Exception as e:
        print(f"{Colors.RED}[!] mullvad.net 检测失败: {e}{Colors.RESET}")
    return None

def test_direct_dns():
    """测试常见域名的 DNS 解析"""
    print(f"\n{Colors.BLUE}[*] 测试 DNS 解析...{Colors.RESET}")
    
    test_domains = [
        'google.com',
        'facebook.com', 
        'twitter.com',
        'youtube.com',
        'github.com',
        'baidu.com',
        'qq.com',
        'bilibili.com',
    ]
    
    results = []
    for domain in test_domains:
        try:
            start = time.time()
            ip = socket.gethostbyname(domain)
            elapsed = (time.time() - start) * 1000
            results.append({
                'domain': domain,
                'ip': ip,
                'time_ms': round(elapsed, 2),
                'success': True
            })
        except Exception as e:
            results.append({
                'domain': domain,
                'error': str(e),
                'success': False
            })
    
    return results

def check_china_dns_servers(dns_servers):
    """检查是否使用了中国的 DNS 服务器"""
    china_keywords = ['china', 'cn', '中国', 'alibaba', 'aliyun', 'tencent', 
                      'baidu', 'dnspod', '114dns', 'unicom', 'telecom', 
                      'chinamobile', 'cmcc', 'chinanet', '电信', '联通', '移动']
    
    china_dns = []
    foreign_dns = []
    
    for dns in dns_servers:
        ip = dns.get('ip', '')
        org = dns.get('org', '').lower() if dns.get('org') else ''
        country = dns.get('country', '').lower() if dns.get('country') else ''
        country_name = dns.get('country_name', '').lower() if dns.get('country_name') else ''
        
        is_china = False
        if country in ['cn', 'china'] or country_name in ['china', '中国']:
            is_china = True
        elif any(kw in org for kw in china_keywords):
            is_china = True
            
        if is_china:
            china_dns.append(dns)
        else:
            foreign_dns.append(dns)
    
    return china_dns, foreign_dns

def print_dns_results(dns_servers, title="DNS 服务器"):
    """打印 DNS 服务器信息"""
    if not dns_servers:
        print(f"{Colors.YELLOW}  未检测到 {title}{Colors.RESET}")
        return
        
    print(f"\n{Colors.PURPLE}{Colors.BOLD}  {title} ({len(dns_servers)} 个):{Colors.RESET}")
    
    for i, dns in enumerate(dns_servers, 1):
        ip = dns.get('ip', 'N/A')
        country = dns.get('country_name') or dns.get('country', 'N/A')
        org = dns.get('org') or dns.get('isp', 'N/A')
        
        print(f"    {i}. {Colors.CYAN}{ip:18}{Colors.RESET} | {country:15} | {org}")

def main():
    print_banner()
    
    # 1. 获取公网 IP
    print(f"\n{Colors.BLUE}[*] 正在获取公网 IP...{Colors.RESET}")
    public_ip = get_public_ip()
    
    if public_ip:
        ip_info = get_ip_info(public_ip)
        print(f"\n{Colors.GREEN}{Colors.BOLD}  你的公网 IP:{Colors.RESET}")
        print(f"    IP: {Colors.CYAN}{public_ip}{Colors.RESET}")
        print(f"    位置: {ip_info.get('city', 'N/A')}, {ip_info.get('region', 'N/A')}, {ip_info.get('country', 'N/A')}")
        print(f"    ISP/组织: {ip_info.get('org', 'N/A')}")
    else:
        print(f"{Colors.RED}[!] 无法获取公网 IP{Colors.RESET}")
    
    # 2. DNS 解析测试
    dns_results = test_direct_dns()
    print(f"\n{Colors.GREEN}{Colors.BOLD}  DNS 解析测试结果:{Colors.RESET}")
    for result in dns_results:
        if result['success']:
            status = f"{Colors.GREEN}✓{Colors.RESET}"
            info = f"{result['ip']:18} ({result['time_ms']}ms)"
        else:
            status = f"{Colors.RED}✗{Colors.RESET}"
            info = f"{Colors.RED}{result['error']}{Colors.RESET}"
        print(f"    {status} {result['domain']:20} → {info}")
    
    # 3. DNS 污染分析
    pollution_result = test_dns_via_known_resolvers()
    if pollution_result:
        # 显示 fake-ip 结果
        if pollution_result['fake_ip']:
            print(f"\n{Colors.GREEN}{Colors.BOLD}  ✓ Fake-IP 模式检测:{Colors.RESET}")
            for item in pollution_result['fake_ip']:
                domain = item.get('domain', 'N/A')
                ip = item.get('ip', 'N/A')
                note = item.get('note', '')
                print(f"    {Colors.GREEN}✓{Colors.RESET} {domain:20} → {Colors.CYAN}{ip}{Colors.RESET}  ({note})")
        
        # 显示正常解析
        if pollution_result['possibly_clean']:
            print(f"\n{Colors.GREEN}{Colors.BOLD}  ✓ 正常 DNS 解析:{Colors.RESET}")
            for item in pollution_result['possibly_clean']:
                domain = item.get('domain', 'N/A')
                ip = item.get('ip', 'N/A')
                print(f"    {Colors.GREEN}✓{Colors.RESET} {domain:20} → {Colors.CYAN}{ip}{Colors.RESET}")
        
        # 显示可能被污染的
        if pollution_result['possibly_polluted']:
            print(f"\n{Colors.YELLOW}{Colors.BOLD}  ⚠️  可能的 DNS 污染:{Colors.RESET}")
            for item in pollution_result['possibly_polluted']:
                domain = item.get('domain', 'N/A')
                ip = item.get('ip', item.get('error', 'N/A'))
                print(f"    {Colors.RED}✗{Colors.RESET} {domain:20} → {ip}")
                if 'expected' in item:
                    print(f"      预期 IP 段: {', '.join(item['expected'][:3])}...")
            
            # 给出建议
            print(f"\n{Colors.YELLOW}  💡 可能原因:{Colors.RESET}")
            print(f"      1. DNS 缓存 - 尝试运行: ipconfig /flushdns")
            print(f"      2. fake-ip 范围配置不是 198.18.0.0/16")
            print(f"      3. DNS 请求绕过了代理")
            print(f"      4. 真实的 DNS 污染")
        
        # 如果全部正常
        if not pollution_result['possibly_polluted'] and (pollution_result['fake_ip'] or pollution_result['possibly_clean']):
            print(f"\n{Colors.GREEN}  ✓ DNS 解析正常！{Colors.RESET}")
    
    # 4. DNS 泄露检测
    dns_servers = []
    
    # 使用 bash.ws
    bash_result = test_dns_leak_bash()
    if bash_result and isinstance(bash_result, list):
        for item in bash_result:
            if item.get('type') == 'dns':
                dns_servers.append(item)
    
    # 使用 dnsleaktest.com
    dnsleaktest_result = test_dns_leak_dnsleaktest()
    if dnsleaktest_result and isinstance(dnsleaktest_result, list):
        dns_servers.extend(dnsleaktest_result)
    
    # 使用 ipleak.net
    ipleak_result = test_dns_leak_ipleak()
    if ipleak_result and ipleak_result.get('dns_servers'):
        dns_servers.extend(ipleak_result['dns_servers'])
    
    # 使用 mullvad
    mullvad_result = test_dns_leak_mullvad()
    if mullvad_result:
        print(f"\n{Colors.GREEN}{Colors.BOLD}  Mullvad 检测结果:{Colors.RESET}")
        print(f"    IP: {Colors.CYAN}{mullvad_result.get('ip', 'N/A')}{Colors.RESET}")
        print(f"    位置: {mullvad_result.get('city', 'N/A')}, {mullvad_result.get('country', 'N/A')}")
        print(f"    组织: {mullvad_result.get('org', 'N/A')}")
    
    # 去重
    seen_ips = set()
    unique_dns = []
    for dns in dns_servers:
        ip = dns.get('ip')
        if ip and ip not in seen_ips:
            seen_ips.add(ip)
            unique_dns.append(dns)
    
    # 4. 分析结果
    if unique_dns:
        china_dns, foreign_dns = check_china_dns_servers(unique_dns)
        
        print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}  DNS 泄露检测结果{Colors.RESET}")
        print(f"{'='*60}")
        
        print_dns_results(china_dns, "🇨🇳 中国 DNS 服务器")
        print_dns_results(foreign_dns, "🌍 国外 DNS 服务器")
        
        # 判断是否泄露
        print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}  结论{Colors.RESET}")
        print(f"{'='*60}")
        
        if china_dns and not foreign_dns:
            print(f"""
  {Colors.RED}{Colors.BOLD}⚠️  DNS 泄露风险: 高{Colors.RESET}
  {Colors.RED}你的 DNS 请求全部通过中国 DNS 服务器解析！{Colors.RESET}
  
  这意味着:
    - 你的真实 IP 位置可能被暴露
    - ISP 可以看到你访问的所有域名
    - IP 归属地伪装可能无效
    
  建议:
    - 检查代理软件的 DNS 设置
    - 确保启用了 DNS 加密 (DoH/DoT)
    - 使用 fake-ip 模式
""")
        elif china_dns and foreign_dns:
            print(f"""
  {Colors.YELLOW}{Colors.BOLD}⚠️  DNS 泄露风险: 中{Colors.RESET}
  {Colors.YELLOW}检测到同时使用中国和国外 DNS 服务器{Colors.RESET}
  
  可能原因:
    - DNS 分流配置不完整
    - 部分请求绕过了代理
    
  建议:
    - 检查 DNS 分流规则
    - 确认需要代理的域名走代理 DNS
""")
        else:
            print(f"""
  {Colors.GREEN}{Colors.BOLD}✓ DNS 无泄露{Colors.RESET}
  {Colors.GREEN}你的 DNS 请求通过国外 DNS 服务器解析{Colors.RESET}
  
  这意味着:
    - DNS 请求已加密或通过代理
    - IP 归属地伪装正常工作
""")
    else:
        print(f"\n{Colors.YELLOW}[!] 未能获取 DNS 服务器信息，请稍后重试{Colors.RESET}")
    
    print(f"\n{Colors.CYAN}[*] 检测完成！{Colors.RESET}\n")

if __name__ == '__main__':
    main()

