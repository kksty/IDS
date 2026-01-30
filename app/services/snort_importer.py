"""Snort3规则导入器 - 将Snort3规则转换为系统规则格式。

支持的Snort3规则格式：
alert tcp any any -> any 80 (msg:"HTTP GET"; content:"GET"; http_method; sid:1000001;)
alert tcp any any -> any 22 (msg:"SSH Brute Force"; content:"password"; threshold: type both, track by_src, count 5, seconds 60; sid:2000001;)
"""

import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import json


@dataclass
class SnortRule:
    """解析后的Snort规则"""
    action: str
    protocol: str
    src_ip: str
    src_port: str
    direction: str
    dst_ip: str
    dst_port: str
    options: Dict[str, Any]
    raw_rule: str


class SnortRuleParser:
    """Snort3规则解析器"""

    # Snort规则正则表达式
    RULE_PATTERN = re.compile(
        r'^(?P<action>\w+)\s+'
        r'(?P<protocol>\w+)\s+'
        r'(?P<src_ip>[^\s]+)\s+'
        r'(?P<src_port>[^\s]+)\s+'
        r'(?P<direction>->|<>)\s+'
        r'(?P<dst_ip>[^\s]+)\s+'
        r'(?P<dst_port>[^\s]+)\s*'
        r'\((?P<options>.*)\)$'
    )

    # 选项解析正则表达式
    OPTION_PATTERNS = {
        'msg': re.compile(r'msg:"([^"]*)";'),
        'content': re.compile(r'content:"([^"]*)";'),
        'content_hex': re.compile(r'content:([0-9a-fA-F]+);'),
        'pcre': re.compile(r'pcre:"([^"]*)";'),
        'sid': re.compile(r'sid:(\d+);'),
        'rev': re.compile(r'rev:(\d+);'),
        'gid': re.compile(r'gid:(\d+);'),
        'priority': re.compile(r'priority:(\d+);'),
        'classtype': re.compile(r'classtype:([^;]+);'),
        'threshold': re.compile(r'threshold:\s*([^;]+);'),
        'http_method': re.compile(r'http_method;'),
        'http_uri': re.compile(r'http_uri;'),
        'http_header': re.compile(r'http_header;'),
        'http_cookie': re.compile(r'http_cookie;'),
        'http_body': re.compile(r'http_body;'),
        'flow': re.compile(r'flow:([^;]+);'),
        'flags': re.compile(r'flags:([^;]+);'),
        'dsize': re.compile(r'dsize:([^;]+);'),
    }

    def parse_rule(self, rule_line: str) -> Optional[SnortRule]:
        """解析单条Snort规则"""
        rule_line = rule_line.strip()
        if not rule_line or rule_line.startswith('#'):
            return None

        match = self.RULE_PATTERN.match(rule_line)
        if not match:
            return None

        groups = match.groupdict()
        options_str = groups['options']

        # 解析选项
        options = {}
        for option_name, pattern in self.OPTION_PATTERNS.items():
            matches = pattern.findall(options_str)
            if matches:
                if len(matches) == 1:
                    options[option_name] = matches[0]
                else:
                    options[option_name] = matches

        return SnortRule(
            action=groups['action'],
            protocol=groups['protocol'],
            src_ip=groups['src_ip'],
            src_port=groups['src_port'],
            direction=groups['direction'],
            dst_ip=groups['dst_ip'],
            dst_port=groups['dst_port'],
            options=options,
            raw_rule=rule_line
        )

    def convert_to_system_rule(self, snort_rule: SnortRule) -> Dict[str, Any]:
        """将Snort规则转换为系统规则格式"""

        # 生成规则ID
        sid = snort_rule.options.get('sid', 'unknown')
        rule_id = f"snort_{sid}"

        # 确定协议
        protocol_map = {
            'tcp': 'tcp',
            'udp': 'udp',
            'ip': None,
            'icmp': 'icmp'
        }
        protocol = protocol_map.get(snort_rule.protocol.lower())

        # 转换IP地址
        src_ip = 'any' if snort_rule.src_ip == 'any' else snort_rule.src_ip
        dst_ip = 'any' if snort_rule.dst_ip == 'any' else snort_rule.dst_ip

        # 转换端口
        def convert_port(port_str: str) -> Optional[List[int]]:
            if port_str == 'any':
                return None
            if ':' in port_str:
                # 处理端口范围，如 80:443
                start, end = port_str.split(':')
                return list(range(int(start), int(end) + 1))
            return [int(port_str)]

        src_ports = convert_port(snort_rule.src_port)
        dst_ports = convert_port(snort_rule.dst_port)

        # 确定匹配模式和内容
        pattern = None
        pattern_type = 'string'

        if 'pcre' in snort_rule.options:
            pattern = snort_rule.options['pcre']
            pattern_type = 'pcre'
        elif 'content' in snort_rule.options:
            pattern = snort_rule.options['content']
            pattern_type = 'string'
        elif 'content_hex' in snort_rule.options:
            # 转换十六进制内容
            hex_content = snort_rule.options['content_hex']
            try:
                pattern = bytes.fromhex(hex_content).decode('latin-1')
            except:
                pattern = hex_content

        # 确定优先级
        priority_map = {
            'attempted-admin': 1,
            'successful-admin': 1,
            'attempted-user': 2,
            'successful-user': 2,
            'policy-violation': 3,
            'attempted-dos': 2,
            'successful-dos': 1,
            'attempted-recon': 3,
            'successful-recon': 2,
            'bad-unknown': 3,
            'default': 3
        }

        classtype = snort_rule.options.get('classtype', 'default')
        priority = priority_map.get(classtype, 3)

        # 确定描述
        description = snort_rule.options.get('msg', f"Snort rule {sid}")

        # 确定类别
        category_map = {
            'web-application-attack': 'web',
            'attempted-admin': 'admin',
            'successful-admin': 'admin',
            'attempted-user': 'user',
            'successful-user': 'user',
            'policy-violation': 'policy',
            'attempted-dos': 'dos',
            'successful-dos': 'dos',
            'attempted-recon': 'recon',
            'successful-recon': 'recon',
            'bad-unknown': 'unknown'
        }

        category = category_map.get(classtype, 'unknown')

        return {
            'rule_id': rule_id,
            'name': description,
            'action': 'alert',
            'priority': priority,
            'protocol': protocol,
            'src': src_ip,
            'src_ports': src_ports,
            'direction': snort_rule.direction,
            'dst': dst_ip,
            'dst_ports': dst_ports,
            'pattern': pattern,
            'pattern_type': pattern_type,
            'description': description,
            'category': category,
            'tags': ['snort', 'imported'],
            'metadata': {
                'snort_sid': sid,
                'snort_rev': snort_rule.options.get('rev'),
                'snort_gid': snort_rule.options.get('gid'),
                'classtype': classtype,
                'raw_rule': snort_rule.raw_rule
            },
            'enabled': True
        }


class SnortRuleImporter:
    """Snort规则批量导入器"""

    def __init__(self):
        self.parser = SnortRuleParser()

    def import_from_file(self, file_path: str) -> List[Dict[str, Any]]:
        """从文件导入Snort规则"""
        rules = []

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                try:
                    snort_rule = self.parser.parse_rule(line)
                    if snort_rule:
                        system_rule = self.parser.convert_to_system_rule(snort_rule)
                        rules.append(system_rule)
                except Exception as e:
                    print(f"Warning: Failed to parse line {line_num}: {e}")
                    continue

        return rules

    def import_from_text(self, rules_text: str) -> List[Dict[str, Any]]:
        """从文本导入Snort规则"""
        rules = []

        for line_num, line in enumerate(rules_text.split('\n'), 1):
            try:
                snort_rule = self.parser.parse_rule(line)
                if snort_rule:
                    system_rule = self.parser.convert_to_system_rule(snort_rule)
                    rules.append(system_rule)
            except Exception as e:
                print(f"Warning: Failed to parse line {line_num}: {e}")
                continue

        return rules


def bulk_import_snort_rules(rules_text: str) -> List[Dict[str, Any]]:
    """批量导入Snort规则的便捷函数"""
    importer = SnortRuleImporter()
    return importer.import_from_text(rules_text)


# 使用示例
if __name__ == "__main__":
    importer = SnortRuleImporter()

    # 示例Snort规则
    sample_rules = '''
    alert tcp any any -> any 80 (msg:"HTTP GET"; content:"GET"; http_method; sid:1000001;)
    alert tcp any any -> any 22 (msg:"SSH Login Attempt"; content:"password"; sid:2000001;)
    alert tcp any any -> any 3306 (msg:"MySQL Login"; content:"select user"; nocase; sid:3000001;)
    alert udp any any -> any 53 (msg:"DNS Query"; content:"|01 00 00 01|"; sid:4000001;)
    '''

    rules = importer.import_from_text(sample_rules)

    print(f"Imported {len(rules)} rules:")

# 使用示例
if __name__ == "__main__":
    importer = SnortRuleImporter()

    # 示例Snort规则
    sample_rules = """
    alert tcp any any -> any 80 (msg:"HTTP GET"; content:"GET"; http_method; sid:1000001;)
    alert tcp any any -> any 22 (msg:"SSH Login Attempt"; content:"password"; sid:2000001;)
    alert tcp any any -> any 3306 (msg:"MySQL Login"; content:"select user"; nocase; sid:3000001;)
    alert udp any any -> any 53 (msg:"DNS Query"; content:"|01 00 00 01|"; sid:4000001;)
    """

    rules = importer.import_from_text(sample_rules)

    print(f"Imported {len(rules)} rules:")
    for rule in rules:
        print(f"- {rule["rule_id"]}: {rule["name"]}")




def bulk_import_snort_rules(rules_text: str) -> List[Dict[str, Any]]:
    """批量导入Snort规则的便捷函数"""
    importer = SnortRuleImporter()
    return importer.import_from_text(rules_text)

