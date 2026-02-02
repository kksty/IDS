"""Snort3规则导入器 - 将Snort3规则转换为系统规则格式。
"""

import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import json

from app.db import SessionLocal
from app.models.db_models import ConfigModel


# Snort变量默认值配置
DEFAULT_SNORT_VARIABLES = {
    '$HOME_NET': '192.168.0.0/16',  # 默认家庭网络，可通过配置覆盖
    '$EXTERNAL_NET': '!$HOME_NET',   # 外部网络（非家庭网络）
    '$HTTP_SERVERS': '$HOME_NET',    # HTTP服务器
    '$SQL_SERVERS': '$HOME_NET',     # SQL服务器
    '$SMTP_SERVERS': '$HOME_NET',    # SMTP服务器
    '$DNS_SERVERS': 'any',           # DNS服务器
    '$TELNET_SERVERS': '$HOME_NET',  # Telnet服务器
    '$SNMP_SERVERS': '$HOME_NET',    # SNMP服务器
    '$FTP_SERVERS': '$HOME_NET',     # FTP服务器
    '$SSH_SERVERS': '$HOME_NET',     # SSH服务器
    '$SIP_SERVERS': '$HOME_NET',     # SIP服务器
    # 端口变量
    '$HTTP_PORTS': '80,443',         # HTTP端口
    '$SHELLCODE_PORTS': '!80',       # Shellcode端口
    '$ORACLE_PORTS': '1521',         # Oracle端口
    '$SSH_PORTS': '22',              # SSH端口
    '$FTP_PORTS': '21,2100,3535',    # FTP端口
    '$SIP_PORTS': '5060,5061',       # SIP端口
    '$FILE_DATA_PORTS': '110,143',   # 文件数据端口
    '$GTP_PORTS': '2123,2152,3386',  # GTP端口
}

# 当前变量值（用于缓存）
SNORT_VARIABLES = DEFAULT_SNORT_VARIABLES.copy()


def resolve_snort_variable(var_name: str, variables: Optional[Dict[str, str]] = None) -> str:
    """解析Snort变量，返回实际的IP地址或网络范围"""
    if variables is None:
        variables = SNORT_VARIABLES
        
    if var_name in variables:
        value = variables[var_name]
        # 处理嵌套变量
        if value.startswith('$'):
            return resolve_snort_variable(value, variables)
        # 处理否定变量（如 !$HOME_NET）
        if value.startswith('!'):
            if value[1:].startswith('$'):
                # 处理 !$HOME_NET 这样的情况
                negated_var = value[1:]  # 移除!前缀，得到$HOME_NET
                resolved_var = resolve_snort_variable(negated_var, variables)
                return '!' + resolved_var
            else:
                return value  # 保留否定语法，匹配时再处理
        return value
    # 未知变量返回any
    return 'any'


def update_snort_variable(var_name: str, value: str):
    """更新Snort变量的值并保存到数据库"""
    # 更新内存缓存
    SNORT_VARIABLES[var_name] = value
    
    # 保存到数据库
    session = SessionLocal()
    try:
        # 检查是否已存在
        config = session.query(ConfigModel).filter(ConfigModel.key == f"snort_var_{var_name}").first()
        if config:
            config.value = value
        else:
            config = ConfigModel(key=f"snort_var_{var_name}", value=value)
            session.add(config)
        session.commit()
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def get_snort_variables() -> Dict[str, str]:
    """获取所有Snort变量的当前值，从数据库加载"""
    # 从默认值开始
    current_vars = DEFAULT_SNORT_VARIABLES.copy()
    
    # 从数据库加载已保存的配置
    session = SessionLocal()
    try:
        configs = session.query(ConfigModel).filter(ConfigModel.key.like("snort_var_%")).all()
        for config in configs:
            var_name = config.key.replace("snort_var_", "")
            current_vars[var_name] = config.value
    except Exception:
        pass  # 如果数据库查询失败，使用默认值
    finally:
        session.close()
    
    # 返回原始值（不解析），让用户看到变量之间的关系
    return current_vars


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


@dataclass
class ContentItem:
    """Content项及其修饰符"""
    content: str
    modifiers: Dict[str, Any]


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
        'content': re.compile(r'content:(?:"([^"]*)"|([^;]*))(?:,([^;]+))?;', re.IGNORECASE),
        'content_hex': re.compile(r'content:([0-9a-fA-F]+);'),
        'uricontent': re.compile(r'uricontent:(?:"([^"]*)"|([^;]*))(?:,([^;]+))?;', re.IGNORECASE),
        'pcre': re.compile(r'pcre:"([^"]*)";'),
        'sid': re.compile(r'sid:(\d+);'),
        'rev': re.compile(r'rev:(\d+);'),
        'gid': re.compile(r'gid:(\d+);'),
        'priority': re.compile(r'priority:(\d+);'),
        'classtype': re.compile(r'classtype:([^;]+);'),
        'threshold': re.compile(r'threshold:\s*([^;]+);'),
        'metadata': re.compile(r'metadata:([^;]+);'),
        'reference': re.compile(r'reference:([^;]+);'),
        'icmp_id': re.compile(r'icmp_id:(\d+);'),
        'itype': re.compile(r'itype:(\d+);'),
        'http_method': re.compile(r'http_method;'),
        'http_uri': re.compile(r'http_uri;'),
        'http_header': re.compile(r'http_header;'),
        'http_cookie': re.compile(r'http_cookie;'),
        'http_body': re.compile(r'http_body;'),
        'http_stat_code': re.compile(r'http_stat_code(?::([^;]+))?;', re.IGNORECASE),
        'http_request_line': re.compile(r'http_request_line;'),
        'pkt_data': re.compile(r'pkt_data;'),
        'flow': re.compile(r'flow:([^;]+);'),
        'flags': re.compile(r'flags:([^;]+);'),
        'dsize': re.compile(r'dsize:([^;]+);'),
        'depth': re.compile(r'depth:(\d+);'),
        'offset': re.compile(r'offset:(\d+);'),
        'within': re.compile(r'within:(\d+);'),
        'distance': re.compile(r'distance:(\d+);'),
        'nocase': re.compile(r'nocase;'),
        'service': re.compile(r'service:([^;]+);'),
        'app-layer-protocol': re.compile(r'app-layer-protocol:([^;]+);'),
        'ssl_version': re.compile(r'ssl_version:([^;]+);'),
        'ftp_command': re.compile(r'ftp_command;'),
        'dns_query': re.compile(r'dns_query;'),
        'smtp_command': re.compile(r'smtp_command;'),
        'pop_command': re.compile(r'pop_command;'),
    }

    def parse_snort_content(self, content_str: str) -> str:
        """解析Snort content字段，支持混合字符串和十六进制内容
        
        对于前端显示，我们保持原始的Snort格式，让前端处理十六进制显示。
        """
        if not content_str:
            return ""

        # 如果内容包含十六进制部分（有|分隔符），保持原始格式
        if '|' in content_str:
            return content_str
        
        # 如果是纯字符串，直接返回
        return content_str

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
        content_items = []  # 收集所有content项
        
        # 首先解析所有选项
        for option_name, pattern in self.OPTION_PATTERNS.items():
            matches = pattern.findall(options_str)
            if matches:
                if option_name == 'content':
                    # 特殊处理content选项，解析每个content及其修饰符
                    content_items = self._parse_content_options(options_str)
                    options['content'] = content_items
                elif len(matches) == 1:
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

    def _parse_content_options(self, options_str: str) -> List[ContentItem]:
        """解析content选项，支持每个content的独立修饰符"""
        content_items = []
        
        # 将选项字符串按分号分割，然后重新组合content相关的选项
        options_parts = [part.strip() for part in options_str.split(';') if part.strip()]
        
        i = 0
        while i < len(options_parts):
            part = options_parts[i]
            if not part:
                i += 1
                continue
                
            # 检查是否是content声明
            if part.startswith('content:'):
                # 解析content
                content_match = re.match(r'content:(?:"([^"]*)"|([^;]*))(?:,([^;]+))?', part, re.IGNORECASE)
                if content_match:
                    quoted_content, unquoted_content, content_modifiers = content_match.groups()
                    content_value = quoted_content or unquoted_content
                    if content_value:
                        parsed_content = self.parse_snort_content(content_value)
                        
                        # 解析content特定的修饰符
                        item_modifiers = {}
                        
                        if content_modifiers:
                            modifier_parts = [m.strip() for m in content_modifiers.split(',') if m.strip()]
                            for mod in modifier_parts:
                                if mod.startswith('depth:'):
                                    item_modifiers['depth'] = int(mod.split(':')[1])
                                elif mod.startswith('offset:'):
                                    item_modifiers['offset'] = int(mod.split(':')[1])
                                elif mod.startswith('within:'):
                                    item_modifiers['within'] = int(mod.split(':')[1])
                                elif mod.startswith('distance '):
                                    item_modifiers['distance'] = int(mod.split()[1])
                                elif mod == 'nocase':
                                    item_modifiers['nocase'] = True
                        
                        # 检查紧跟content的修饰符选项
                        j = i + 1
                        while j < len(options_parts):
                            next_part = options_parts[j].strip()
                            if next_part in ['http_method', 'http_uri', 'http_header', 'http_cookie', 'http_body', 'pkt_data']:
                                item_modifiers[next_part] = True
                                j += 1
                            elif next_part.startswith('distance:'):
                                item_modifiers['distance'] = int(next_part.split(':')[1])
                                j += 1
                            elif next_part.startswith('within:'):
                                item_modifiers['within'] = int(next_part.split(':')[1])
                                j += 1
                            elif next_part.startswith('offset:'):
                                item_modifiers['offset'] = int(next_part.split(':')[1])
                                j += 1
                            elif next_part.startswith('depth:'):
                                item_modifiers['depth'] = int(next_part.split(':')[1])
                                j += 1
                            elif next_part == 'nocase':
                                item_modifiers['nocase'] = True
                                j += 1
                            else:
                                # 不是content修饰符，停止检查
                                break
                        
                        content_items.append(ContentItem(
                            content=parsed_content,
                            modifiers=item_modifiers
                        ))
                        
                        i = j - 1  # 更新主循环索引，跳过已处理的修饰符
            else:
                # 跳过非content选项
                pass
            
            i += 1
        
        return content_items

    def convert_to_system_rule(self, snort_rule: SnortRule) -> Dict[str, Any]:
        """将Snort规则转换为系统规则格式"""

        # 获取最新的Snort变量配置
        current_variables = get_snort_variables()

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

        # 转换IP地址 - 使用变量解析器
        def convert_ip(ip_str: str) -> str:
            if ip_str == 'any':
                return 'any'
            # 使用变量解析器处理Snort变量
            elif ip_str.startswith('$'):
                return resolve_snort_variable(ip_str, current_variables)
            else:
                return ip_str

        src_ip = convert_ip(snort_rule.src_ip)
        dst_ip = convert_ip(snort_rule.dst_ip)

        # 转换端口
        def convert_port(port_str: str) -> Optional[List[str]]:
            if port_str == 'any':
                return None
            # 处理Snort变量
            if port_str.startswith('$'):
                resolved_port = resolve_snort_variable(port_str, current_variables)
                # 如果解析后的端口包含逗号，说明是端口列表
                if ',' in resolved_port:
                    return [p.strip() for p in resolved_port.split(',')]
                return [resolved_port]
            # 处理Snort端口列表格式，如 [12345,12346]
            if port_str.startswith('[') and port_str.endswith(']'):
                port_list = port_str[1:-1].split(',')
                return [p.strip() for p in port_list]
            # 处理否定端口，如 !21 或 !21:23
            if port_str.startswith('!'):
                negated_port = port_str[1:]  # 移除 ! 前缀
                if ':' in negated_port:
                    # 处理否定端口范围，如 !21:23
                    parts = negated_port.split(':')
                    if len(parts) == 2:
                        start_str, end_str = parts
                        try:
                            start = int(start_str)
                            if end_str == '':  # 如 !1024: 表示除了从1024到65535的所有端口
                                end = 65535
                            else:
                                end = int(end_str)
                            # 对于否定端口范围，返回特殊格式表示
                            return [f"!{start}:{end}"]
                        except ValueError:
                            # 如果无法转换为整数，保持原样
                            return [port_str]
                    else:
                        return [port_str]
                else:
                    # 处理单个否定端口，如 !21
                    try:
                        port_num = int(negated_port)
                        return [f"!{port_num}"]
                    except ValueError:
                        return [port_str]
            if ':' in port_str:
                # 处理端口范围，如 80:443 或 1024: (从1024到65535)
                parts = port_str.split(':')
                if len(parts) == 2:
                    start_str, end_str = parts
                    try:
                        start = int(start_str)
                        if end_str == '':  # 如 1024: 表示从1024到65535
                            end = 65535
                        else:
                            end = int(end_str)
                        return [str(p) for p in range(start, end + 1)]
                    except ValueError:
                        # 如果无法转换为整数，保持原样
                        return [port_str]
                else:
                    # 无效的端口范围格式
                    return [port_str]
            return [port_str]

        src_ports = convert_port(snort_rule.src_port)
        dst_ports = convert_port(snort_rule.dst_port)

        # 确定匹配模式和内容
        pattern = None
        pattern_type = 'string'
        content_metadata = {}  # 存储content相关的元数据

        if 'pcre' in snort_rule.options:
            pattern = snort_rule.options['pcre']
            pattern_type = 'pcre'
        elif 'uricontent' in snort_rule.options:
            # uricontent 被视为 content + http_uri
            uricontent_data = snort_rule.options['uricontent']
            if isinstance(uricontent_data, tuple) and len(uricontent_data) >= 1:
                pattern = uricontent_data[0]  # uricontent的内容
                content_metadata['http_uri'] = True  # 设置http_uri修饰符
                # 处理其他uricontent修饰符
                if len(uricontent_data) > 2 and uricontent_data[2]:
                    # uricontent可能有额外的修饰符
                    pass
            else:
                pattern = uricontent_data
                content_metadata['http_uri'] = True
            pattern_type = 'string'
        elif 'content' in snort_rule.options:
            content_data = snort_rule.options['content']
            if isinstance(content_data, list) and content_data and isinstance(content_data[0], ContentItem):
                # 多个content项，每个有自己的修饰符
                patterns = []
                content_options = []
                
                for i, content_item in enumerate(content_data):
                    patterns.append(content_item.content)
                    # 收集每个content的选项
                    content_opts = {}
                    for key, value in content_item.modifiers.items():
                        content_opts[f'content_{i}_{key}'] = value
                    content_options.append(content_opts)
                
                pattern = patterns
                content_metadata['content_options'] = content_options
                pattern_type = 'string'
            elif isinstance(content_data, list):
                # 向后兼容：简单的content列表
                pattern = content_data
                pattern_type = 'string'
            else:
                # 单个content
                pattern = content_data
                pattern_type = 'string'
        elif 'http_stat_code' in snort_rule.options:
            # http_stat_code 有值时，将值作为模式
            stat_code_data = snort_rule.options['http_stat_code']
            if stat_code_data:
                pattern = stat_code_data
                content_metadata['http_stat_code'] = True
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
                'raw_rule': snort_rule.raw_rule,
                # 添加高级Snort选项到metadata
                'depth': snort_rule.options.get('depth'),
                'offset': snort_rule.options.get('offset'),
                'within': snort_rule.options.get('within'),
                'distance': snort_rule.options.get('distance'),
                'nocase': 'nocase' in snort_rule.options,
                'http_method': 'http_method' in snort_rule.options,
                'http_uri': 'http_uri' in snort_rule.options or 'uricontent' in snort_rule.options,  # uricontent implies http_uri
                'http_header': 'http_header' in snort_rule.options,
                'http_cookie': 'http_cookie' in snort_rule.options,
                'http_body': 'http_body' in snort_rule.options,
                'http_stat_code': 'http_stat_code' in snort_rule.options,
                'http_request_line': 'http_request_line' in snort_rule.options,
                'pkt_data': 'pkt_data' in snort_rule.options,
                'service': snort_rule.options.get('service'),
                'app-layer-protocol': snort_rule.options.get('app-layer-protocol'),
                'ssl_version': snort_rule.options.get('ssl_version'),
                'ftp_command': 'ftp_command' in snort_rule.options,
                'dns_query': 'dns_query' in snort_rule.options,
                'smtp_command': 'smtp_command' in snort_rule.options,
                'pop_command': 'pop_command' in snort_rule.options,
                'flow': snort_rule.options.get('flow'),
                'flags': snort_rule.options.get('flags'),
                'dsize': snort_rule.options.get('dsize'),
                'threshold': snort_rule.options.get('threshold'),
                'metadata': snort_rule.options.get('metadata'),
                'reference': snort_rule.options.get('reference'),
                'icmp_id': snort_rule.options.get('icmp_id'),
                'itype': snort_rule.options.get('itype'),
                **content_metadata  # 合并content相关的元数据
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

    def import_from_text(self, rules_text: str) -> Dict[str, Any]:
        """从文本导入Snort规则"""
        rules = []
        failed_rules = []

        for line_num, line in enumerate(rules_text.split('\n'), 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue  # 跳过空行和注释
                
            try:
                snort_rule = self.parser.parse_rule(line)
                if snort_rule:
                    system_rule = self.parser.convert_to_system_rule(snort_rule)
                    rules.append(system_rule)
                else:
                    failed_rules.append({
                        "line": line_num,
                        "rule": line,
                        "error": "规则解析失败"
                    })
            except Exception as e:
                failed_rules.append({
                    "line": line_num,
                    "rule": line,
                    "error": str(e)
                })
                continue

        return {
            "success": rules,
            "failed": failed_rules,
            "total": len(rules) + len(failed_rules),
            "imported": len(rules),
            "failed_count": len(failed_rules)
        }


def bulk_import_snort_rules(rules_text: str) -> Dict[str, Any]:
    """批量导入Snort规则的便捷函数"""
    importer = SnortRuleImporter()
    result = importer.import_from_text(rules_text)
    
    # 保存成功导入的规则到数据库
    if result["success"]:
        from app.db import SessionLocal
        from app.models.db_models import RuleModel
        import json
        
        session = SessionLocal()
        try:
            saved_count = 0
            for rule_data in result["success"]:
                try:
                    # 检查规则ID是否已存在
                    exists = session.query(RuleModel).filter(RuleModel.rule_id == rule_data["rule_id"]).first()
                    if exists:
                        continue  # 跳过已存在的规则
                    
                    # 准备pattern字段
                    pattern_val = rule_data["pattern"]
                    if isinstance(pattern_val, list):
                        pattern_store = json.dumps(pattern_val, ensure_ascii=False)
                    else:
                        pattern_store = str(pattern_val)
                    
                    # 创建数据库记录
                    rule_model = RuleModel(
                        rule_id=rule_data["rule_id"],
                        name=rule_data["name"],
                        action=rule_data["action"],
                        priority=rule_data["priority"],
                        protocol=rule_data["protocol"],
                        src=rule_data["src"],
                        src_ports=rule_data["src_ports"],
                        direction=rule_data["direction"],
                        dst=rule_data["dst"],
                        dst_ports=rule_data["dst_ports"],
                        pattern=pattern_store,
                        pattern_type=rule_data["pattern_type"],
                        description=rule_data["description"],
                        category=rule_data["category"],
                        tags=rule_data["tags"],
                        rule_metadata=rule_data["metadata"],
                        enabled=rule_data.get("enabled", True)
                    )
                    
                    session.add(rule_model)
                    saved_count += 1
                    
                except Exception as e:
                    print(f"Failed to save rule {rule_data.get('rule_id', 'unknown')}: {e}")
                    continue
            
            session.commit()
            result["saved"] = saved_count
            result["message"] = f"成功导入并保存了 {saved_count} 条规则"
            
        except Exception as e:
            session.rollback()
            result["saved"] = 0
            result["message"] = f"保存规则失败: {str(e)}"
        finally:
            session.close()
    else:
        result["saved"] = 0
        result["message"] = "没有规则被保存"
    
    return result

