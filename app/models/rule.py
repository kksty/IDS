from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any, Union
from datetime import datetime
import re


def _parse_snort_content(content_str: str) -> bytes:
    """支持混合字符串和十六进制
    
    支持格式：
    - 纯字符串: "Hello World"
    - 纯十六进制: "|48 65 6c 6c 6f|"
    - 混合格式: "|00 01|Hello|02 03|"
    - 二进制转义: "\\x00\\x01Hello"
    
    返回字节序列用于匹配
    """
    if not content_str:
        return b""
    
    result = b""
    i = 0
    
    while i < len(content_str):
        if content_str[i] == '|':
            # 找到十六进制部分的结束
            hex_end = content_str.find('|', i + 1)
            if hex_end == -1:
                # 没有找到结束符，当作普通字符处理
                result += content_str[i].encode('latin-1')
                i += 1
                continue
                
            # 解析十六进制部分
            hex_part = content_str[i + 1:hex_end]
            try:
                # 移除空格并转换为字节
                hex_bytes = bytes.fromhex(hex_part.replace(' ', ''))
                result += hex_bytes
            except ValueError:
                # 十六进制解析失败，当作普通字符处理
                result += content_str[i:hex_end + 1].encode('latin-1')
            
            i = hex_end + 1
        elif content_str[i:i+2] == '\\x':
            # 处理\x转义
            try:
                hex_byte = bytes.fromhex(content_str[i+2:i+4])
                result += hex_byte
                i += 4
            except (ValueError, IndexError):
                # 转义失败，当作普通字符处理
                result += content_str[i].encode('latin-1')
                i += 1
        else:
            # 普通字符
            result += content_str[i].encode('latin-1')
            i += 1
    
    return result


def _parse_http_payload(payload: bytes) -> Optional[Dict[str, bytes]]:
    """解析HTTP payload，返回各个部分的字节数据
    
    返回格式：
    {
        'method': b'GET',
        'uri': b'/path',
        'status_code': b'404',
        'headers': b'header1: value1\r\nheader2: value2\r\n',
        'cookie': b'cookie_value',
        'body': b'body_content'
    }
    """
    try:
        # 简单的HTTP解析
        payload_str = payload.decode('utf-8', errors='ignore')
        lines = payload_str.split('\r\n')
        
        if not lines:
            return None
            
        # 解析第一行
        first_line = lines[0]
        parts = first_line.split()
        if len(parts) < 3:
            return None
            
        # 检查是请求还是响应
        if parts[0].startswith('HTTP/'):  # 响应: "HTTP/1.1 404 Not Found"
            method = b''  # 响应没有方法
            uri = b''     # 响应没有URI
            status_code = parts[1].encode()
        else:  # 请求: "GET /path HTTP/1.1"
            method = parts[0].encode()
            uri = parts[1].encode()
            status_code = b''  # 请求没有状态码
        
        # 找到头部结束的位置
        header_end = -1
        for i, line in enumerate(lines):
            if line == '':
                header_end = i
                break
                
        if header_end == -1:
            return None
            
        # 提取头部
        headers_lines = lines[1:header_end]
        headers_bytes = '\r\n'.join(headers_lines).encode()
        
        # 提取Cookie - 从Cookie头部提取值
        cookie_bytes = b''
        for line in headers_lines:
            if line.lower().startswith('cookie:'):
                # 提取cookie头部的值部分
                cookie_part = line.split(':', 1)[1].strip()
                cookie_bytes = cookie_part.encode()
                break
        
        # 提取body
        body_start = header_end + 1
        body_bytes = '\r\n'.join(lines[body_start:]).encode() if body_start < len(lines) else b''
        
        return {
            'method': method,
            'uri': uri,
            'status_code': status_code,
            'headers': headers_bytes,
            'cookie': cookie_bytes,
            'body': body_bytes
        }
        
    except Exception:
        return None


class Rule(BaseModel):

    # 基本标识
    rule_id: str = Field(..., description="规则唯一标识，对应 Snort 的 SID")
    name: Optional[str] = Field(None, description="规则名称/简要描述")
    action: str = Field("alert", description="规则动作，例如 alert/log/drop")
    priority: int = Field(3, description="优先级，1 高，2 中，3 低")

    # 五元组/协议选择（可选）
    protocol: Optional[str] = Field(None, description="协议：TCP/UDP/ICMP/HTTP/ANY")
    src: Optional[str] = Field("any", description="源地址或 any")
    src_ports: Optional[List[str]] = None
    direction: Optional[str] = Field("->", description="方向，-> 或 <>")
    dst: Optional[str] = Field("any", description="目的地址或 any")
    dst_ports: Optional[List[str]] = None

    # 匹配相关
    # 支持单个字符串或多个关键词/正则组合（后续引擎将统一处理）
    pattern: Union[str, List[str]] = Field(..., description="关键词或正则，字符串或字符串列表")
    pattern_type: str = Field("string", description="'string' 或 'pcre'，决定如何解释 pattern 字段")

    # 额外信息
    description: Optional[str] = None
    category: Optional[str] = None
    tags: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None
    enabled: bool = Field(True, description="是否启用规则")

    created_at: datetime = Field(default_factory=datetime.utcnow)

    @validator("protocol", pre=True, always=True)
    def _normalize_protocol(cls, v):
        if v is None:
            return None
        return v.upper()

    @validator("priority")
    def _check_priority(cls, v):
        if v not in (1, 2, 3):
            raise ValueError("priority must be 1, 2 or 3")
        return v

    def patterns_list(self) -> List[str]:
        """返回规则的模式列表，统一为字符串列表。"""
        if isinstance(self.pattern, list):
            return [str(p) for p in self.pattern]
        return [str(self.pattern)]

    def compile_pcre(self) -> List[re.Pattern]:
        """当 pattern_type == 'pcre' 时，将 pattern 列表编译为 PCRE（Python regex）。"""
        if self.pattern_type != "pcre":
            return []
        pats = self.patterns_list()
        compiled = []
        for p in pats:
            try:
                compiled.append(re.compile(p))
            except re.error:
                # 留给上层记录或验证时处理错误
                continue
        return compiled

    def matches_payload(self, payload: bytes) -> bool:
        """匹配接口：用于单包或抓取到的 payload 快速验证。

        支持高级选项：
        - depth: 从匹配位置开始，向后搜索的最大字节数
        - offset: 从payload开始跳过的字节数
        - within: 在offset之后的最大搜索范围
        - nocase: 不区分大小写匹配
        - HTTP选项: 只在HTTP协议特定部分匹配
        - pkt_data: 在整个数据包中匹配（默认行为）
        - distance: 内容之间的最小距离

        - 若 pattern_type == 'string'：逐个关键词做 bytes 子串查找（支持高级选项）
        - 若 pattern_type == 'pcre'：使用已编译的正则去匹配解码后的文本（高级选项暂不支持）
        """
        if not self.enabled:
            return False

        pats = self.patterns_list()

        # 获取content_options（per-content修饰符）
        metadata = self.metadata or {}
        content_options = metadata.get('content_options', [])

        # 如果没有per-content选项，使用全局选项的向后兼容模式
        if not content_options or len(content_options) != len(pats):
            return self._matches_payload_legacy(payload)

        # Per-content匹配模式
        if self.pattern_type == "string":
            # 解析HTTP payload（如果需要）
            http_parts = None
            has_http_content = any(
                opts.get('http_method') or opts.get('http_uri') or 
                opts.get('http_header') or opts.get('http_cookie') or opts.get('http_body')
                for opts in content_options
            )
            
            if has_http_content:
                http_parts = _parse_http_payload(payload)
                if http_parts is None:
                    return False  # 不是有效的HTTP流量

            # 跟踪上一个匹配的位置，用于distance计算
            last_match_end = 0
            
            for i, (pattern, opts) in enumerate(zip(pats, content_options)):
                # 解析Snort风格的内容（支持混合十六进制和字符串）
                pattern_bytes = _parse_snort_content(pattern)
                pattern_len = len(pattern_bytes)
                
                # 获取当前content的选项
                nocase = opts.get('nocase', False)
                offset = opts.get('offset', 0)
                within = opts.get('within')
                depth = opts.get('depth')
                distance = opts.get('distance', 0)  # 距离上一个content的距离
                
                # HTTP选项
                http_method = opts.get('http_method', False)
                http_uri = opts.get('http_uri', False)
                http_header = opts.get('http_header', False)
                http_cookie = opts.get('http_cookie', False)
                http_body = opts.get('http_body', False)
                pkt_data = opts.get('pkt_data', False)
                
                # 确定搜索范围
                if http_method or http_uri or http_header or http_cookie or http_body:
                    # HTTP特定部分匹配
                    search_payloads = []
                    
                    if http_method and http_parts:
                        search_payloads.append(http_parts['method'])
                    if http_uri and http_parts:
                        search_payloads.append(http_parts['uri'])
                    if http_header and http_parts:
                        search_payloads.append(http_parts['headers'])
                    if http_cookie and http_parts:
                        search_payloads.append(http_parts['cookie'])
                    if http_body and http_parts:
                        search_payloads.append(http_parts['body'])
                        
                    # 如果没有匹配的HTTP部分，使用整个payload
                    if not search_payloads:
                        search_payloads = [payload]
                else:
                    # pkt_data或其他情况，在整个payload中搜索
                    search_payloads = [payload]

                pattern_found = False
                
                for search_payload in search_payloads:
                    # 应用distance：从上一个匹配结束位置开始，加上distance偏移
                    search_start = max(last_match_end + distance, offset)
                    
                    # 计算搜索范围
                    start_pos = max(0, search_start)
                    
                    # within: 限制搜索范围为N字节
                    if within is not None:
                        end_pos = start_pos + within
                    else:
                        end_pos = len(search_payload)

                    # depth: 从搜索开始位置，向后搜索最多N字节
                    if depth is not None:
                        end_pos = min(end_pos, start_pos + depth + pattern_len)

                    # 确保搜索范围有效
                    if start_pos >= len(search_payload) or start_pos >= end_pos:
                        continue

                    actual_search = search_payload[start_pos:end_pos]

                    # 处理nocase选项
                    if nocase:
                        pattern_bytes_cmp = pattern_bytes.lower()
                        search_bytes = actual_search.lower()
                    else:
                        pattern_bytes_cmp = pattern_bytes
                        search_bytes = actual_search

                    # 查找匹配
                    match_pos = search_bytes.find(pattern_bytes_cmp)
                    if match_pos != -1:
                        # 计算实际匹配位置（相对于整个payload）
                        actual_match_start = start_pos + match_pos
                        actual_match_end = actual_match_start + pattern_len
                        
                        # 更新last_match_end用于下一个content的distance计算
                        last_match_end = actual_match_end
                        
                        pattern_found = True
                        break
                        
                # 如果当前pattern没有找到，匹配失败
                if not pattern_found:
                    return False
                    
            return True

        # PCRE模式暂不支持per-content选项
        return self._matches_payload_legacy(payload)

    def _matches_payload_legacy(self, payload: bytes) -> bool:
        """向后兼容的匹配方法，使用全局选项"""
        pats = self.patterns_list()
        metadata = self.metadata or {}
        
        if self.pattern_type == "string":
        # 检查是否有HTTP选项
            http_method = metadata.get('http_method', False)
            http_uri = metadata.get('http_uri', False)
            http_header = metadata.get('http_header', False)
            http_cookie = metadata.get('http_cookie', False)
            http_body = metadata.get('http_body', False)
            http_stat_code = metadata.get('http_stat_code', False)
            
            # 如果有HTTP选项，需要解析HTTP
            if http_method or http_uri or http_header or http_cookie or http_body or http_stat_code:
                http_parts = _parse_http_payload(payload)
                if http_parts is None:
                    return False  # 不是有效的HTTP流量
                
                search_payloads = []
                if http_method:
                    search_payloads.append(http_parts['method'])
                if http_uri:
                    search_payloads.append(http_parts['uri'])
                if http_header:
                    search_payloads.append(http_parts['headers'])
                if http_cookie:
                    search_payloads.append(http_parts['cookie'])
                if http_body:
                    search_payloads.append(http_parts['body'])
                if http_stat_code:
                    search_payloads.append(http_parts['status_code'])
                
                # 在HTTP部分中搜索
                for search_payload in search_payloads:
                    for p in pats:
                        if _parse_snort_content(p) in search_payload:
                            return True
                return False
            else:
                # 在整个payload中搜索
                for p in pats:
                    if _parse_snort_content(p) in payload:
                        return True
                return False

        # PCRE 模式：尝试将 payload 解码为文本后正则匹配
        try:
            text = payload.decode("utf-8", errors="ignore")
        except Exception:
            text = ""
        for regex in self.compile_pcre():
            if regex.search(text):
                return True
        return False


__all__ = ["Rule"]
