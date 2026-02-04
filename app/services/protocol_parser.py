# -*- coding: utf-8 -*-
"""
协议解析器模块
为不同协议提供专门的解析功能，包括SSH、FTP、DNS等
使用pypcapkit作为主要解析器，结合自定义解析器
"""
import re
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass

logger = logging.getLogger("ids.protocol_parser")

# 尝试导入pypcapkit解析器
try:
    from pcapkit.protocols.application import HTTP as PcapHTTP, FTP as PcapFTP
    _HAVE_PCAPKIT_APP = True
except ImportError:
    _HAVE_PCAPKIT_APP = False
    logger.warning("pypcapkit application protocols not available, using fallback parsers")

@dataclass
class ParsedProtocol:
    """解析后的协议数据"""
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    payload: bytes
    parsed_data: Dict[str, Any]
    raw_text: Optional[str] = None

class ProtocolParser:
    """协议解析器"""

    def __init__(self):
        self.parsers = {
            'ssh': self._parse_ssh,
            'ftp': self._parse_ftp_pypcapkit if _HAVE_PCAPKIT_APP else self._parse_ftp,
            'dns': self._parse_dns,
            'smtp': self._parse_smtp,
            'pop3': self._parse_pop3,
            'imap': self._parse_imap,
            'telnet': self._parse_telnet,
            'http': self._parse_http_pypcapkit if _HAVE_PCAPKIT_APP else self._parse_http_fallback,  # Use pypcapkit with improved error handling
        }

    def parse_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                    payload: bytes, protocol: str) -> Optional[ParsedProtocol]:
        """
        解析数据包
        """
        try:
            # 确定协议类型
            detected_protocol = self._detect_protocol(src_port, dst_port, protocol, payload)
            if not detected_protocol:
                return None

            # 获取对应的解析器
            parser = self.parsers.get(detected_protocol)
            if not parser:
                return None

            # 解析数据
            parsed_data = parser(payload, src_port, dst_port)

            # 尝试解码为文本
            raw_text = None
            try:
                raw_text = payload.decode('utf-8', errors='ignore').strip()
            except:
                pass

            return ParsedProtocol(
                protocol=detected_protocol,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                payload=payload,
                parsed_data=parsed_data,
                raw_text=raw_text
            )

        except Exception as e:
            logger.debug(f"Failed to parse {protocol} packet: {e}")
            return None

    def _detect_protocol(self, src_port: int, dst_port: int, protocol: str, payload: bytes) -> Optional[str]:
        """检测协议类型"""
        # 只对TCP和UDP进行基于payload的检测，ICMP不进行应用层协议检测
        if protocol not in ('TCP', 'UDP'):
            # 只进行基于端口的检测
            port_protocols = {
                22: 'ssh',
                21: 'ftp',
                20: 'ftp',  # FTP数据端口
                53: 'dns',
                25: 'smtp',
                587: 'smtp',  # SMTP提交
                465: 'smtp',  # SMTPS
                110: 'pop3',
                995: 'pop3',  # POP3S
                143: 'imap',
                993: 'imap',  # IMAPS
                23: 'telnet',
            }
            for port in [src_port, dst_port]:
                if port in port_protocols:
                    return port_protocols[port]
            return None

        # 基于端口的检测
        port_protocols = {
            22: 'ssh',
            21: 'ftp',
            20: 'ftp',  # FTP数据端口
            53: 'dns',
            25: 'smtp',
            587: 'smtp',  # SMTP提交
            465: 'smtp',  # SMTPS
            110: 'pop3',
            995: 'pop3',  # POP3S
            143: 'imap',
            993: 'imap',  # IMAPS
            23: 'telnet',
        }

        # 检查源端口和目的端口
        for port in [src_port, dst_port]:
            if port in port_protocols:
                return port_protocols[port]

        # 基于payload的检测（只对TCP/UDP）
        if len(payload) > 0:
            payload_str = payload[:50].decode('utf-8', errors='ignore').lower()

            # HTTP检测
            if payload_str.startswith(('get ', 'post ', 'put ', 'delete ', 'head ', 'options ', 'patch ')) or \
               'http/' in payload_str[:100]:
                return 'http'

            # SSH检测
            if payload.startswith(b'SSH-') or b'ssh' in payload[:20].lower():
                return 'ssh'

            # FTP检测
            if any(cmd in payload_str for cmd in ['user ', 'pass ', 'retr ', 'stor ', 'list ']):
                return 'ftp'

            # DNS检测（简化）
            if len(payload) >= 12:
                # DNS查询的标志位检查
                flags = payload[2:4]
                if flags and (flags[0] & 0x80) == 0:  # QR位为0表示查询
                    return 'dns'

        return None

    def _parse_ssh(self, payload: bytes, src_port: int, dst_port: int) -> Dict[str, Any]:
        """解析SSH协议"""
        data = {
            'type': 'unknown',
            'version': None,
            'commands': [],
            'errors': []
        }

        try:
            payload_str = payload.decode('utf-8', errors='ignore')

            # SSH版本识别
            if payload_str.startswith('SSH-'):
                lines = payload_str.split('\n')
                if lines:
                    data['version'] = lines[0].strip()

            # 简单的命令检测（实际SSH是加密的，这里只是基本检测）
            if b'password' in payload.lower():
                data['type'] = 'authentication'
            elif any(cmd in payload_str.lower() for cmd in ['exec', 'shell', 'subsystem']):
                data['type'] = 'command'
            else:
                data['type'] = 'handshake'

        except Exception as e:
            data['errors'].append(str(e))

        return data

    def _parse_ftp_pypcapkit(self, payload: bytes, src_port: int, dst_port: int) -> Dict[str, Any]:
        """使用pypcapkit解析FTP协议"""
        data = {
            'type': 'unknown',
            'command': None,
            'args': None,
            'response_code': None,
            'response_text': None,
            'errors': []
        }

        try:
            ftp_parser = PcapFTP(payload)
            info = ftp_parser.info

            # 解析FTP信息
            if hasattr(info, 'type'):
                data['type'] = info.type

            if hasattr(info, 'cmmd'):
                data['command'] = info.cmmd

            if hasattr(info, 'args'):
                data['args'] = info.args

            # 如果是响应
            if hasattr(info, 'code'):
                data['response_code'] = info.code

            if hasattr(info, 'text'):
                data['response_text'] = info.text

        except Exception as e:
            data['errors'].append(f"pypcapkit FTP parsing failed: {e}")
            # 回退到自定义解析
            return self._parse_ftp(payload, src_port, dst_port)

        return data

    def _parse_http_pypcapkit(self, payload: bytes, src_port: int, dst_port: int) -> Dict[str, Any]:
        """使用pypcapkit解析HTTP协议"""
        data = {
            'method': None,
            'uri': None,
            'version': None,
            'status_code': None,
            'status_text': None,
            'headers': {},
            'body': None,
            'errors': []
        }

        try:
            # 首先检查payload是否可能是HTTP数据
            if not payload or len(payload) < 10:
                data['errors'].append("Payload too short for HTTP parsing")
                return self._parse_http_fallback(payload, src_port, dst_port)

            # 检查是否以HTTP方法或HTTP/开头
            payload_str = payload[:50].decode('utf-8', errors='ignore').strip()
            if not (payload_str.upper().startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ')) or
                    'HTTP/' in payload_str.upper()):
                data['errors'].append("Payload does not appear to be HTTP")
                return self._parse_http_fallback(payload, src_port, dst_port)

            # 尝试使用pcapkit解析
            http_parser = PcapHTTP(payload)
            info = http_parser.info

            # 解析HTTP信息
            if hasattr(info, 'receipt') and info.receipt:
                receipt = info.receipt
                # 手动解析method（pcapkit有时解析不完整）
                if hasattr(receipt, 'method'):
                    method = str(receipt.method).strip()
                    if not method:
                        # 从原始payload提取method
                        try:
                            payload_start = payload.decode('utf-8', errors='ignore').strip()
                            if payload_start:
                                first_line = payload_start.split('\n')[0]
                                method_part = first_line.split()[0] if ' ' in first_line else None
                                if method_part and method_part.isalpha():
                                    method = method_part.upper()
                        except:
                            pass
                    data['method'] = method if method else None
                else:
                    # 从原始payload提取method
                    try:
                        payload_start = payload.decode('utf-8', errors='ignore').strip()
                        if payload_start:
                            first_line = payload_start.split('\n')[0]
                            method_part = first_line.split()[0] if ' ' in first_line else None
                            if method_part and method_part.isalpha():
                                data['method'] = method_part.upper()
                    except:
                        pass

                if hasattr(receipt, 'uri') and receipt.uri:
                    data['uri'] = str(receipt.uri)
                if hasattr(receipt, 'version') and receipt.version:
                    data['version'] = str(receipt.version)

                # 如果是响应
                if hasattr(receipt, 'status') and receipt.status:
                    data['status_code'] = receipt.status
                    data['status_text'] = getattr(receipt, 'text', '')

            # 解析头部
            if hasattr(info, 'header') and info.header:
                headers = {}
                try:
                    for key, value in info.header.items():
                        headers[str(key)] = str(value)
                    data['headers'] = headers
                except Exception as header_e:
                    data['errors'].append(f"Header parsing failed: {header_e}")

            # 解析body
            if hasattr(info, 'body') and info.body:
                try:
                    data['body'] = info.body if isinstance(info.body, bytes) else str(info.body).encode('utf-8')
                except Exception as body_e:
                    data['errors'].append(f"Body parsing failed: {body_e}")

        except Exception as e:
            error_msg = f"pypcapkit HTTP parsing failed: {type(e).__name__}: {e}"
            data['errors'].append(error_msg)
            logger.debug(f"pcapkit HTTP parsing error for payload length {len(payload)}: {error_msg}")
            # 回退到自定义解析
            return self._parse_http_fallback(payload, src_port, dst_port)

        return data

    def _parse_http_fallback(self, payload: bytes, src_port: int, dst_port: int) -> Dict[str, Any]:
        """HTTP解析回退方法（简化版）"""
        data = {
            'method': None,
            'uri': None,
            'version': None,
            'headers': {},
            'body': None,
            'errors': []
        }

        try:
            payload_str = payload.decode('utf-8', errors='ignore')
            lines = payload_str.split('\n')

            if lines:
                # 解析请求行
                request_line = lines[0].strip()
                parts = request_line.split()
                if len(parts) >= 3:
                    data['method'] = parts[0]
                    data['uri'] = parts[1]
                    data['version'] = parts[2]

        except Exception as e:
            data['errors'].append(str(e))

        return data

    def _parse_ftp(self, payload: bytes, src_port: int, dst_port: int) -> Dict[str, Any]:
        """解析FTP协议"""
        data = {
            'commands': [],
            'responses': [],
            'files': [],
            'errors': []
        }

        try:
            payload_str = payload.decode('utf-8', errors='ignore')
            lines = payload_str.split('\n')

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                # FTP命令
                if re.match(r'^[A-Z]{3,4}\s', line.upper()):
                    data['commands'].append(line)
                # FTP响应
                elif re.match(r'^\d{3}\s', line):
                    data['responses'].append(line)
                # 文件名检测
                elif any(keyword in line.lower() for keyword in ['filename', 'file=', 'name=']):
                    data['files'].append(line)

        except Exception as e:
            data['errors'].append(str(e))

        return data

    def _parse_dns(self, payload: bytes, src_port: int, dst_port: int) -> Dict[str, Any]:
        """解析DNS协议"""
        data = {
            'query_type': 'unknown',
            'domain': None,
            'record_type': None,
            'errors': []
        }

        try:
            if len(payload) < 12:
                return data

            # DNS头部解析（简化）
            transaction_id = payload[0:2].hex()
            flags = payload[2:4].hex()

            # 问题数量
            qdcount = int.from_bytes(payload[4:6], 'big')

            data['query_type'] = 'query' if (payload[2] & 0x80) == 0 else 'response'

            # 尝试提取域名（简化解析）
            if qdcount > 0 and len(payload) > 12:
                try:
                    domain_parts = []
                    pos = 12
                    while pos < len(payload) and payload[pos] != 0:
                        length = payload[pos]
                        if length == 0:
                            break
                        if pos + length + 1 < len(payload):
                            part = payload[pos+1:pos+1+length].decode('utf-8', errors='ignore')
                            domain_parts.append(part)
                            pos += length + 1
                        else:
                            break

                    if domain_parts:
                        data['domain'] = '.'.join(domain_parts)

                    # 记录类型（在域名后2字节）
                    if pos + 2 < len(payload):
                        qtype = int.from_bytes(payload[pos+1:pos+3], 'big')
                        qtype_map = {
                            1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA',
                            12: 'PTR', 13: 'HINFO', 15: 'MX', 16: 'TXT',
                            28: 'AAAA', 33: 'SRV'
                        }
                        data['record_type'] = qtype_map.get(qtype, f'UNKNOWN({qtype})')

                except Exception as e:
                    data['errors'].append(f"Domain parsing failed: {e}")

        except Exception as e:
            data['errors'].append(str(e))

        return data

    def _parse_smtp(self, payload: bytes, src_port: int, dst_port: int) -> Dict[str, Any]:
        """解析SMTP协议"""
        data = {
            'commands': [],
            'responses': [],
            'emails': [],
            'errors': []
        }

        try:
            payload_str = payload.decode('utf-8', errors='ignore')
            lines = payload_str.split('\n')

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                # SMTP命令
                if re.match(r'^(EHLO|HELO|MAIL FROM|RCPT TO|DATA|QUIT|RSET|NOOP|VRFY|EXPN|HELP)', line.upper()):
                    data['commands'].append(line)
                # SMTP响应
                elif re.match(r'^\d{3}\s', line):
                    data['responses'].append(line)
                # 邮件地址检测
                elif '@' in line and ('from:' in line.lower() or 'to:' in line.lower()):
                    data['emails'].append(line)

        except Exception as e:
            data['errors'].append(str(e))

        return data

    def _parse_pop3(self, payload: bytes, src_port: int, dst_port: int) -> Dict[str, Any]:
        """解析POP3协议"""
        data = {
            'commands': [],
            'responses': [],
            'errors': []
        }

        try:
            payload_str = payload.decode('utf-8', errors='ignore')
            lines = payload_str.split('\n')

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                # POP3命令
                if re.match(r'^(USER|PASS|STAT|LIST|RETR|DELE|NOOP|RSET|QUIT|TOP|UIDL)', line.upper()):
                    data['commands'].append(line)
                # POP3响应
                elif line.startswith('+OK') or line.startswith('-ERR'):
                    data['responses'].append(line)

        except Exception as e:
            data['errors'].append(str(e))

        return data

    def _parse_imap(self, payload: bytes, src_port: int, dst_port: int) -> Dict[str, Any]:
        """解析IMAP协议"""
        data = {
            'commands': [],
            'responses': [],
            'errors': []
        }

        try:
            payload_str = payload.decode('utf-8', errors='ignore')
            lines = payload_str.split('\n')

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                # IMAP命令
                if re.match(r'^\w+\s+(LOGIN|SELECT|EXAMINE|CREATE|DELETE|RENAME|SUBSCRIBE|UNSUBSCRIBE|LIST|LSUB|STATUS|APPEND|CHECK|CLOSE|EXPUNGE|SEARCH|FETCH|STORE|COPY|UID)', line.upper()):
                    data['commands'].append(line)
                # IMAP响应
                elif line.startswith('* ') or re.match(r'^\w+\s+(OK|NO|BAD)', line.upper()):
                    data['responses'].append(line)

        except Exception as e:
            data['errors'].append(str(e))

        return data

    def _parse_telnet(self, payload: bytes, src_port: int, dst_port: int) -> Dict[str, Any]:
        """解析Telnet协议"""
        data = {
            'commands': [],
            'negotiations': [],
            'data': None,
            'errors': []
        }

        try:
            # Telnet协议有特殊的命令序列（IAC）
            if len(payload) > 0:
                iac_positions = []
                i = 0
                while i < len(payload) - 1:
                    if payload[i] == 255:  # IAC
                        iac_positions.append(i)
                        i += 2  # 跳过IAC和命令
                    else:
                        i += 1

                data['negotiations'] = len(iac_positions)

                # 提取非控制数据
                if iac_positions:
                    # 简单的数据提取（实际Telnet解析更复杂）
                    data['data'] = payload.decode('utf-8', errors='ignore').strip()
                else:
                    data['data'] = payload.decode('utf-8', errors='ignore').strip()

        except Exception as e:
            data['errors'].append(str(e))

        return data

# 全局协议解析器实例
protocol_parser = ProtocolParser()

def parse_packet_for_protocol(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                             payload: bytes, protocol: str) -> Optional[ParsedProtocol]:
    """
    解析数据包的协议内容
    """
    return protocol_parser.parse_packet(src_ip, dst_ip, src_port, dst_port, payload, protocol)