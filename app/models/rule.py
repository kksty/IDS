from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any, Union
from datetime import datetime
import re


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
        """简单的匹配接口：用于单包或抓取到的 payload 快速验证。

        - 若 pattern_type == 'string'：逐个关键词做 bytes 子串查找（case-sensitive）
        - 若 pattern_type == 'pcre'：使用已编译的正则去匹配解码后的文本（utf-8 忽略错误）
        """
        if not self.enabled:
            return False

        pats = self.patterns_list()
        if self.pattern_type == "string":
            for p in pats:
                if p.encode() in payload:
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
