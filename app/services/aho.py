# -*- coding: utf-8 -*-
"""Aho-Corasick 多模式匹配实现（仅依赖 pyahocorasick）。

此模块强制要求 `pyahocorasick` 安装；若未安装会立刻抛出 ImportError，避免在运行时退回到性能较差的 Python 实现。
"""
from __future__ import annotations

import re
from typing import Dict, List, Tuple, Any, Iterable, Optional, Set

try:
    import ahocorasick as _pyahocorasick  # type: ignore
except Exception as exc:  # pragma: no cover - installation-time error
    raise ImportError(
        "pyahocorasick is required by app.services.aho. Install it with: pip install pyahocorasick"
    ) from exc


class _PyAho:
    """包装 pyahocorasick 的简洁接口"""

    def __init__(self):
        self._A = _pyahocorasick.Automaton()

    def add(self, pattern: str, pid: Any):
        self._A.add_word(pattern, (pid, pattern))

    def build(self):
        self._A.make_automaton()

    def find_all(self, text: str) -> List[Tuple[int, Any, str]]:
        results: List[Tuple[int, Any, str]] = []
        for end_idx, (pid, patt) in self._A.iter(text):
            results.append((end_idx, pid, patt))
        return results


AhoAutomaton = _PyAho


class RuleEngine:
    """简单的规则引擎：支持 string-patterns (Aho) 与 pcre-patterns (regex)。

    用法：
      engine = RuleEngine()
      engine.load_rules(rules_iterable)
      engine.build()
      matches = engine.match(payload_bytes)
    返回：匹配到的规则 id 列表及匹配内容
    """

    def __init__(self):
        self._aho = AhoAutomaton()
        self._pcre_map: Dict[str, List[re.Pattern]] = {}  # rule_id -> list of compiled regex
        self._rule_meta: Dict[str, Dict[str, Any]] = {}  # rule_id -> metadata (priority, action...)
        self._rules_with_content: Set[str] = set()
        self._rules_with_pcre: Set[str] = set()

    def load_rules(self, rules: Iterable[Any]):
        """加载规则集合（可迭代）。期望每个 rule 至少包含 `rule_id`, `pattern`, `pattern_type`。"""
        # 存储模式到规则的映射：pattern -> [rule_ids]
        self._pattern_to_rules: Dict[str, List[str]] = {}
        self._rules_with_options: List[Any] = []  # 已废弃：保留占位
        added_patterns = set()  # 跟踪已添加的模式
        self._rules_with_content.clear()
        self._rules_with_pcre.clear()

        for r in rules:
            # 处理字典格式的规则
            if isinstance(r, dict):
                enabled = r.get("enabled", True)
                rid = r.get("rule_id")
                priority = r.get("priority", 3)
                action = r.get("action", "alert")
                pattern = r.get("pattern")
                pattern_type = r.get("pattern_type", "string")
                metadata = r.get("metadata") or {}
            else:
                # 处理对象格式的规则
                enabled = getattr(r, "enabled", True)
                rid = getattr(r, "rule_id", None)
                priority = getattr(r, "priority", 3)
                action = getattr(r, "action", "alert")
                pattern = getattr(r, "pattern", None)
                pattern_type = getattr(r, "pattern_type", "string")
                metadata = getattr(r, "metadata") or {}

            if not enabled or rid is None or pattern is None:
                continue

            self._rule_meta[rid] = {
                "priority": priority,
                "action": action,
                "description": getattr(r, "description", ""),
                "metadata": metadata,
                "byte_tests": metadata.get("byte_tests") if isinstance(metadata, dict) else None,
                "byte_test_only": metadata.get("byte_test_only") if isinstance(metadata, dict) else False,
                "ip_proto": metadata.get("ip_proto") if isinstance(metadata, dict) else None,
            }

            if pattern_type == "string":
                self._rules_with_content.add(rid)
                # 获取模式列表
                if isinstance(r, dict):
                    patterns = r.get("patterns_list", lambda: [pattern])() if "patterns_list" in r else [pattern]
                else:
                    patterns = r.patterns_list() if hasattr(r, "patterns_list") else [pattern]

                # 语义统一：同一条规则多个字符串条件应为 AND。
                # 旧逻辑仅靠 Aho 命中任一 pattern 就会让规则进入候选，导致表现为 OR。
                # 这里在缺失时自动填充 metadata.content_patterns，让上层二次校验执行 AND。
                try:
                    pats_clean = [_normalize_snort_content_for_match(p) for p in patterns]
                    pats_clean = [p for p in pats_clean if p]
                    if isinstance(metadata, dict) and len(pats_clean) > 1 and not metadata.get("content_patterns"):
                        metadata = dict(metadata)
                        metadata["content_patterns"] = pats_clean
                        # 同步到 rule_meta，确保 match_payload() 看到更新后的 metadata
                        if rid in self._rule_meta:
                            self._rule_meta[rid]["metadata"] = metadata
                except Exception:
                    pass

                for p in patterns:
                    norm = _normalize_snort_content_for_match(p)
                    if not norm:
                        continue
                    # 记录模式到规则的映射
                    if norm not in self._pattern_to_rules:
                        self._pattern_to_rules[norm] = []
                    if rid not in self._pattern_to_rules[norm]:
                        self._pattern_to_rules[norm].append(rid)
                    # 只添加一次模式到Aho-Corasick
                    if norm not in added_patterns:
                        self._aho.add(norm, norm)  # 使用pattern本身作为ID
                        added_patterns.add(norm)
            elif pattern_type == "pcre":
                # PCRE模式处理
                pats = []
                if isinstance(pattern, list):
                    pats = pattern
                else:
                    pats = [pattern]
                compiled = []
                for pat in pats:
                    try:
                        compiled.append(_compile_pcre(str(pat)))
                    except re.error:
                        continue
                    except Exception:
                        continue
                compiled = [c for c in compiled if c is not None]
                if compiled:
                    self._pcre_map[rid] = compiled
                    self._rules_with_pcre.add(rid)

    def build(self):
        self._aho.build()

    def match_content(self, payload: bytes, candidate_rule_ids: Optional[Set[str]] = None) -> Tuple[List[Dict[str, Any]], Set[str]]:
        """只做Aho匹配（string），返回匹配条目列表与命中的 rule_id 集合。"""
        results: List[Dict[str, Any]] = []
        matched_rules: Set[str] = set()
        if not payload:
            return results, matched_rules

        text_l1 = payload.decode("latin-1")
        for end_idx, pattern, patt in self._aho.find_all(text_l1):
            rule_ids = self._pattern_to_rules.get(pattern, [pattern])
            start = end_idx - len(patt) + 1
            for rid in rule_ids:
                if candidate_rule_ids is not None and rid not in candidate_rule_ids:
                    continue
                matched_rules.add(rid)
                results.append({"rule_id": rid, "match": patt, "pos": (start, end_idx), "type": "string"})

        return results, matched_rules

    def match_pcre(self, payload: bytes, rule_ids: Iterable[str]) -> List[Dict[str, Any]]:
        """仅对指定规则执行PCRE匹配，返回匹配条目列表。"""
        results: List[Dict[str, Any]] = []
        if not payload:
            return results
        rule_id_set = set(rule_ids)
        if not rule_id_set:
            return results

        try:
            text = payload.decode("utf-8", errors="ignore")
        except Exception:
            text = ""

        for rid in rule_id_set:
            regexes = self._pcre_map.get(rid)
            if not regexes:
                continue

            # Snort 语义：同一条规则中的多个 pcre 选项是 AND 关系。
            # 需要全部匹配才算命中；OR 请在正则内部使用 '|' 表达。
            first_match = None
            for rx in regexes:
                try:
                    m = rx.search(text)
                except Exception:
                    first_match = None
                    break
                if not m:
                    first_match = None
                    break
                if first_match is None:
                    first_match = m

            if first_match is not None:
                results.append({"rule_id": rid, "match": first_match.group(0), "pos": first_match.span(), "type": "pcre"})

        return results

    def match(self, payload: bytes) -> List[Dict[str, Any]]:
        """兼容旧接口：Aho + 全量PCRE匹配。"""
        results, _ = self.match_content(payload)
        if self._pcre_map:
            results.extend(self.match_pcre(payload, self._pcre_map.keys()))
        return results


def _compile_pcre(pat: str) -> Optional[re.Pattern]:
    """Compile PCRE patterns.

    Supports Snort-style delimiters and flags: /.../i, /.../ismx.
    If no delimiter form is detected, compiles as a normal Python regex.
    """
    if pat is None:
        return None
    s = str(pat).strip()
    if len(s) >= 2 and s.startswith("/") and "/" in s[1:]:
        last = s.rfind("/")
        if last > 0:
            body = s[1:last]
            flags_str = s[last + 1 :]
            # Snort/PCRE escaping for delimiter
            body = body.replace("\\/", "/")
            flags = 0
            for ch in flags_str:
                if ch == "i":
                    flags |= re.IGNORECASE
                elif ch == "m":
                    flags |= re.MULTILINE
                elif ch == "s":
                    flags |= re.DOTALL
                elif ch == "x":
                    flags |= re.VERBOSE
                else:
                    # ignore unknown flags (Snort supports more than Python)
                    continue
            return re.compile(body, flags=flags)
    return re.compile(s)


def _normalize_snort_content_for_match(pat: Any) -> str:
    """Normalize Snort-style content strings into a latin-1 string suitable for matching.

    Supports:
    - Pure text
    - Hex blocks: |01 02 0a|
    - Mixed: |00 01|Hello|02 03|
    - Byte escapes: \x01\x02

    Returns a unicode string where each codepoint 0-255 corresponds to a byte value (latin-1).
    """
    if pat is None:
        return ""
    s = str(pat)
    if s == "":
        return ""

    # Fast path for plain text (no Snort hex markers / escapes)
    if "|" not in s and "\\x" not in s:
        return s

    out = bytearray()
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if ch == "|":
            j = s.find("|", i + 1)
            if j == -1:
                out.extend(ch.encode("latin-1", errors="ignore"))
                i += 1
                continue
            hex_part = s[i + 1 : j]
            try:
                out.extend(bytes.fromhex(hex_part.replace(" ", "")))
            except Exception:
                out.extend(s[i : j + 1].encode("latin-1", errors="ignore"))
            i = j + 1
            continue

        if s.startswith("\\x", i) and i + 3 < n:
            try:
                out.append(int(s[i + 2 : i + 4], 16))
                i += 4
                continue
            except Exception:
                pass

        out.extend(ch.encode("latin-1", errors="ignore"))
        i += 1

    return out.decode("latin-1", errors="ignore")


__all__ = ["AhoAutomaton", "RuleEngine"]
