"""Aho-Corasick 多模式匹配实现（仅依赖 pyahocorasick）。

此模块强制要求 `pyahocorasick` 安装；若未安装会立刻抛出 ImportError，避免在运行时退回到性能较差的 Python 实现。
"""
from __future__ import annotations

import re
from typing import Dict, List, Tuple, Any, Iterable

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

    def load_rules(self, rules: Iterable[Any]):
        """加载规则集合（可迭代）。期望每个 rule 至少包含 `rule_id`, `pattern`, `pattern_type`。"""
        # 存储模式到规则的映射：pattern -> [rule_ids]
        self._pattern_to_rules: Dict[str, List[str]] = {}
        self._rules_with_options: List[Any] = []  # 存储带有高级选项的规则
        added_patterns = set()  # 跟踪已添加的模式

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

            self._rule_meta[rid] = {"priority": priority, "action": action, "description": getattr(r, "description", "")}

            # 检查是否有高级选项
            has_advanced_options = (
                metadata.get('depth') is not None or
                metadata.get('offset') is not None or
                metadata.get('within') is not None or
                metadata.get('distance') is not None or
                metadata.get('nocase') is True
            )

            if has_advanced_options:
                # 带有高级选项的规则，存储起来单独处理
                self._rules_with_options.append(r)
                continue

            if pattern_type == "string":
                # 获取模式列表
                if isinstance(r, dict):
                    patterns = r.get("patterns_list", lambda: [pattern])() if "patterns_list" in r else [pattern]
                else:
                    patterns = r.patterns_list() if hasattr(r, "patterns_list") else [pattern]

                for p in patterns:
                    if not p:
                        continue
                    # 记录模式到规则的映射
                    if p not in self._pattern_to_rules:
                        self._pattern_to_rules[p] = []
                    if rid not in self._pattern_to_rules[p]:
                        self._pattern_to_rules[p].append(rid)
                    # 只添加一次模式到Aho-Corasick
                    if p not in added_patterns:
                        self._aho.add(p, p)  # 使用pattern本身作为ID
                        added_patterns.add(p)
            else:
                # PCRE模式处理
                pats = []
                if isinstance(pattern, list):
                    pats = pattern
                else:
                    pats = [pattern]
                compiled = []
                for pat in pats:
                    try:
                        compiled.append(re.compile(pat))
                    except re.error:
                        continue
                if compiled:
                    self._pcre_map[rid] = compiled

    def build(self):
        self._aho.build()

    def match(self, payload: bytes) -> List[Dict[str, Any]]:
        """匹配 payload（bytes），返回匹配条目列表：{rule_id, match_text, pos, type}"""
        results: List[Dict[str, Any]] = []
        if not payload:
            return results

        text_l1 = payload.decode("latin-1")
        for end_idx, pattern, patt in self._aho.find_all(text_l1):
            # 对于每个匹配的模式，展开所有相关的规则
            rule_ids = self._pattern_to_rules.get(pattern, [pattern])
            start = end_idx - len(patt) + 1
            for rid in rule_ids:
                results.append({"rule_id": rid, "match": patt, "pos": (start, end_idx), "type": "string"})

        if self._pcre_map:
            try:
                text = payload.decode("utf-8", errors="ignore")
            except Exception:
                text = ""
            for rid, regexes in self._pcre_map.items():
                for rx in regexes:
                    m = rx.search(text)
                    if m:
                        results.append({"rule_id": rid, "match": m.group(0), "pos": m.span(), "type": "pcre"})
                        break

        # 检查带有高级选项的规则
        for rule in self._rules_with_options:
            if isinstance(rule, dict):
                rule_obj = None
                # 如果是字典格式，尝试创建Rule对象进行匹配
                try:
                    from ..models.rule import Rule
                    rule_obj = Rule(**rule)
                except:
                    continue
            else:
                rule_obj = rule

            if rule_obj and rule_obj.matches_payload(payload):
                # 获取匹配的模式
                pattern = rule_obj.pattern
                if isinstance(pattern, list):
                    pattern = pattern[0] if pattern else ""
                results.append({
                    "rule_id": rule_obj.rule_id, 
                    "match": pattern, 
                    "pos": (0, len(payload)),  # 高级选项匹配不提供精确位置
                    "type": "string_advanced"
                })

        return results


__all__ = ["AhoAutomaton", "RuleEngine"]
