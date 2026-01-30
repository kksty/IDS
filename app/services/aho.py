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

        for r in rules:
            if not getattr(r, "enabled", True):
                continue
            rid = getattr(r, "rule_id", None)
            if rid is None:
                continue
            self._rule_meta[rid] = {"priority": getattr(r, "priority", 3), "action": getattr(r, "action", "alert")}
            ptype = getattr(r, "pattern_type", "string")
            if ptype == "string":
                for p in (r.patterns_list() if hasattr(r, "patterns_list") else [r.pattern]):
                    if not p:
                        continue
                    # 记录模式到规则的映射
                    if p not in self._pattern_to_rules:
                        self._pattern_to_rules[p] = []
                    if rid not in self._pattern_to_rules[p]:
                        self._pattern_to_rules[p].append(rid)
                    # 只添加一次模式到Aho-Corasick
                    if p not in [existing for existing in self._aho._A]:
                        self._aho.add(p, p)  # 使用pattern本身作为ID
            else:
                pats = []
                if isinstance(r.pattern, list):
                    pats = r.pattern
                else:
                    pats = [r.pattern]
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

        return results


__all__ = ["AhoAutomaton", "RuleEngine"]
