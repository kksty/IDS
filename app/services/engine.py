# -*- coding: utf-8 -*-
"""规则引擎管理：维护规则集合并封装 `RuleEngine` 的重建/匹配接口。

支持优化的多级匹配：
1. 快速端口/协议过滤
2. 规则分组和索引
3. Aho-Corasick模式匹配
"""
from typing import List, Dict, Any, Optional, Tuple
from threading import RLock, Thread, Event
import time
import json
import ipaddress

from app.services.aho import RuleEngine

# 运行时的规则集合（保存原始 Rule 对象）
_rules: List[Any] = []
_engine: Optional[RuleEngine] = None
_lock = RLock()

# 优化的规则索引：(protocol, dst_port) -> [rule_ids]
_port_rule_index: Dict[Tuple[str, Optional[str]], List[str]] = {}
_protocol_rule_index: Dict[str, List[str]] = {}

# 后台重建管理
_rebuild_thread: Optional[Thread] = None
_rebuild_stop = Event()
_rebuild_in_progress = Event()


def _build_engine_from_rules(rules: List[Any]) -> RuleEngine:
    """从规则列表构建优化的规则引擎"""
    eng = RuleEngine()

    # 构建规则索引
    global _port_rule_index, _protocol_rule_index
    _port_rule_index.clear()
    _protocol_rule_index.clear()

    for r in rules:
        if not getattr(r, "enabled", True):
            continue

        rid = getattr(r, "rule_id", None)
        if rid is None:
            continue

        # 构建端口索引
        protocol = getattr(r, "protocol", "").upper() if getattr(r, "protocol") else ""
        dst_ports = getattr(r, "dst_ports", None) or []

        # 为每个端口创建索引
        if dst_ports:
            for port in dst_ports:
                key = (protocol, str(port))
                if key not in _port_rule_index:
                    _port_rule_index[key] = []
                _port_rule_index[key].append(rid)
        else:
            # 无端口限制的规则
            key = (protocol, None)
            if key not in _port_rule_index:
                _port_rule_index[key] = []
            _port_rule_index[key].append(rid)

        # 构建协议索引
        if protocol not in _protocol_rule_index:
            _protocol_rule_index[protocol] = []
        _protocol_rule_index[protocol].append(rid)

    # 加载所有规则到引擎（引擎内部会处理模式匹配）
    eng.load_rules(rules)
    eng.build()
    return eng


def _swap_engine(new_eng: RuleEngine):
    global _engine
    with _lock:
        _engine = new_eng


def _rebuild_engine_sync():
    """同步重建并原子切换（用于启动/强制刷新）。"""
    global _rules
    new_eng = _build_engine_from_rules(list(_rules))
    _swap_engine(new_eng)


def _rebuild_worker(rules_snapshot: List[Any]):
    try:
        _rebuild_in_progress.set()
        from app.metrics import ENGINE_REBUILD_SECONDS, ENGINE_READY

        start = None
        try:
            start = time.time()
            with ENGINE_REBUILD_SECONDS.time():
                new_eng = _build_engine_from_rules(rules_snapshot)
            _swap_engine(new_eng)
            ENGINE_READY.set(1)
        except Exception:
            ENGINE_READY.set(0)
            raise
        finally:
            if start is not None:
                pass
    finally:
        _rebuild_in_progress.clear()


def rebuild_async():
    """在后台线程中重建引擎并原子切换。

    如果已有重建进行中则不会重复启动（去抖）。
    """
    global _rebuild_thread
    if _rebuild_in_progress.is_set():
        return
    # snapshot rules to avoid holding lock during build
    with _lock:
        snapshot = list(_rules)

    t = Thread(target=_rebuild_worker, args=(snapshot,), daemon=True)
    _rebuild_thread = t
    t.start()


def list_rules() -> List[Any]:
    with _lock:
        return list(_rules)


def add_rule(rule: Any, rebuild: bool = True):
    """添加规则；默认异步重建引擎以避免阻塞。"""
    with _lock:
        _rules.append(rule)
    if rebuild:
        rebuild_async()


def remove_rule(rule_id: str, rebuild: bool = True) -> bool:
    """删除规则（通过 rule_id），返回是否删除成功，并可选异步重建引擎。"""
    with _lock:
        orig = len(_rules)
        _rules[:] = [r for r in _rules if getattr(r, "rule_id", None) != rule_id]
        changed = len(_rules) != orig
    if changed and rebuild:
        rebuild_async()
    return changed


def remove_rules(rule_ids: List[str], rebuild: bool = True) -> int:
    """批量删除规则（通过 rule_id 列表），返回删除的规则数量，并可选异步重建引擎。"""
    if not rule_ids:
        return 0
    
    with _lock:
        orig = len(_rules)
        _rules[:] = [r for r in _rules if getattr(r, "rule_id", None) not in rule_ids]
        deleted_count = orig - len(_rules)
    
    if deleted_count > 0 and rebuild:
        rebuild_async()
    return deleted_count


def match_payload(payload: bytes, protocol: str = "", dst_port: Optional[str] = None,
                  src_ip: Optional[str] = None, src_port: Optional[str] = None,
                  dst_ip: Optional[str] = None,
                  packet_info: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    Args:
        payload: 要匹配的载荷数据
        protocol: 协议类型 (TCP/UDP等)
        dst_port: 目的端口
        src_ip: 源IP地址
        src_port: 源端口
        dst_ip: 目的IP地址
    Returns:
        匹配结果列表
    """
    # 在锁内一次性快照当前引擎和规则集合，避免在匹配过程中与重建线程竞争
    with _lock:
        eng = _engine
        rules_snapshot = list(_rules)
    if eng is None:
        return []

    # 1. 首先进行端口/协议/方向预过滤（基于快照，避免遍历过程中被修改）
    candidate_rule_ids = _get_candidate_rules(
        rules_snapshot,
        protocol.upper(),
        dst_port,
        src_ip,
        src_port,
        dst_ip,
    )

    if not candidate_rule_ids:
        return []

    candidate_rule_id_set = set(candidate_rule_ids)

    sticky_buffers = {}
    try:
        sticky_buffers = (packet_info or {}).get("sticky_buffers") or {}
    except Exception:
        sticky_buffers = {}

    def _buffer_key_for_rule(rule_id: str) -> str:
        try:
            meta = eng._rule_meta.get(rule_id, {})
            md = meta.get("metadata") or {}
            if md.get("dns_query"):
                return "dns_query"
            if md.get("smtp_command"):
                return "smtp_command"
            if md.get("pop_command"):
                return "pop_command"
        except Exception:
            pass
        return "raw"

    # 2. 按 buffer 做 AC 匹配（content），让 dns_query/ftp_command 等规则在语义字段上匹配而非原始 payload
    group_map: Dict[str, set] = {}
    for rid in candidate_rule_ids:
        bk = _buffer_key_for_rule(rid)
        if bk not in group_map:
            group_map[bk] = set()
        group_map[bk].add(rid)

    all_matches = []
    content_matched_rule_ids: set[str] = set()
    for bk, rid_set in group_map.items():
        buf = payload if bk == "raw" else sticky_buffers.get(bk, b"")
        if not buf:
            continue
        matches, matched_ids = eng.match_content(buf, rid_set)
        for m in matches:
            try:
                m["_buffer"] = bk
            except Exception:
                pass
        all_matches.extend(matches)
        try:
            content_matched_rule_ids |= set(matched_ids)
        except Exception:
            pass

    # 3. 过滤出候选规则中的匹配结果（content 命中）
    filtered_matches = []
    for match in all_matches:
        rule_id = match.get("rule_id")
        if not rule_id:
            continue
        if rule_id not in candidate_rule_id_set:
            continue
        bk = match.get("_buffer") or "raw"
        buf = payload if bk == "raw" else sticky_buffers.get(bk, b"")
        # 从规则元数据中添加消息
        meta = eng._rule_meta.get(rule_id, {})
        match["message"] = meta.get("description", "")
        if "priority" in meta:
            match["priority"] = meta.get("priority")
        # 过滤高级选项（如 ip_proto/ttl/flags/icmp 等）
        if not _match_advanced_filters(meta, packet_info, match.get("pos"), buf):
            continue
        metadata = meta.get("metadata") or {}
        if not _match_content_patterns(buf, metadata):
            continue
        if metadata.get("content_patterns") and eng._pcre_map.get(rule_id):
            if not _pcre_matches(buf, eng._pcre_map.get(rule_id, [])):
                continue
        # 如果规则包含 byte_test，则必须满足 byte_test 条件
        byte_tests = meta.get("byte_tests") or (meta.get("metadata") or {}).get("byte_tests")
        if byte_tests:
            # byte_test 更接近“原始 payload 偏移语义”，这里仍对原始 payload 求值
            if not _eval_byte_tests(payload, byte_tests):
                continue
        try:
            match.pop("_buffer", None)
        except Exception:
            pass
        filtered_matches.append(match)

    # 4. 对 pcre-only 规则做匹配（无 content_patterns 的规则）
    pcre_only_rule_ids = []
    for rule_id in candidate_rule_ids:
        if rule_id in content_matched_rule_ids:
            continue
        if rule_id not in eng._pcre_map:
            continue
        meta = eng._rule_meta.get(rule_id, {})
        metadata = meta.get("metadata") or {}
        if rule_id in eng._rules_with_content:
            continue
        pcre_only_rule_ids.append(rule_id)

    # 对 pcre-only 规则也按 buffer 分组匹配（例如 dns_query + pcre）
    pcre_group_map: Dict[str, List[str]] = {}
    for rid in pcre_only_rule_ids:
        bk = _buffer_key_for_rule(rid)
        if bk not in pcre_group_map:
            pcre_group_map[bk] = []
        pcre_group_map[bk].append(rid)

    for bk, rid_list in pcre_group_map.items():
        buf = payload if bk == "raw" else sticky_buffers.get(bk, b"")
        if not buf:
            continue

        # 先用 content_patterns 做一次廉价预筛，减少不必要的正则开销
        rid_list_prefiltered = []
        for rid in rid_list:
            meta = eng._rule_meta.get(rid, {})
            metadata = meta.get("metadata") or {}
            if not _match_content_patterns(buf, metadata):
                continue
            rid_list_prefiltered.append(rid)

        for match in eng.match_pcre(buf, rid_list_prefiltered):
            rule_id = match.get("rule_id")
            if not rule_id:
                continue
            meta = eng._rule_meta.get(rule_id, {})
            match["message"] = meta.get("description", "")
            if "priority" in meta:
                match["priority"] = meta.get("priority")
            if not _match_advanced_filters(meta, packet_info, match.get("pos"), buf):
                continue
            metadata = meta.get("metadata") or {}
            byte_tests = meta.get("byte_tests") or (meta.get("metadata") or {}).get("byte_tests")
            if byte_tests:
                if not _eval_byte_tests(payload, byte_tests):
                    continue
            filtered_matches.append(match)

    # 对 byte_test-only 规则进行检测（没有内容匹配的情况）
    matched_rule_ids = {m.get("rule_id") for m in filtered_matches}
    for rule_id in candidate_rule_ids:
        if rule_id in matched_rule_ids:
            continue
        meta = eng._rule_meta.get(rule_id, {})
        if not _match_advanced_filters(meta, packet_info, None, payload):
            continue
        metadata = meta.get("metadata") or {}
        if not _match_content_patterns(payload, metadata):
            continue
        if metadata.get("content_patterns") and eng._pcre_map.get(rule_id):
            if not _pcre_matches(payload, eng._pcre_map.get(rule_id, [])):
                continue
        byte_tests = meta.get("byte_tests") or (meta.get("metadata") or {}).get("byte_tests")
        byte_test_only = meta.get("byte_test_only") or (meta.get("metadata") or {}).get("byte_test_only")
        if not byte_tests:
            continue
        if not byte_test_only:
            continue
        if _eval_byte_tests(payload, byte_tests):
            filtered_matches.append({
                "rule_id": rule_id,
                "match": "byte_test",
                "type": "byte_test",
                "message": meta.get("description", ""),
                "priority": meta.get("priority"),
            })

    return filtered_matches


def _eval_byte_tests(payload: bytes, byte_tests: List[Dict[str, Any]]) -> bool:
    """Evaluate all byte_test conditions against payload. All must pass."""
    if not byte_tests:
        return True
    if payload is None:
        return False
    for bt in byte_tests:
        try:
            if bt.get("relative"):
                # relative not supported in this lightweight implementation
                return False
            num_bytes = int(bt.get("bytes", 0))
            offset = int(bt.get("offset", 0))
            if num_bytes <= 0 or offset < 0:
                return False
            end = offset + num_bytes
            if end > len(payload):
                return False
            endian = bt.get("endian", "big")
            val = int.from_bytes(payload[offset:end], byteorder=endian, signed=False)
            target = int(bt.get("value"))
            op = str(bt.get("op"))
            if op == ">":
                if not (val > target):
                    return False
            elif op == "<":
                if not (val < target):
                    return False
            elif op == ">=":
                if not (val >= target):
                    return False
            elif op == "<=":
                if not (val <= target):
                    return False
            elif op == "=" or op == "==":
                if not (val == target):
                    return False
            elif op == "!=" or op == "!":
                if not (val != target):
                    return False
            elif op == "&":
                if not ((val & target) == target):
                    return False
            elif op == "!&":
                if not ((val & target) == 0):
                    return False
            else:
                # unsupported operator
                return False
        except Exception:
            return False
    return True


def _match_content_patterns(payload: Optional[bytes], metadata: Dict[str, Any]) -> bool:
    patterns = metadata.get("content_patterns") if isinstance(metadata, dict) else None
    if not patterns:
        return True
    if payload is None:
        return False

    def _as_int(val: Any) -> Optional[int]:
        if val is None:
            return None
        try:
            return int(val)
        except Exception:
            return None

    def _as_bool(val: Any) -> bool:
        if isinstance(val, bool):
            return val
        if val is None:
            return False
        s = str(val).strip().lower()
        return s in ("1", "true", "yes", "y", "on")

    payload_bytes = payload or b""
    global_nocase = bool(metadata.get("nocase"))

    options = metadata.get("content_options")
    options_list: Optional[list] = options if isinstance(options, list) else None

    # 向后兼容：旧导入器可能把 offset/depth/within/distance 写在 metadata 顶层
    # 仅在没有 content_options 时，将其应用到第一条 content。
    if options_list is None:
        legacy_any = any(metadata.get(k) is not None for k in ("offset", "depth", "within", "distance"))
        if legacy_any:
            options_list = [
                {
                    "offset": metadata.get("offset"),
                    "depth": metadata.get("depth"),
                    "within": metadata.get("within"),
                    "distance": metadata.get("distance"),
                    "nocase": metadata.get("nocase"),
                }
            ]

    cursor_end = 0
    for idx, pat in enumerate(patterns):
        if not pat:
            continue

        pat_bytes = str(pat).encode("latin-1", errors="ignore")
        if not pat_bytes:
            continue

        opt: Dict[str, Any] = {}
        if options_list is not None and idx < len(options_list) and isinstance(options_list[idx], dict):
            opt = options_list[idx]

        nocase_this = global_nocase or _as_bool(opt.get("nocase"))
        offset = _as_int(opt.get("offset"))
        depth = _as_int(opt.get("depth"))
        distance = _as_int(opt.get("distance"))
        within = _as_int(opt.get("within"))

        # 计算搜索窗口
        if idx == 0:
            start = max(0, offset or 0)
        else:
            start = cursor_end
            if distance is not None and distance >= 0:
                start = cursor_end + distance
            if offset is not None and offset >= 0:
                start = max(start, offset)

        start = max(0, start)
        end = len(payload_bytes)

        # depth：限制搜索窗口长度（相对 offset 或 start）
        if depth is not None and depth >= 0:
            depth_base = offset if (offset is not None and offset >= 0) else start
            end = min(end, depth_base + depth)

        # within：限制匹配起点相对上一个匹配结束位置
        if idx > 0 and within is not None and within >= 0:
            max_start = cursor_end + within
            end = min(end, max_start + len(pat_bytes))

        if end < start:
            return False
        if start > len(payload_bytes):
            return False

        segment = payload_bytes[start:end]
        if nocase_this:
            pos = segment.lower().find(pat_bytes.lower())
        else:
            pos = segment.find(pat_bytes)
        if pos < 0:
            return False

        match_start = start + pos
        if idx > 0 and within is not None and within >= 0:
            if match_start > cursor_end + within:
                return False

        cursor_end = match_start + len(pat_bytes)

    return True


def _pcre_matches(payload: Optional[bytes], regexes: List[Any]) -> bool:
    if not regexes:
        return True
    try:
        text = (payload or b"").decode("utf-8", errors="ignore")
    except Exception:
        text = ""

    # Snort 语义：同一条规则中的多个 pcre 选项是 AND 关系。
    # 即：必须全部匹配才算命中；单条规则内的 OR 应由正则自身用 '|' 表达。
    any_valid = False
    for rx in regexes:
        try:
            m = rx.search(text)
            any_valid = True
        except Exception:
            return False
        if not m:
            return False
    return any_valid


def _parse_flow_tokens(flow_val: Any) -> List[str]:
    if flow_val is None:
        return []
    if isinstance(flow_val, list):
        tokens = []
        for item in flow_val:
            if item is None:
                continue
            tokens.extend([t.strip().lower() for t in str(item).split(",") if t.strip()])
        return tokens
    return [t.strip().lower() for t in str(flow_val).split(",") if t.strip()]


def _normalize_flag_string(val: Any) -> str:
    if val is None:
        return ""
    s = str(val).upper()
    return "".join(ch for ch in s if ch.isalpha())


def _match_advanced_filters(meta: Dict[str, Any], packet_info: Optional[Dict[str, Any]], match_pos: Optional[Any], payload: Optional[bytes]) -> bool:
    if not meta:
        return True
    metadata = meta.get("metadata") or {}
    if not isinstance(metadata, dict):
        return True

    pkt = packet_info or {}

    # dsize
    # Snort 语义（简化支持）：
    # - dsize:100
    # - dsize:>100, >=100, <100, <=100
    # - dsize:100<>200 (inclusive)
    # - dsize:100-200 (inclusive)
    # - dsize:!100 或 !>100（negate）
    dsize_rule = metadata.get("dsize")
    if dsize_rule is not None:
        payload_len = len(payload) if payload is not None else 0
        expr = str(dsize_rule).strip().replace(" ", "")
        negate = False
        if expr.startswith("!"):
            negate = True
            expr = expr[1:]

        ok = True
        try:
            if "<>" in expr:
                left, right = expr.split("<>", 1)
                lo = int(left)
                hi = int(right)
                ok = lo <= payload_len <= hi
            elif "-" in expr and expr.count("-") == 1 and not expr.startswith("-"):
                left, right = expr.split("-", 1)
                lo = int(left)
                hi = int(right)
                ok = lo <= payload_len <= hi
            elif expr.startswith(">="):
                ok = payload_len >= int(expr[2:])
            elif expr.startswith("<="):
                ok = payload_len <= int(expr[2:])
            elif expr.startswith(">"):
                ok = payload_len > int(expr[1:])
            elif expr.startswith("<"):
                ok = payload_len < int(expr[1:])
            else:
                ok = payload_len == int(expr)
        except Exception:
            return False

        if negate:
            ok = not ok
        if not ok:
            return False

    # Sticky buffer / service hints（简化）：如果规则声明了特定协议缓冲区，则要求 packet_info.app_proto 匹配。
    app_proto = (pkt.get("app_proto") or "").lower()
    if metadata.get("dns_query"):
        if app_proto != "dns":
            return False
    if metadata.get("smtp_command"):
        if app_proto != "smtp":
            return False
    if metadata.get("pop_command"):
        if app_proto != "pop3":
            return False

    # ip_id
    if metadata.get("ip_id") is not None:
        try:
            rule_ip_id = int(metadata.get("ip_id"))
            pkt_ip_id = int(pkt.get("ip_id")) if pkt.get("ip_id") is not None else None
        except Exception:
            return False
        if pkt_ip_id is None or pkt_ip_id != rule_ip_id:
            return False

    # ip_proto
    if metadata.get("ip_proto") is not None:
        try:
            rule_ip_proto = int(metadata.get("ip_proto"))
            pkt_ip_proto = int(pkt.get("ip_proto")) if pkt.get("ip_proto") is not None else None
        except Exception:
            return False
        if pkt_ip_proto is None or pkt_ip_proto != rule_ip_proto:
            return False

    # TCP flags
    rule_flags = metadata.get("flags")
    if rule_flags:
        pkt_flags = _normalize_flag_string(pkt.get("flags"))
        rule_flags_norm = _normalize_flag_string(rule_flags)
        if not pkt_flags or not rule_flags_norm:
            return False
        if any(flag not in pkt_flags for flag in rule_flags_norm):
            return False

    # isdataat
    isdataat_list = metadata.get("isdataat") or []
    if isdataat_list:
        payload_len = len(payload) if payload is not None else 0
        base = 0
        if isinstance(match_pos, (list, tuple)) and len(match_pos) >= 2:
            try:
                base = int(match_pos[1]) + 1
            except Exception:
                base = 0
        for ida in isdataat_list:
            if not isinstance(ida, dict):
                return False
            offset = ida.get("offset")
            if offset is None:
                return False
            try:
                offset_val = int(offset)
            except Exception:
                return False
            use_relative = bool(ida.get("relative"))
            negated = bool(ida.get("negated"))
            check_base = base if use_relative else 0
            has_data = payload_len > (check_base + offset_val)
            if negated:
                if has_data:
                    return False
            else:
                if not has_data:
                    return False

    # flow keywords
    flow_tokens = _parse_flow_tokens(metadata.get("flow"))
    if flow_tokens:
        flow_dir = pkt.get("flow_dir")
        flow_established = pkt.get("flow_established")
        stream_flag = pkt.get("stream")

        dir_expected = set()
        if "to_client" in flow_tokens:
            dir_expected.add("to_client")
        if "to_server" in flow_tokens:
            dir_expected.add("to_server")
        if "from_client" in flow_tokens:
            dir_expected.add("to_server")
        if "from_server" in flow_tokens:
            dir_expected.add("to_client")

        if dir_expected:
            # 部分协议/场景下（例如 UDP）我们没有可靠的 flow 方向追踪。
            # 若 flow_dir 缺失，则不因方向关键字直接判失败；有值时才严格校验。
            if flow_dir is not None and flow_dir not in dir_expected:
                return False

        if "only_stream" in flow_tokens:
            if stream_flag is not True:
                return False
        if "no_stream" in flow_tokens:
            if stream_flag is True:
                return False

        # established/not_established: 仅当 flow_established 明确为 False 时判为不匹配；
        # 为 None（如 UDP、或 flow 状态未计算）时放行，避免规则完全无法命中。
        if "stateless" not in flow_tokens:
            if "established" in flow_tokens:
                if flow_established is False:
                    return False
            if "not_established" in flow_tokens:
                if flow_established is True:
                    return False

    return True


def _get_candidate_rules(rules: List[Any], protocol: str, dst_port: Optional[str] = None,
                         src_ip: Optional[str] = None, src_port: Optional[str] = None,
                         dst_ip: Optional[str] = None) -> List[str]:
    """获取候选规则ID列表（基于端口优先级排序，所有规则都参与但按匹配度排序）"""
    candidates = []

    # 基于当前快照中的所有规则进行方向过滤
    for rule in rules:
        if not getattr(rule, "enabled", True):
            continue

        rule_id = getattr(rule, "rule_id", None)
        if rule_id is None:
            continue

        # 检查协议匹配（可选）：如果规则指定了协议，则必须匹配；如果没指定，则允许
        rule_protocol = getattr(rule, "protocol", "").upper() if getattr(rule, "protocol") else ""
        if rule_protocol and rule_protocol != protocol:
            if rule_protocol != "IP":
                continue  # 规则指定了特定协议但不匹配，跳过

        # 检查方向匹配（现在包括IP和端口）
        direction = getattr(rule, "direction", "->")
        direction_match = _matches_direction(src_ip, src_port, dst_ip, dst_port, rule, direction)

        if direction_match:
            # 计算匹配优先级：端口匹配 > IP匹配 > 协议匹配
            priority = _calculate_match_priority(src_ip, src_port, dst_ip, dst_port, rule)
            candidates.append((rule_id, priority))

    # 按优先级排序：高优先级（匹配度更高）在前
    candidates.sort(key=lambda x: x[1], reverse=True)
    return [rule_id for rule_id, _ in candidates]


def _calculate_match_priority(src_ip: Optional[str], src_port: Optional[str],
                            dst_ip: Optional[str], dst_port: Optional[str], rule) -> int:
    """计算规则匹配优先级：端口匹配 > IP匹配 > 协议匹配"""
    priority = 0

    rule_src = getattr(rule, "src", "any")
    rule_dst = getattr(rule, "dst", "any")
    rule_src_ports = getattr(rule, "src_ports", None) or []
    rule_dst_ports = getattr(rule, "dst_ports", None) or []

    # 端口匹配优先级（最高，+100分）
    port_score = 0
    if rule_dst_ports and dst_port and str(dst_port) in [str(p) for p in rule_dst_ports]:
        port_score += 50  # 目的端口匹配
    if rule_src_ports and src_port and str(src_port) in [str(p) for p in rule_src_ports]:
        port_score += 50  # 源端口匹配
    if port_score > 0:
        priority += 100 + port_score

    # IP匹配优先级（中等，+10分）
    ip_score = 0
    if rule_src != "any" and src_ip == rule_src:
        ip_score += 5  # 源IP匹配
    if rule_dst != "any" and dst_ip == rule_dst:
        ip_score += 5  # 目的IP匹配
    if ip_score > 0:
        priority += 10 + ip_score

    # 协议匹配优先级（基础，+1分）
    rule_protocol = getattr(rule, "protocol", "").upper() if getattr(rule, "protocol") else ""
    if rule_protocol:
        priority += 1  # 有协议指定就加分

    return priority


def _matches_direction(src_ip: Optional[str], src_port: Optional[str],
                      dst_ip: Optional[str], dst_port: Optional[str],
                      rule, direction: str) -> bool:
    """检查流量方向是否匹配规则方向"""
    rule_src = getattr(rule, "src", "any")
    rule_dst = getattr(rule, "dst", "any")
    rule_src_ports = getattr(rule, "src_ports", None) or []
    rule_dst_ports = getattr(rule, "dst_ports", None) or []

    if direction == "->":
        # 单向匹配：packet.src->packet.dst 必须等于 rule.src->rule.dst
        # 并且端口也要匹配
        src_ip_match = _ip_matches(rule_src, src_ip)
        dst_ip_match = _ip_matches(rule_dst, dst_ip)

        src_port_match = not rule_src_ports or (src_port and str(src_port) in [str(p) for p in rule_src_ports])
        dst_port_match = not rule_dst_ports or (dst_port and str(dst_port) in [str(p) for p in rule_dst_ports])

        return src_ip_match and dst_ip_match and src_port_match and dst_port_match

    elif direction == "<>":
        # 双向匹配：允许两个方向
        # 正向：packet.src/src_port -> packet.dst/dst_port == rule.src/src_ports -> rule.dst/dst_ports
        forward_src_ip = _ip_matches(rule_src, src_ip)
        forward_dst_ip = _ip_matches(rule_dst, dst_ip)
        forward_src_port = not rule_src_ports or (src_port and str(src_port) in [str(p) for p in rule_src_ports])
        forward_dst_port = not rule_dst_ports or (dst_port and str(dst_port) in [str(p) for p in rule_dst_ports])
        forward_match = forward_src_ip and forward_dst_ip and forward_src_port and forward_dst_port

        # 反向：packet.src/src_port -> packet.dst/dst_port == rule.dst/dst_ports -> rule.src/src_ports
        reverse_src_ip = _ip_matches(rule_dst, src_ip)
        reverse_dst_ip = _ip_matches(rule_src, dst_ip)
        reverse_src_port = not rule_dst_ports or (src_port and str(src_port) in [str(p) for p in rule_dst_ports])
        reverse_dst_port = not rule_src_ports or (dst_port and str(dst_port) in [str(p) for p in rule_src_ports])
        reverse_match = reverse_src_ip and reverse_dst_ip and reverse_src_port and reverse_dst_port

        return forward_match or reverse_match
    else:
        # 默认单向
        return _matches_direction(src_ip, src_port, dst_ip, dst_port, rule, "->")


def _matches_ports(src_port: Optional[str], dst_port: Optional[str], rule) -> bool:
    """检查端口是否匹配规则，支持否定语法"""
    rule_src_ports = getattr(rule, "src_ports", None) or []
    rule_dst_ports = getattr(rule, "dst_ports", None) or []

    # 如果规则没有指定端口，则匹配
    if not rule_src_ports and not rule_dst_ports:
        return True

    # 检查目的端口
    if rule_dst_ports:
        if not _port_list_matches(dst_port, rule_dst_ports):
            return False

    # 检查源端口
    if rule_src_ports:
        if not _port_list_matches(src_port, rule_src_ports):
            return False

    return True


def _port_list_matches(packet_port: Optional[str], rule_ports: List[str]) -> bool:
    """检查单个端口是否匹配端口规则列表，支持否定语法"""
    if not packet_port:
        return False

    packet_port_str = str(packet_port)

    # 分离普通端口和否定端口
    normal_ports = []
    negated_ports = []

    for rule_port in rule_ports:
        rule_port_str = str(rule_port)
        if rule_port_str.startswith('!'):
            negated_ports.append(rule_port_str[1:])  # 移除!前缀
        else:
            normal_ports.append(rule_port_str)

    # 如果有普通端口，检查是否匹配任何一个普通端口
    if normal_ports:
        for normal_port in normal_ports:
            if packet_port_str == normal_port:
                return True
        # 如果有普通端口但没有匹配，则不匹配（除非有否定端口允许）
        if not negated_ports:
            return False

    # 检查否定端口：如果数据包端口在任何否定范围内，则不匹配
    for negated_port in negated_ports:
        if ':' in negated_port:
            # 处理否定端口范围：21:23
            try:
                start_str, end_str = negated_port.split(':')
                start = int(start_str)
                end = int(end_str) if end_str else 65535
                packet_port_num = int(packet_port_str)
                # 如果数据包端口在这个否定范围内，则不匹配
                if start <= packet_port_num <= end:
                    return False
            except (ValueError, TypeError):
                # 如果无法解析为数字，则按字符串匹配
                if packet_port_str == negated_port:
                    return False
        else:
            # 处理单个否定端口：21
            try:
                negated_port_num = int(negated_port)
                packet_port_num = int(packet_port_str)
                # 如果数据包端口等于这个否定端口，则不匹配
                if packet_port_num == negated_port_num:
                    return False
            except (ValueError, TypeError):
                # 如果无法解析为数字，则按字符串匹配
                if packet_port_str == negated_port:
                    return False

    # 如果只有普通端口且已经检查过（上面返回了），这里不会到达
    # 如果有普通端口匹配，上面已经返回True
    # 如果有否定端口且数据包端口不在否定范围内，则匹配
    # 如果既没有普通端口也没有否定端口，则匹配（虽然这种情况不应该发生）
    return True


def load_rules_from_db():
    """从数据库加载规则到内存并同步重建引擎（启动时使用）。

    如果没有可用的 DB 依赖或连接，将抛出异常。
    """
    try:
        from app.db import SessionLocal
        from app.models.db_models import RuleModel
        from app.models.rule import Rule as PydanticRule
    except Exception as exc:
        raise RuntimeError("Database support is not available. Ensure app.db and db models are importable.") from exc

    session = SessionLocal()
    try:
        rows = session.query(RuleModel).order_by(RuleModel.id).all()
        with _lock:
            _rules.clear()
            for r in rows:
                # pattern may be JSON-serialized list or plain string
                pat = None
                try:
                    val = json.loads(r.pattern)
                    if isinstance(val, list):
                        pat = val
                    else:
                        pat = str(val)
                except Exception:
                    pat = r.pattern

                pr = PydanticRule(
                    rule_id=r.rule_id,
                    name=r.name,
                    action=r.action,
                    priority=r.priority,
                    protocol=r.protocol,
                    src=r.src,
                    src_ports=r.src_ports,
                    direction=r.direction,
                    dst=r.dst,
                    dst_ports=r.dst_ports,
                    pattern=pat,
                    pattern_type=r.pattern_type,
                    description=r.description,
                    category=r.category,
                    tags=r.tags,
                    metadata=getattr(r, "rule_metadata", None),
                    enabled=r.enabled,
                )
                _rules.append(pr)
        # 同步构建以保证启动后立即可用
        _rebuild_engine_sync()
    finally:
        session.close()


def _ip_matches(rule_ip: str, packet_ip: str) -> bool:
    """检查数据包IP是否匹配规则IP，支持CIDR和否定语法"""
    if rule_ip == "any":
        return True

    if not packet_ip:
        return False

    # 处理否定语法：!192.168.0.0/16 表示不匹配该网络
    if rule_ip.startswith('!'):
        negated_ip = rule_ip[1:]  # 移除!前缀
        return not _ip_matches_single(negated_ip, packet_ip)
    else:
        return _ip_matches_single(rule_ip, packet_ip)


def _ip_matches_single(rule_ip: str, packet_ip: str) -> bool:
    """检查单个IP规则是否匹配，支持CIDR表示法"""
    if rule_ip == "any":
        return True
    
    try:
        # 如果是CIDR表示法，如 192.168.0.0/16
        if '/' in rule_ip:
            network = ipaddress.ip_network(rule_ip, strict=False)
            packet_addr = ipaddress.ip_address(packet_ip)
            return packet_addr in network
        else:
            # 精确匹配单个IP
            return rule_ip == packet_ip
    except (ipaddress.AddressValueError, ValueError):
        # 如果解析失败，回退到字符串匹配
        return rule_ip == packet_ip


__all__ = ["list_rules", "add_rule", "remove_rule", "match_payload", "rebuild_async", "load_rules_from_db"]
