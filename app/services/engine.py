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


def match_payload(payload: bytes, protocol: str = "", dst_port: Optional[str] = None,
                  src_ip: Optional[str] = None, src_port: Optional[str] = None,
                  dst_ip: Optional[str] = None) -> List[Dict[str, Any]]:
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
    with _lock:
        eng = _engine
    if eng is None:
        return []

    # 1. 首先进行端口/协议/方向预过滤
    candidate_rule_ids = _get_candidate_rules(protocol.upper(), dst_port, src_ip, src_port, dst_ip)

    if not candidate_rule_ids:
        return []

    # 2. 获取完整的匹配结果
    all_matches = eng.match(payload)

    # 3. 过滤出候选规则中的匹配结果
    filtered_matches = []
    for match in all_matches:
        rule_id = match.get("rule_id")
        if rule_id in candidate_rule_ids:
            filtered_matches.append(match)

    return filtered_matches


def _get_candidate_rules(protocol: str, dst_port: Optional[str] = None,
                        src_ip: Optional[str] = None, src_port: Optional[str] = None,
                        dst_ip: Optional[str] = None) -> List[str]:
    """获取候选规则ID列表（基于端口优先级排序，所有规则都参与但按匹配度排序）"""
    candidates = []

    # 获取所有规则进行方向过滤
    for rule in _rules:
        if not getattr(rule, "enabled", True):
            continue

        rule_id = getattr(rule, "rule_id", None)
        if rule_id is None:
            continue

        # 检查协议匹配（可选）：如果规则指定了协议，则必须匹配；如果没指定，则允许
        rule_protocol = getattr(rule, "protocol", "").upper() if getattr(rule, "protocol") else ""
        if rule_protocol and rule_protocol != protocol:
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
        src_ip_match = rule_src == "any" or src_ip == rule_src
        dst_ip_match = rule_dst == "any" or dst_ip == rule_dst

        src_port_match = not rule_src_ports or (src_port and str(src_port) in [str(p) for p in rule_src_ports])
        dst_port_match = not rule_dst_ports or (dst_port and str(dst_port) in [str(p) for p in rule_dst_ports])

        return src_ip_match and dst_ip_match and src_port_match and dst_port_match

    elif direction == "<>":
        # 双向匹配：允许两个方向
        # 正向：packet.src/src_port -> packet.dst/dst_port == rule.src/src_ports -> rule.dst/dst_ports
        forward_src_ip = rule_src == "any" or src_ip == rule_src
        forward_dst_ip = rule_dst == "any" or dst_ip == rule_dst
        forward_src_port = not rule_src_ports or (src_port and str(src_port) in [str(p) for p in rule_src_ports])
        forward_dst_port = not rule_dst_ports or (dst_port and str(dst_port) in [str(p) for p in rule_dst_ports])
        forward_match = forward_src_ip and forward_dst_ip and forward_src_port and forward_dst_port

        # 反向：packet.src/src_port -> packet.dst/dst_port == rule.dst/dst_ports -> rule.src/src_ports
        reverse_src_ip = rule_dst == "any" or src_ip == rule_dst
        reverse_dst_ip = rule_src == "any" or dst_ip == rule_src
        reverse_src_port = not rule_dst_ports or (src_port and str(src_port) in [str(p) for p in rule_dst_ports])
        reverse_dst_port = not rule_src_ports or (dst_port and str(dst_port) in [str(p) for p in rule_src_ports])
        reverse_match = reverse_src_ip and reverse_dst_ip and reverse_src_port and reverse_dst_port

        return forward_match or reverse_match
    else:
        # 默认单向
        return _matches_direction(src_ip, src_port, dst_ip, dst_port, rule, "->")


def _matches_ports(src_port: Optional[str], dst_port: Optional[str], rule) -> bool:
    """检查端口是否匹配规则"""
    rule_src_ports = getattr(rule, "src_ports", None) or []
    rule_dst_ports = getattr(rule, "dst_ports", None) or []

    # 如果规则没有指定端口，则匹配
    if not rule_src_ports and not rule_dst_ports:
        return True

    # 检查目的端口
    if rule_dst_ports:
        dst_port_match = dst_port and str(dst_port) in [str(p) for p in rule_dst_ports]
        if not dst_port_match:
            return False

    # 检查源端口
    if rule_src_ports:
        src_port_match = src_port and str(src_port) in [str(p) for p in rule_src_ports]
        if not src_port_match:
            return False

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
                    pat = val
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


__all__ = ["list_rules", "add_rule", "remove_rule", "match_payload", "rebuild_async", "load_rules_from_db"]
