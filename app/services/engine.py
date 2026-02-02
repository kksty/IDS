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
            # 从规则元数据中添加消息
            meta = eng._rule_meta.get(rule_id, {})
            match["message"] = meta.get("description", "")
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
