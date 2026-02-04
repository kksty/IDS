# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""简单的集成测试脚本：

流程：
 1. 向后端 POST 一条规则（默认 rule_id=R_test，pattern=password=）
 2. 连接 WebSocket `/ws/alerts` 并等待告警
 3. 通过 scapy 向指定接口发送包含触发字符串的简单 HTTP 请求样例
 4. 如果收到包含匹配信息的告警则退出成功

用法：
  sudo python3 tests/integration_test.py --iface lo
（Scrapy 发送原始包通常需要 root；若在 loopback 上且有能力可不 sudo）
"""
import argparse
import asyncio
import json
import threading
import time
import sys

import requests


def send_packet(iface: str, dst_ip: str, dst_port: int, payload: bytes):
    # 延迟导入 scapy，避免导入时没有 root 权限问题
    try:
        from scapy.all import IP, TCP, Raw, send
    except Exception as e:
        print("scapy import failed:", e)
        return

    pkt = IP(dst=dst_ip) / TCP(dport=dst_port) / Raw(load=payload)
    print(f"[TEST] Sending packet to {dst_ip}:{dst_port} on iface {iface}")
    send(pkt, iface=iface, verbose=False)


async def ws_listen(uri: str, pattern: str, timeout: int = 10) -> dict | None:
    import websockets

    try:
        async with websockets.connect(uri) as ws:
            print("[TEST] WebSocket connected, waiting for alert...")
            end_time = time.time() + timeout
            while time.time() < end_time:
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=end_time - time.time())
                except asyncio.TimeoutError:
                    return None
                print("[TEST] Received WS message:", msg)
                try:
                    data = json.loads(msg)
                except Exception:
                    continue
                # 检查告警中的匹配字段或 packet_summary
                if pattern in str(data.get("match_text", "")) or pattern in str(data.get("packet_summary", "")):
                    return data
            return None
    except Exception as e:
        print("[TEST] WebSocket error:", e)
        return None


def post_rule(base_url: str, rule_id: str, pattern: str, pattern_type: str = "string") -> bool:
    url = f"{base_url}/api/rules"
    payload = {
        "rule_id": rule_id,
        "pattern": pattern,
        "pattern_type": pattern_type,
        "priority": 3,
    }
    try:
        r = requests.post(url, json=payload, timeout=5)
        print("[TEST] POST /api/rules ->", r.status_code, r.text)
        return r.status_code == 200
    except Exception as e:
        print("[TEST] Failed to POST rule:", e)
        return False


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="localhost")
    p.add_argument("--http-port", type=int, default=8000)
    p.add_argument("--ws-port", type=int, default=8000)
    p.add_argument("--iface", default="lo", help="Interface to send test packet on")
    p.add_argument("--pattern", default="password=", help="Pattern to add and expect")
    p.add_argument("--rule-id", default="R_test")
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("--skip-post", action="store_true", help="Skip posting rule to API (use existing DB rule)")
    args = p.parse_args()

    base = f"http://{args.host}:{args.http_port}"
    ws_uri = f"ws://{args.host}:{args.ws_port}/ws/alerts"

    if not args.skip_post:
        ok = post_rule(base, args.rule_id, args.pattern, pattern_type="string")
        if not ok:
            print("[TEST] Failed to create rule, abort.")
            sys.exit(2)
    else:
        print('[TEST] Skipping POST; using existing DB rule if present')

    # prepare payload (HTTP-like) that contains the pattern
    payload = f"GET /?{args.pattern}1 HTTP/1.1\r\nHost: {args.host}\r\n\r\n".encode()

    # start ws listener
    loop = asyncio.new_event_loop()

    result_container = {"match": None}

    def run_listener():
        asyncio.set_event_loop(loop)
        data = loop.run_until_complete(ws_listen(ws_uri, args.pattern, timeout=args.timeout))
        result_container["match"] = data

    t = threading.Thread(target=run_listener, daemon=True)
    t.start()

    # wait briefly for WS connect
    time.sleep(1)

    # send packet in another thread (scapy send is blocking)
    sender = threading.Thread(target=send_packet, args=(args.iface, "127.0.0.1", 80, payload), daemon=True)
    sender.start()

    # wait for listener to finish or timeout
    t.join(args.timeout + 1)

    match = result_container.get("match")
    if match:
        print("[TEST] Success: received alert:")
        print(json.dumps(match, indent=2, ensure_ascii=False))
        sys.exit(0)
    else:
        print("[TEST] No alert received within timeout")
        sys.exit(1)


if __name__ == "__main__":
    main()
