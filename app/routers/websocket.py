from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import logging
import json

router = APIRouter()

logger = logging.getLogger("ids.websocket")


# 简单的连接管理器（改进日志与错误处理）
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info("New client connected. Total: %d", len(self.active_connections))

    def disconnect(self, websocket: WebSocket):
        try:
            self.active_connections.remove(websocket)
        except ValueError:
            logger.warning("Attempted to remove websocket not in active list")
        logger.info("Client disconnected. Total: %d", len(self.active_connections))

    async def broadcast(self, message: dict):
        """广播消息到所有连接的客户端"""
        if not self.active_connections:
            return

        # 使用 json 序列化
        try:
            payload = json.dumps(message, default=str)
        except (TypeError, ValueError) as e:
            logger.error(f"Failed to serialize message: {e}")
            return

        # 并发发送到所有客户端
        import asyncio
        tasks = []
        disconnected_clients = []

        for websocket in self.active_connections:
            task = self._send_to_client(websocket, payload, disconnected_clients)
            tasks.append(task)

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        # 清理断开的连接
        for client in disconnected_clients:
            self.disconnect(client)

    async def _send_to_client(self, websocket: WebSocket, payload: str, disconnected_clients: list):
        """发送消息到单个客户端"""
        try:
            await websocket.send_text(payload)
        except Exception as e:
            logger.warning(f"Failed to send message to client: {e}")
            disconnected_clients.append(websocket)


manager = ConnectionManager()


@router.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket端点用于实时告警"""
    await manager.connect(websocket)
    try:
        while True:
            # 保持连接，监听前端发送的消息（如果需要）
            try:
                data = await websocket.receive_text()
            except WebSocketDisconnect:
                raise
            except Exception as e:
                logger.exception("Error receiving message from client: %s", e)
                # 若接收异常，主动断开并退出循环
                break
            # 可以在这里处理前端指令，例如 "ping"
    except WebSocketDisconnect:
        logger.info("Client disconnected by WebSocketDisconnect")
    except Exception:
        logger.exception("Unexpected error in websocket endpoint")
    finally:
        manager.disconnect(websocket)