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
        # 使用 json 序列化，并记录更详细的异常信息
        payload = json.dumps(message, default=str)
        clients = list(self.active_connections)  # 拷贝以便安全移除
        logger.debug("Broadcasting to %d clients: %s", len(clients), message)
        for connection in clients:
            try:
                await connection.send_text(payload)
            except Exception as e:
                # 记录堆栈以便排查连接或序列化问题
                logger.exception("Failed to send message to client: %s", e)
                # 尝试断开并从列表中移除不可用连接
                try:
                    self.active_connections.remove(connection)
                except ValueError:
                    pass


manager = ConnectionManager()


@router.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
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