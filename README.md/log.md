
---

## 1. 如何使用？（三步走）

要在其他文件或函数中使用日志，你只需要遵循标准的“获取-记录”流程：

### 第一步：获取“记录器”（Logger）

在每个 `.py` 文件的顶部，定义一个属于该模块的记录器。

Python

```
import logging

# 获取当前模块的名字作为记录器名称
logger = logging.getLogger(__name__) 
```

> **为什么要写 `__name__`？**
> 
> 这样日志里 `[%(name)s]` 的位置就会显示是哪个文件在说话。比如在 `app/services/sniffer.py` 里，它会显示为 `[app.services.sniffer]`。

### 第二步：在代码中记录

根据事情的严重程度，调用不同的方法：

Python

```
def process_packet(packet_data):
    # 1. 记录琐碎细节（只有在 DEBUG 模式下才会显示）
    logger.debug(f"正在解析原始数据: {packet_data[:10]}...")

    # 2. 记录重要进展
    logger.info("成功捕获一个可疑数据包")

    # 3. 记录警告（可能存在风险）
    if len(packet_data) > 1500:
        logger.warning("捕获到超大数据包，可能存在异常流量")

    # 4. 记录错误
    try:
        # 模拟解析错误
        raise ValueError("解析失败")
    except Exception as e:
        logger.error(f"处理数据包时出错: {e}")
```

---

## 2. 它是如何生效的？

当你调用 `logger.info()` 时，会发生以下过程：

1. **级别检查**：你代码里设置了 `level=INFO`。如果你调用 `logger.debug()`，日志系统会直接无视它，不会打印任何东西。
    
2. **格式化**：如果级别符合，它会按照你定义的 `format`（带上时间、名称等）把文字拼好。
    
3. **输出**：最终显示在你的控制台屏幕上。
    

---

## 3. 实际运行效果

假设你在启动程序时没有设置环境变量（默认为 `INFO`），你的控制台看起来会像这样：

Plaintext

```
2026-01-28 18:30:01 INFO [app.main] IDS Backend is running
2026-01-28 18:30:02 INFO [app.services.sniffer] [*] Sniffer thread tied to loop 140234...
2026-01-28 18:30:05 ERROR [app.services.sniffer] [!] 无法访问网卡 wlo1，请检查权限
```

---

## 4. 进阶技巧：如何切换级别？

既然代码里写了 `os.getenv("IDS_LOG_LEVEL", "INFO")`，你不需要改代码就能改变打印内容的详略：

- **如果你想看到所有调试信息（非常啰嗦）**：
    
    在终端启动时输入：`export IDS_LOG_LEVEL=DEBUG && python main.py`
    
- **如果你只想看到错误（非常清静）**：
    
    在终端启动时输入：`export IDS_LOG_LEVEL=ERROR && python main.py`
    

---

## 总结

1. **初始化**：在 `main.py` 里写一次 `basicConfig`。
    
2. **使用**：在每个需要的 `.py` 里 `logger = logging.getLogger(__name__)`，然后用 `logger.info()` 等方法说话。
    

**你想试试在你的 `sniffer.py` 里的 `start_sniffing` 函数中加入几行 `logger.info` 吗？我可以教你如何记录抓包的实时状态。**