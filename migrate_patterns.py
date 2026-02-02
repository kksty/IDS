#!/usr/bin/env python3
"""
迁移脚本：将数据库中所有规则的 pattern 字段统一为 JSON 列表格式
"""

import sys
import os
import json
import logging

# 添加项目路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.db import SessionLocal
from app.models.db_models import RuleModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def migrate_patterns():
    """迁移所有规则的 pattern 字段为 JSON 列表格式"""
    session = SessionLocal()
    try:
        # 查询所有规则
        rules = session.query(RuleModel).all()
        logger.info(f"找到 {len(rules)} 条规则需要检查")

        migrated_count = 0

        for rule in rules:
            original_pattern = rule.pattern
            new_pattern = None

            # 检查是否已经是 JSON 列表
            if original_pattern.strip().startswith('['):
                try:
                    parsed = json.loads(original_pattern)
                    if isinstance(parsed, list):
                        # 已经是列表，跳过
                        continue
                except json.JSONDecodeError:
                    pass

            # 需要迁移：将字符串转换为 ["string"]
            if isinstance(original_pattern, str) and original_pattern.strip():
                new_pattern = json.dumps([original_pattern], ensure_ascii=False)
            else:
                # 空字符串或其他情况
                new_pattern = json.dumps([""], ensure_ascii=False)

            # 更新数据库
            rule.pattern = new_pattern
            migrated_count += 1
            logger.info(f"迁移规则 {rule.rule_id}: '{original_pattern[:50]}...' -> {new_pattern}")

        # 提交更改
        session.commit()
        logger.info(f"✅ 成功迁移 {migrated_count} 条规则")

    except Exception as e:
        session.rollback()
        logger.error(f"❌ 迁移失败: {e}")
        raise
    finally:
        session.close()


if __name__ == "__main__":
    logger.info("开始迁移数据库中的规则模式格式...")
    migrate_patterns()
    logger.info("迁移完成！")