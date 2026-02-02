from fastapi import APIRouter, HTTPException, UploadFile, File
from typing import List, Any
from sqlalchemy.exc import SQLAlchemyError
import json
import logging

from app.models import Rule
from app.services import engine as engine_mgr

from app.db import SessionLocal
from app.models.db_models import RuleModel

router = APIRouter(prefix="/api/rules", tags=["Rules"])

logger = logging.getLogger(__name__)


def _parse_pattern(pattern_str: str, pattern_type: str = "string") -> Any:
    """解析数据库中的pattern字段（统一为JSON列表格式）"""
    if not pattern_str or pattern_str.strip() == "":
        return []

    # 对于pcre类型的pattern，直接返回字符串列表（不解析JSON）
    if pattern_type == "pcre":
        return [pattern_str]

    # 对于string类型的pattern，如果是JSON列表则解析，否则直接作为字符串返回
    try:
        val = json.loads(pattern_str)
        if isinstance(val, list):
            return val
        else:
            # 如果不是列表，包装成列表
            logger.warning(f"Pattern is not a list, wrapping: {pattern_str[:100]}...")
            return [str(val)]
    except json.JSONDecodeError:
        # 如果不是JSON格式，直接作为字符串返回（这是正常情况）
        return [pattern_str]
    except Exception as e:
        logger.error(f"Unexpected error parsing pattern: {e}")
        return [pattern_str]


@router.get("/ids")
async def get_rule_ids(search: str = "", category: str = "", tags: str = ""):
    """获取符合条件的规则ID列表，用于批量操作"""
    session = SessionLocal()
    try:
        # 构建查询
        query = session.query(RuleModel)
        
        # 搜索条件
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                (RuleModel.rule_id.ilike(search_term)) |
                (RuleModel.name.ilike(search_term)) |
                (RuleModel.description.ilike(search_term))
            )
        
        # 类别筛选
        if category:
            query = query.filter(RuleModel.category.ilike(f"%{category}%"))
        
        # 标签筛选
        if tags:
            query = query.filter(RuleModel.tags.ilike(f"%{tags}%"))
        
        # 获取所有符合条件的规则ID
        rule_ids = query.with_entities(RuleModel.rule_id).all()
        return [rid[0] for rid in rule_ids]
    except SQLAlchemyError as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()


@router.get("/")
async def get_rules(skip: int = 0, limit: int = 20, search: str = "", category: str = "", tags: str = ""):
    """获取规则列表，支持分页、搜索和筛选"""
    session = SessionLocal()
    try:
        # 构建查询
        query = session.query(RuleModel)
        
        # 搜索条件
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                (RuleModel.rule_id.ilike(search_term)) |
                (RuleModel.name.ilike(search_term)) |
                (RuleModel.description.ilike(search_term))
            )
        
        # 类别筛选
        if category:
            query = query.filter(RuleModel.category.ilike(f"%{category}%"))
        
        # 标签筛选
        if tags:
            query = query.filter(RuleModel.tags.ilike(f"%{tags}%"))
        
        # 获取总数
        total = query.count()
        
        # 分页查询
        rows = query.order_by(RuleModel.id).offset(skip).limit(limit).all()
        out: List[Rule] = []
        for r in rows:
            pat = _parse_pattern(r.pattern, r.pattern_type)
            out.append(
                Rule(
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
                    metadata=r.rule_metadata,
                    enabled=r.enabled,
                )
            )
        # 返回分页数据
        return {
            "rules": out,
            "total": total,
            "skip": skip,
            "limit": limit,
            "search": search,
            "category": category,
            "tags": tags
        }
    except SQLAlchemyError as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()


@router.post("/", response_model=Rule)
async def create_rule(rule: Rule):
    session = SessionLocal()
    try:
        exists = session.query(RuleModel).filter(RuleModel.rule_id == rule.rule_id).first()
        if exists:
            raise HTTPException(status_code=400, detail="Rule ID already exists")

        pattern_val = rule.pattern
        if isinstance(pattern_val, list):
            pattern_store = json.dumps(pattern_val, ensure_ascii=False)
        else:
            pattern_store = str(pattern_val)

        row = RuleModel(
            rule_id=rule.rule_id,
            name=rule.name,
            action=rule.action,
            priority=rule.priority,
            protocol=rule.protocol,
            src=rule.src,
            src_ports=rule.src_ports,
            direction=rule.direction,
            dst=rule.dst,
            dst_ports=rule.dst_ports,
            pattern=pattern_store,
            pattern_type=rule.pattern_type,
            description=rule.description,
            category=rule.category,
            tags=rule.tags,
            rule_metadata=rule.metadata,
            enabled=rule.enabled,
        )
        session.add(row)
        session.commit()
        # 更新引擎（使用原始 pydantic rule）
        engine_mgr.add_rule(rule)
        return rule
    except SQLAlchemyError as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

@router.delete("/batch")
async def batch_delete_rules(rule_ids: List[str]):
    """批量删除规则"""
    if not rule_ids:
        raise HTTPException(status_code=400, detail="规则ID列表不能为空")
    
    session = SessionLocal()
    try:
        # 查询要删除的规则（只删除存在的规则）
        rules_to_delete = session.query(RuleModel).filter(RuleModel.rule_id.in_(rule_ids)).all()
        
        if not rules_to_delete:
            return {
                "message": "没有找到要删除的规则",
                "deleted_count": 0
            }
        
        deleted_count = 0
        deleted_ids = []
        for rule in rules_to_delete:
            deleted_ids.append(rule.rule_id)
            session.delete(rule)
            deleted_count += 1
        
        session.commit()
        
        # 重新加载引擎
        from app.services import engine as engine_mgr
        engine_mgr.remove_rules(deleted_ids, rebuild=True)
        
        return {
            "message": f"成功删除 {deleted_count} 条规则",
            "deleted_count": deleted_count
        }
    
    except SQLAlchemyError as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=f"批量删除失败: {str(e)}")
    finally:
        session.close()

@router.delete("/{rule_id}")
async def delete_rule(rule_id: str):
    session = SessionLocal()
    try:
        row = session.query(RuleModel).filter(RuleModel.rule_id == rule_id).first()
        if not row:
            raise HTTPException(status_code=404, detail="Rule not found")
        session.delete(row)
        session.commit()
        engine_mgr.remove_rule(rule_id)
        return {"status": "deleted"}
    except SQLAlchemyError as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()


@router.put("/{rule_id}", response_model=Rule)
async def update_rule(rule_id: str, rule: Rule):
    """更新已有规则（按 rule_id），替换存储并触发引擎重建。"""
    session = SessionLocal()
    try:
        row = session.query(RuleModel).filter(RuleModel.rule_id == rule_id).first()
        if not row:
            raise HTTPException(status_code=404, detail="Rule not found")

        # 更新字段
        row.name = rule.name
        row.action = rule.action
        row.priority = rule.priority
        row.protocol = rule.protocol
        row.src = rule.src
        row.src_ports = rule.src_ports
        row.direction = rule.direction
        row.dst = rule.dst
        row.dst_ports = rule.dst_ports
        # 确保 pattern 总是以列表格式保存
        if isinstance(rule.pattern, list):
            pattern_to_save = rule.pattern
        else:
            # 将单个字符串包装成列表
            pattern_to_save = [str(rule.pattern)] if rule.pattern else []
        
        row.pattern = json.dumps(pattern_to_save, ensure_ascii=False)
        row.pattern_type = rule.pattern_type
        row.description = rule.description
        row.category = rule.category
        row.tags = rule.tags
        row.rule_metadata = rule.metadata
        row.enabled = rule.enabled

        session.add(row)
        session.commit()

        # 更新内存引擎（使用 pydantic 对象）；触发异步重建以避免阻塞请求
        engine_mgr.remove_rule(rule_id, rebuild=False)
        engine_mgr.add_rule(rule, rebuild=True)

        return rule
    except SQLAlchemyError as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()


@router.post("/bulk-import")
async def bulk_import_rules(file: UploadFile = File(...)):
    """
    批量导入Snort3规则文件
    支持上传.rules文件，自动解析并转换为系统规则格式
    """
    if not file.filename.endswith('.rules'):
        raise HTTPException(status_code=400, detail="只支持.rules文件格式")

    try:
        # 读取文件内容
        content = await file.read()
        rules_text = content.decode('utf-8')

        # 导入Snort3规则
        from app.services.snort_importer import bulk_import_snort_rules
        import_result = bulk_import_snort_rules(rules_text)

        # 构建详细的响应消息
        success_count = import_result["imported"]
        failed_count = import_result["failed_count"]
        total_count = import_result["total"]

        message_parts = []
        if success_count > 0:
            message_parts.append(f"成功导入 {success_count} 条规则")
        if failed_count > 0:
            message_parts.append(f"失败 {failed_count} 条规则")
            # 添加失败原因示例
            if import_result["failed"]:
                first_error = import_result["failed"][0]
                message_parts.append(f"示例错误: {first_error.get('error', '未知错误')}")

        response = {
            "message": "，".join(message_parts),
            "total": total_count,
            "imported": success_count,
            "failed": failed_count,
            "imported_rules": import_result["success"],
            "failed_rules": import_result["failed"]
        }

        # 如果全部失败，返回错误状态
        if success_count == 0 and failed_count > 0:
            raise HTTPException(status_code=400, detail=response["message"])

        return response

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"导入失败: {str(e)}")


@router.post("/bulk-import-json")
async def bulk_import_rules_json(rules: List[dict]):
    """
    批量导入JSON格式的规则列表
    直接接受规则对象的JSON数组
    """
    try:
        imported_rules = []
        session = SessionLocal()

        for rule_data in rules:
            # 验证规则数据
            if not all(k in rule_data for k in ['name', 'patterns', 'severity']):
                continue

            # 创建规则对象
            rule = Rule(
                name=rule_data['name'],
                patterns=rule_data['patterns'],
                severity=rule_data.get('severity', 'medium'),
                description=rule_data.get('description', ''),
                category=rule_data.get('category', 'custom'),
                tags=rule_data.get('tags', []),
                metadata=rule_data.get('metadata', {}),
                enabled=rule_data.get('enabled', True)
            )

            # 保存到数据库
            row = RuleModel(
                id=rule.id,
                name=rule.name,
                patterns=json.dumps(rule.patterns),
                severity=rule.severity,
                description=rule.description,
                category=rule.category,
                tags=json.dumps(rule.tags),
                rule_metadata=json.dumps(rule.metadata),
                enabled=rule.enabled,
            )
            session.add(row)
            imported_rules.append(rule)

        session.commit()

        # 更新引擎
        for rule in imported_rules:
            engine_mgr.add_rule(rule)

        return {
            "message": f"成功导入 {len(imported_rules)} 条规则",
            "imported_rules": [rule.dict() for rule in imported_rules]
        }

    except SQLAlchemyError as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"导入失败: {str(e)}")
    finally:
        session.close()



@router.get("/snort-variables")
async def get_snort_variables():
    """获取Snort变量配置"""
    from app.services.snort_importer import get_snort_variables
    return get_snort_variables()


@router.put("/snort-variables/{var_name}")
async def update_snort_variable(var_name: str, value: str):
    """更新Snort变量的值"""
    from app.services.snort_importer import update_snort_variable
    # var_name 可能是 "$HOME_NET" 或 "HOME_NET" 格式，确保以 $ 开头
    if not var_name.startswith('$'):
        var_name = f"${var_name}"
    update_snort_variable(var_name, value)
    return {"message": f"变量 {var_name} 已更新为 {value}"}


@router.get("/snort-variables-config")
async def get_snort_variables_config():
    """获取Snort变量配置说明"""
    return {
        "description": "Snort变量配置系统",
        "variables": {
            "HOME_NET": {
                "description": "家庭网络/内部网络的IP范围",
                "default": "192.168.0.0/16",
                "example": "192.168.1.0/24"
            },
            "EXTERNAL_NET": {
                "description": "外部网络，通常是!$HOME_NET",
                "default": "!$HOME_NET",
                "example": "any"
            },
            "HTTP_SERVERS": {
                "description": "HTTP服务器IP范围",
                "default": "$HOME_NET",
                "example": "192.168.1.100/32"
            },
            "SQL_SERVERS": {
                "description": "SQL服务器IP范围",
                "default": "$HOME_NET",
                "example": "192.168.1.200/32"
            }
        },
        "usage": "通过PUT /api/rules/snort-variables/{VAR_NAME}更新变量值"
    }
