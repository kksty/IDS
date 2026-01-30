from fastapi import APIRouter, HTTPException, UploadFile, File
from typing import List
from sqlalchemy.exc import SQLAlchemyError
import json

from app.models import Rule
from app.services import engine as engine_mgr

from app.db import SessionLocal
from app.models.db_models import RuleModel

router = APIRouter(prefix="/api/rules", tags=["Rules"])


@router.get("/", response_model=List[Rule])
async def get_rules():
    session = SessionLocal()
    try:
        rows = session.query(RuleModel).order_by(RuleModel.id).all()
        out: List[Rule] = []
        for r in rows:
            pat = None
            try:
                pat = json.loads(r.pattern)
            except Exception:
                pat = r.pattern
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
        return out
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
        if isinstance(rule.pattern, list):
            row.pattern = json.dumps(rule.pattern, ensure_ascii=False)
        else:
            row.pattern = str(rule.pattern)
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
        imported_rules = bulk_import_snort_rules(rules_text)

        return {
            "message": f"成功导入 {len(imported_rules)} 条规则",
            "imported_rules": imported_rules
        }

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
