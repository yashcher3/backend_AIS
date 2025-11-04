import datetime
from fastapi import Request
import os
from fastapi.responses import FileResponse, RedirectResponse
import re
from datetime import datetime, timedelta

from s3_storage import get_s3_storage

from fastapi import FastAPI, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
import json
from typing import List, Optional

from fastapi.responses import JSONResponse
from datetime import timedelta

from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt

from database import get_db, engine

from models import (
    Base, DBCaseTemplate, DBStageTemplate, DBAttributeTemplate, DBExecutor,
    DBCase, DBStage, DBAttribute,
    CaseTemplateCreate, CaseTemplateResponse, StageTemplateResponse,
    ExportData, StageTemplateBase, ExecutorCreate, ExecutorResponse,
    ExecutorBase, AttributeTemplateCreate, AttributeTemplateResponse,
    CaseCreate, CaseResponse, CaseUpdate, CaseFilter,
    StageCreate, StageResponse, StageUpdate, StageFilter,
    AttributeCreate, AttributeResponse, AttributeUpdate,
    FileUploadResponse, PaginatedCaseResponse, StageApprovalRequest, StageWithCaseInfo
)
from stage_logic import validate_stage_format

from fastapi import UploadFile, File, Form

from auth_models import UserCreate, Token, UserResponse
from auth_config import authenticate_user, create_access_token, ACCESS_TOKEN_EXPIRE_HOURS, SECRET_KEY, ALGORITHM, \
    require_admin_or_manager, require_admin_only
from auth_config import get_user
from auth_deps import get_current_active_user, require_role

from fastapi.middleware.cors import CORSMiddleware
from stage_numbering import get_next_stage_number, get_stage_hierarchy

# Создаем таблицы
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Case Management API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://localhost:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
security = HTTPBearer()


@app.middleware("http")
async def catch_exceptions_middleware(request: Request, call_next):
    try:
        response = await call_next(request)
        response.headers["Access-Control-Allow-Origin"] = "http://localhost:5173"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
        return response
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"detail": str(e)},
            headers={
                "Access-Control-Allow-Origin": "http://localhost:5173",
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
            }
        )


async def simple_auth(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        role = payload.get("role")
        return {
            "username": username,
            "role": role,
            "is_active": True
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Token error: {str(e)}")


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: UserCreate):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверное имя пользователя или пароль",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    access_token = create_access_token(
        data={"sub": user["username"], "role": user["role"]},
        expires_delta=access_token_expires
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "username": user["username"],
        "role": user["role"]
    }


@app.get("/users/me/", response_model=UserResponse)
async def read_users_me(current_user: dict = Depends(simple_auth)):
    return {
        "id": 1,
        "username": current_user["username"],
        "role": current_user["role"],
        "is_active": current_user.get("is_active", True)
    }


@app.post("/case_templates/export/", response_model=CaseTemplateResponse)
def export_case_template(
        export_data: ExportData,
        db: Session = Depends(get_db),
        current_user: dict = Depends(simple_auth)
):
    try:
        if not export_data.name or not export_data.description:
            raise HTTPException(status_code=400, detail="Название и описание дела обязательны")

        if not export_data.stages:
            raise HTTPException(status_code=400, detail="Должен быть хотя бы один этап")

        for stage in export_data.stages:
            if not stage.name_stage or not stage.desc or not stage.duration:
                raise HTTPException(
                    status_code=400,
                    detail=f"Этап {stage.id} имеет незаполненные обязательные поля"
                )

            total_fields = stage.file_fields + stage.text_fields
            total_templates = len(stage.attribute_templates)

            if total_templates != total_fields:
                raise HTTPException(
                    status_code=400,
                    detail=f"Этап {stage.id}: количество названий полей ({total_templates}) не соответствует количеству полей ({total_fields})"
                )

        db_case_template = DBCaseTemplate(
            name=export_data.name,
            description=export_data.description,
            stages_list=json.dumps([stage.id for stage in export_data.stages])
        )
        db.add(db_case_template)
        db.commit()
        db.refresh(db_case_template)

        for stage in export_data.stages:
            stage_id = f"{db_case_template.id}.{stage.id}"

            db_stage_template = DBStageTemplate(
                id=stage_id,
                case_template_id=db_case_template.id,
                name_stage=stage.name_stage,
                file_fields=stage.file_fields,
                text_fields=stage.text_fields,
                desc=stage.desc,
                duration=stage.duration,
                condition=stage.condition
            )
            db.add(db_stage_template)

        for stage in export_data.stages:
            stage_id = f"{db_case_template.id}.{stage.id}"
            for template in stage.attribute_templates:
                db_template = DBAttributeTemplate(
                    stage_template_id=stage_id,
                    field_type=template.field_type,
                    field_index=template.field_index,
                    label=template.label
                )
                db.add(db_template)

        db.commit()
        return db_case_template

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка при экспорте дела: {str(e)}")


@app.post("/stage_templates/{stage_id}/attribute_templates/", response_model=List[AttributeTemplateResponse])
def save_attribute_templates(
        stage_id: str,
        templates: List[AttributeTemplateCreate],
        db: Session = Depends(get_db),
        current_user: dict = Depends(simple_auth)
):
    try:
        db.query(DBAttributeTemplate).filter(DBAttributeTemplate.stage_template_id == stage_id).delete()

        saved_templates = []
        for template in templates:
            db_template = DBAttributeTemplate(
                stage_template_id=stage_id,
                field_type=template.field_type,
                field_index=template.field_index,
                label=template.label
            )
            db.add(db_template)
            saved_templates.append(db_template)

        db.commit()

        for template in saved_templates:
            db.refresh(template)

        return saved_templates

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка при сохранении шаблонов: {str(e)}")


@app.get("/stage_templates/{stage_id}/attribute_templates/", response_model=List[AttributeTemplateResponse])
def get_attribute_templates(
        stage_id: str,
        db: Session = Depends(get_db),
        current_user: dict = Depends(simple_auth)
):
    templates = db.query(DBAttributeTemplate).filter(DBAttributeTemplate.stage_template_id == stage_id).all()
    return templates


@app.post("/case_templates/", response_model=CaseTemplateResponse)
def create_case_template(
        case_data: CaseTemplateCreate,
        db: Session = Depends(get_db),
        current_user: dict = Depends(require_admin_or_manager)
):
    try:
        db_case_template = DBCaseTemplate(
            name=case_data.name,
            description=case_data.description,
            stages_list=json.dumps([stage.id for stage in case_data.stages])
        )
        db.add(db_case_template)
        db.commit()
        db.refresh(db_case_template)

        for stage in case_data.stages:
            stage_id = f"{db_case_template.id}.{stage.id}"

            db_stage_template = DBStageTemplate(
                id=stage_id,
                case_template_id=db_case_template.id,
                name_stage=stage.name_stage,
                file_fields=stage.file_fields,
                text_fields=stage.text_fields,
                desc=stage.desc,
                duration=stage.duration,
                condition=stage.condition
            )
            db.add(db_stage_template)

        db.commit()
        return db_case_template

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка при создании шаблона дела: {str(e)}")


@app.get("/case_templates/", response_model=List[CaseTemplateResponse])
def get_case_templates(
        skip: int = 0,
        limit: int = 100,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    cases = db.query(DBCaseTemplate).offset(skip).limit(limit).all()
    return cases


@app.get("/case_templates/{case_id}", response_model=CaseTemplateResponse)
def get_case_template(
        case_id: int,
        db: Session = Depends(get_db),
        current_user: dict = Depends(simple_auth)
):
    case = db.query(DBCaseTemplate).filter(DBCaseTemplate.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Шаблон дела не найден")
    return case


@app.get("/case_templates/{case_id}/stage_templates/", response_model=List[StageTemplateResponse])
def get_case_stage_templates(
        case_id: int,
        db: Session = Depends(get_db),
        current_user: dict = Depends(simple_auth)
):
    stages = db.query(DBStageTemplate).filter(DBStageTemplate.case_template_id == case_id).all()
    return stages


@app.post("/token/refresh")
async def refresh_token(current_user: dict = Depends(simple_auth)):
    access_token_expires = timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    access_token = create_access_token(
        data={"sub": current_user["username"], "role": current_user["role"]},
        expires_delta=access_token_expires
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "username": current_user["username"],
        "role": current_user["role"]
    }


@app.delete("/case_templates/{case_id}")
def delete_case_template(
        case_id: int,
        db: Session = Depends(get_db),
        current_user: dict = Depends(require_admin_or_manager)
):
    case = db.query(DBCaseTemplate).filter(DBCaseTemplate.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Шаблон дела не найден")

    try:
        db.query(DBStageTemplate).filter(DBStageTemplate.case_template_id == case_id).delete()
        db.delete(case)
        db.commit()
        return {"message": "Шаблон дела и связанные этапы удалены"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка при удалении: {str(e)}")


@app.post("/executors/", response_model=ExecutorResponse)
def create_executor(
        executor_data: ExecutorCreate,
        db: Session = Depends(get_db),
        current_user: dict = Depends(require_admin_only)
):
    try:
        existing_user = get_user(executor_data.login)
        if existing_user:
            raise HTTPException(
                status_code=400,
                detail="Пользователь с таким логином уже существует"
            )

        existing_executor = db.query(DBExecutor).filter(DBExecutor.login == executor_data.login).first()
        if existing_executor:
            raise HTTPException(
                status_code=400,
                detail="Исполнитель с таким логином уже существует"
            )

        from auth_config import get_password_hash
        hashed_password = get_password_hash(executor_data.password)

        from auth_config import USERS_DATA
        USERS_DATA[executor_data.login] = {
            "username": executor_data.login,
            "hashed_password": hashed_password,
            "role": "user",
            "is_active": True
        }

        db_executor = DBExecutor(
            login=executor_data.login,
            full_name=executor_data.full_name,
            expert_area=executor_data.expert_area,
            created_by=current_user["username"]
        )
        db.add(db_executor)
        db.commit()
        db.refresh(db_executor)

        return db_executor

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка при создании исполнителя: {str(e)}")


@app.get("/executors/", response_model=List[ExecutorResponse])
def get_executors(
        skip: int = 0,
        limit: int = 100,
        db: Session = Depends(get_db),
        current_user: dict = Depends(require_admin_or_manager)
):
    executors = db.query(DBExecutor).offset(skip).limit(limit).all()
    return executors


@app.get("/executors/list", response_model=List[ExecutorResponse])
def get_executors_list(
        skip: int = 0,
        limit: int = 100,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    try:
        executors = db.query(DBExecutor).offset(skip).limit(limit).all()
        return executors
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка при получении списка исполнителей: {str(e)}")


@app.get("/executors/{executor_id}", response_model=ExecutorResponse)
def get_executor(
        executor_id: int,
        db: Session = Depends(get_db),
        current_user: dict = Depends(require_admin_or_manager)
):
    executor = db.query(DBExecutor).filter(DBExecutor.id == executor_id).first()
    if not executor:
        raise HTTPException(status_code=404, detail="Исполнитель не найден")
    return executor


@app.put("/executors/{executor_id}", response_model=ExecutorResponse)
def update_executor(
        executor_id: int,
        executor_data: ExecutorBase,
        db: Session = Depends(get_db),
        current_user: dict = Depends(require_admin_or_manager)
):
    executor = db.query(DBExecutor).filter(DBExecutor.id == executor_id).first()
    if not executor:
        raise HTTPException(status_code=404, detail="Исполнитель не найден")

    try:
        if executor_data.login != executor.login:
            existing_executor = db.query(DBExecutor).filter(DBExecutor.login == executor_data.login).first()
            if existing_executor:
                raise HTTPException(
                    status_code=400,
                    detail="Исполнитель с таким логином уже существует"
                )

        executor.login = executor_data.login
        executor.full_name = executor_data.full_name
        executor.expert_area = executor_data.expert_area

        db.commit()
        db.refresh(executor)

        return executor

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка при обновлении: {str(e)}")


@app.delete("/executors/{executor_id}")
def delete_executor(
        executor_id: int,
        db: Session = Depends(get_db),
        current_user: dict = Depends(require_admin_only)
):
    executor = db.query(DBExecutor).filter(DBExecutor.id == executor_id).first()
    if not executor:
        raise HTTPException(status_code=404, detail="Исполнитель не найден")

    try:
        from auth_config import USERS_DATA
        if executor.login in USERS_DATA:
            del USERS_DATA[executor.login]

        db.delete(executor)
        db.commit()

        return {"message": f"Исполнитель {executor.login} удален"}

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка при удалении: {str(e)}")


@app.get("/")
def read_root():
    return {"message": "Case Management API is running"}


@app.options("/case_templates/export/")
async def options_export():
    return JSONResponse(
        content={"message": "OK"},
        headers={
            "Access-Control-Allow-Origin": "http://localhost:5173",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
        }
    )


@app.options("/token")
async def options_token():
    return JSONResponse(
        content={"message": "OK"},
        headers={
            "Access-Control-Allow-Origin": "http://localhost:5173",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
        }
    )


@app.options("/executors/")
@app.options("/executors/{executor_id}")
async def options_executors():
    return JSONResponse(
        content={"message": "OK"},
        headers={
            "Access-Control-Allow-Origin": "http://localhost:5173",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
            "Access-Control-Allow-Credentials": "true",
        }
    )


@app.options("/stages/{stage_id}/attributes/batch/")
@app.options("/stages/{stage_id}/complete/")
async def options_stages_batch():
    return JSONResponse(
        content={"message": "OK"},
        headers={
            "Access-Control-Allow-Origin": "http://localhost:5173",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
        }
    )


@app.post("/cases/", response_model=CaseResponse)
def create_case(
        case_data: CaseCreate,
        db: Session = Depends(get_db),
        current_user: dict = Depends(require_admin_or_manager)
):
    try:
        template = db.query(DBCaseTemplate).filter(DBCaseTemplate.id == case_data.case_template_id).first()
        if not template:
            raise HTTPException(status_code=404, detail="Шаблон дела не найден")

        for stage_data in case_data.stages:
            executor = db.query(DBExecutor).filter(DBExecutor.login == stage_data.executor).first()
            if not executor:
                raise HTTPException(
                    status_code=404,
                    detail=f"Исполнитель {stage_data.executor} не найден"
                )

        db_case = DBCase(
            name=case_data.name,
            case_template_id=case_data.case_template_id,
            current_stage=None
        )
        db.add(db_case)
        db.commit()
        db.refresh(db_case)

        template_stages = db.query(DBStageTemplate).filter(
            DBStageTemplate.case_template_id == case_data.case_template_id
        ).all()

        stages_by_template_id = {s.stage_template_id: s for s in case_data.stages}

        for template_stage in template_stages:
            stage_data = stages_by_template_id.get(template_stage.id)
            if not stage_data:
                continue

            db_stage = DBStage(
                case_id=db_case.id,
                stage_template_id=template_stage.id,
                executor=stage_data.executor,
                deadline=stage_data.deadline,
                closing_rule=stage_data.closing_rule,
                next_stage_rule=stage_data.next_stage_rule,
                status="pending"
            )
            db.add(db_stage)
            db.commit()
            db.refresh(db_stage)

            attribute_templates = db.query(DBAttributeTemplate).filter(
                DBAttributeTemplate.stage_template_id == template_stage.id
            ).all()

            for attr_template in attribute_templates:
                db_attr = DBAttribute(
                    stage_id=db_stage.id,
                    attribute_template_id=attr_template.id,
                    user_text=None,
                    user_file_path=None
                )
                db.add(db_attr)

        if template_stages:
            first_stage = template_stages[0]
            db_case.current_stage = first_stage.id

            first_db_stage = db.query(DBStage).filter(
                DBStage.case_id == db_case.id,
                DBStage.stage_template_id == first_stage.id
            ).first()

            if first_db_stage:
                first_db_stage.status = 'in_progress'

            db.commit()

        db.refresh(db_case)
        return db_case

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка при создании дела: {str(e)}")


@app.get("/cases/", response_model=PaginatedCaseResponse)
def get_cases(
        page: int = Query(1, ge=1),
        page_size: int = Query(10, ge=1, le=100),
        name: Optional[str] = None,
        case_template_id: Optional[int] = None,
        status: Optional[str] = None,
        executor: Optional[str] = None,
        sort_by: Optional[str] = Query("id"),
        sort_order: Optional[str] = Query("desc"),
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    from sqlalchemy.orm import joinedload
    from sqlalchemy import and_

    query = db.query(DBCase).options(joinedload(DBCase.stages))

    if name:
        query = query.filter(DBCase.name.ilike(f"%{name}%"))
    if case_template_id:
        query = query.filter(DBCase.case_template_id == case_template_id)
    if status:
        query = query.filter(DBCase.status == status)

    if executor and executor != 'all':
        subquery = db.query(DBStage.case_id).filter(
            and_(
                DBStage.stage_template_id == DBCase.current_stage,
                DBStage.executor == executor,
                DBStage.case_id == DBCase.id
            )
        ).exists()
        query = query.filter(subquery)

    sort_column = None
    if sort_by == "id":
        sort_column = DBCase.id
    elif sort_by == "name":
        sort_column = DBCase.name
    elif sort_by == "status":
        sort_column = DBCase.status
    elif sort_by == "created_at":
        sort_column = DBCase.created_at
    elif sort_by == "current_stage":
        sort_column = DBCase.current_stage

    if sort_column:
        if sort_order == "desc":
            sort_column = sort_column.desc()
        else:
            sort_column = sort_column.asc()
        query = query.order_by(sort_column)
    else:
        query = query.order_by(DBCase.id.desc())

    total_count = query.count()
    total_pages = (total_count + page_size - 1) // page_size
    skip = (page - 1) * page_size

    db_cases = query.offset(skip).limit(page_size).all()

    cases_response = []
    for db_case in db_cases:
        stages_response = []
        for stage in db_case.stages:
            attributes_response = []
            for attr in stage.attributes:
                attributes_response.append(AttributeResponse(
                    id=attr.id,
                    stage_id=attr.stage_id,
                    attribute_template_id=attr.attribute_template_id,
                    user_text=attr.user_text,
                    user_file_path=attr.user_file_path,
                    created_at=attr.created_at,
                    updated_at=attr.updated_at
                ))

            stages_response.append(StageResponse(
                id=stage.id,
                case_id=stage.case_id,
                stage_template_id=stage.stage_template_id,
                executor=stage.executor,
                deadline=stage.deadline,
                closing_rule=stage.closing_rule,
                next_stage_rule=stage.next_stage_rule,
                status=stage.status,
                completed_at=stage.completed_at,
                completed_by=stage.completed_by,
                attributes=attributes_response
            ))

        case_response = CaseResponse(
            id=db_case.id,
            name=db_case.name,
            case_template_id=db_case.case_template_id,
            current_stage=db_case.current_stage,
            status=db_case.status,
            created_at=db_case.created_at,
            stages=stages_response
        )
        cases_response.append(case_response)

    return PaginatedCaseResponse(
        cases=cases_response,
        total_count=total_count,
        page=page,
        page_size=page_size,
        total_pages=total_pages
    )


@app.get("/cases/count/")
def get_cases_count(
        name: Optional[str] = None,
        case_template_id: Optional[int] = None,
        status: Optional[str] = None,
        executor: Optional[str] = None,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    query = db.query(DBCase)

    if name:
        query = query.filter(DBCase.name.ilike(f"%{name}%"))
    if case_template_id:
        query = query.filter(DBCase.case_template_id == case_template_id)
    if status:
        query = query.filter(DBCase.status == status)
    if executor:
        query = query.join(DBStage).filter(DBStage.executor == executor)

    return {"total_count": query.count()}


@app.get("/cases/{case_id}", response_model=CaseResponse)
def get_case(
        case_id: int,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    case = db.query(DBCase).filter(DBCase.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Дело не найдено")
    return case


@app.put("/cases/{case_id}", response_model=CaseResponse)
def update_case(
        case_id: int,
        case_data: CaseUpdate,
        db: Session = Depends(get_db),
        current_user: dict = Depends(require_admin_or_manager)
):
    case = db.query(DBCase).filter(DBCase.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Дело не найдено")

    try:
        update_data = case_data.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(case, field, value)

        db.commit()
        db.refresh(case)
        return case

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка при обновлении дела: {str(e)}")


@app.delete("/cases/{case_id}")
def delete_case(
        case_id: int,
        db: Session = Depends(get_db),
        current_user: dict = Depends(require_admin_or_manager)
):
    case = db.query(DBCase).filter(DBCase.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Дело не найдено")

    try:
        stages = db.query(DBStage).filter(DBStage.case_id == case_id).all()
        for stage in stages:
            attributes = db.query(DBAttribute).filter(DBAttribute.stage_id == stage.id).all()
            for attr in attributes:
                if attr.user_file_path:
                    get_s3_storage().delete_file(attr.user_file_path)

        db.query(DBAttribute).filter(DBAttribute.stage_id.in_(
            db.query(DBStage.id).filter(DBStage.case_id == case_id)
        )).delete(synchronize_session=False)

        db.query(DBStage).filter(DBStage.case_id == case_id).delete()
        db.delete(case)
        db.commit()

        return {"message": f"Дело {case_id} и все связанные данные удалены"}

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка при удалении дела: {str(e)}")


@app.get("/download-file/{attribute_id}")
async def download_file_by_attribute(
        attribute_id: int,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    try:
        attribute = db.query(DBAttribute).filter(DBAttribute.id == attribute_id).first()
        if not attribute:
            raise HTTPException(status_code=404, detail="Атрибут не найден")

        if not attribute.user_file_path:
            raise HTTPException(status_code=404, detail="Файл не прикреплен")

        stage = db.query(DBStage).filter(DBStage.id == attribute.stage_id).first()
        if not stage:
            raise HTTPException(status_code=404, detail="Этап не найден")

        if current_user['role'] not in ['admin', 'manager']:
            raise HTTPException(status_code=403, detail="Недостаточно прав")

        storage = get_s3_storage()

        if storage.available and attribute.user_file_path.startswith('cases/'):
            try:
                s3_object = storage.s3_client.get_object(
                    Bucket=storage.bucket,
                    Key=attribute.user_file_path
                )

                file_content = s3_object['Body'].read()
                filename = os.path.basename(attribute.user_file_path)

                import mimetypes
                mime_type, _ = mimetypes.guess_type(filename)
                if not mime_type:
                    mime_type = 'application/octet-stream'

                from fastapi.responses import Response
                return Response(
                    content=file_content,
                    media_type=mime_type,
                    headers={
                        'Content-Disposition': f'attachment; filename="{filename}"',
                        'Content-Type': mime_type
                    }
                )

            except Exception as s3_error:
                raise HTTPException(status_code=500, detail="Ошибка при загрузке файла из S3")

        else:
            if os.path.exists(attribute.user_file_path):
                filename = os.path.basename(attribute.user_file_path)

                import mimetypes
                mime_type, _ = mimetypes.guess_type(filename)
                if not mime_type:
                    mime_type = 'application/octet-stream'

                with open(attribute.user_file_path, 'rb') as file:
                    file_content = file.read()
                from fastapi.responses import Response

                return Response(
                    content=file_content,
                    media_type=mime_type,
                    headers={
                        'Content-Disposition': f'attachment; filename="{filename}"',
                        'Content-Type': mime_type
                    }
                )
            else:
                raise HTTPException(status_code=404, detail="Файл не найден")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка при загрузке файла: {str(e)}")


@app.post("/upload-file/", response_model=FileUploadResponse)
async def upload_file(
        file: UploadFile = File(...),
        case_id: int = Form(...),
        stage_id: int = Form(...),
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    try:
        stage = db.query(DBStage).filter(DBStage.id == stage_id).first()
        if not stage or stage.case_id != case_id:
            raise HTTPException(status_code=404, detail="Этап не найден")

        file_path = get_s3_storage().upload_file(file, case_id, stage_id)
        file_url = get_s3_storage().get_file_url(file_path)

        return FileUploadResponse(
            filename=file.filename,
            file_url=file_url,
            file_path=file_path
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/stages/", response_model=List[StageResponse])
def get_stages(
        skip: int = 0,
        limit: int = 100,
        case_id: Optional[int] = None,
        status: Optional[str] = None,
        executor: Optional[str] = None,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    query = db.query(DBStage)

    if case_id:
        query = query.filter(DBStage.case_id == case_id)
    if status:
        query = query.filter(DBStage.status == status)
    if executor:
        query = query.filter(DBStage.executor == executor)

    stages = query.offset(skip).limit(limit).all()
    return stages


@app.post("/stages/{stage_id}/rework-submit/")
def submit_rework(
        stage_id: int,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    try:
        stage = db.query(DBStage).filter(DBStage.id == stage_id).first()
        if not stage:
            raise HTTPException(status_code=404, detail="Этап не найден")

        if stage.status != 'rework':
            raise HTTPException(status_code=400, detail="Этап не находится на доработке")

        if stage.executor != current_user['username']:
            raise HTTPException(status_code=403, detail="Нет доступа к этому этапу")

        stage.status = 'waiting_approval'
        stage.manager_comment = None
        db.commit()

        return {"message": "Исправления отправлены на проверку руководителю"}

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка при отправке исправлений: {str(e)}")


@app.get("/stages/{stage_id}", response_model=StageResponse)
def get_stage(
        stage_id: int,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    stage = db.query(DBStage).filter(DBStage.id == stage_id).first()
    if not stage:
        raise HTTPException(status_code=404, detail="Этап не найден")
    return stage


@app.put("/stages/{stage_id}", response_model=StageResponse)
def update_stage(
        stage_id: int,
        stage_data: StageUpdate,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    stage = db.query(DBStage).filter(DBStage.id == stage_id).first()
    if not stage:
        raise HTTPException(status_code=404, detail="Этап не найден")

    if stage_data.status == 'completed':
        if stage.closing_rule == 'manager_closing' and current_user['role'] not in ['admin', 'manager']:
            raise HTTPException(
                status_code=403,
                detail="Только руководитель или администратор может завершить этот этап"
            )
        elif stage.closing_rule == 'executor_closing' and current_user['username'] != stage.executor:
            raise HTTPException(
                status_code=403,
                detail="Только исполнитель этапа может завершить этот этап"
            )

    try:
        update_data = stage_data.dict(exclude_unset=True)

        if update_data.get('status') == 'completed' and stage.status != 'completed':
            update_data['completed_at'] = datetime.now()
            if not update_data.get('completed_by'):
                update_data['completed_by'] = current_user['username']

        for field, value in update_data.items():
            setattr(stage, field, value)

        db.commit()
        db.refresh(stage)
        return stage

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка при обновлении этапа: {str(e)}")


@app.delete("/stages/{stage_id}")
def delete_stage(
        stage_id: int,
        db: Session = Depends(get_db),
        current_user: dict = Depends(require_admin_or_manager)
):
    stage = db.query(DBStage).filter(DBStage.id == stage_id).first()
    if not stage:
        raise HTTPException(status_code=404, detail="Этап не найден")

    try:
        attributes = db.query(DBAttribute).filter(DBAttribute.stage_id == stage_id).all()
        for attr in attributes:
            if attr.user_file_path:
                get_s3_storage().delete_file(attr.user_file_path)

        db.query(DBAttribute).filter(DBAttribute.stage_id == stage_id).delete()
        db.delete(stage)
        db.commit()

        return {"message": f"Этап {stage_id} и все связанные атрибуты удалены"}

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка при удалении этапа: {str(e)}")


@app.post("/attributes/", response_model=AttributeResponse)
def create_attribute(
        attribute_data: AttributeCreate,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    try:
        db_attribute = DBAttribute(**attribute_data.dict())
        db.add(db_attribute)
        db.commit()
        db.refresh(db_attribute)
        return db_attribute

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка при создании атрибута: {str(e)}")


@app.get("/attributes/", response_model=List[AttributeResponse])
def get_attributes(
        stage_id: Optional[int] = None,
        skip: int = 0,
        limit: int = 100,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    query = db.query(DBAttribute)

    if stage_id:
        query = query.filter(DBAttribute.stage_id == stage_id)

    attributes = query.offset(skip).limit(limit).all()
    return attributes


@app.put("/attributes/{attribute_id}", response_model=AttributeResponse)
def update_attribute(
        attribute_id: int,
        attribute_data: AttributeUpdate,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    attribute = db.query(DBAttribute).filter(DBAttribute.id == attribute_id).first()
    if not attribute:
        raise HTTPException(status_code=404, detail="Атрибут не найден")

    stage = db.query(DBStage).filter(DBStage.id == attribute.stage_id).first()
    if current_user['username'] != stage.executor and current_user['role'] not in ['admin', 'manager']:
        raise HTTPException(
            status_code=403,
            detail="Недостаточно прав для обновления атрибута"
        )

    try:
        update_data = attribute_data.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(attribute, field, value)

        db.commit()
        db.refresh(attribute)
        return attribute

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка при обновлении атрибута: {str(e)}")


@app.delete("/attributes/{attribute_id}")
def delete_attribute(
        attribute_id: int,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    try:
        attribute = db.query(DBAttribute).filter(DBAttribute.id == attribute_id).first()
        if not attribute:
            raise HTTPException(status_code=404, detail="Атрибут не найден")

        stage = db.query(DBStage).filter(DBStage.id == attribute.stage_id).first()
        if not stage:
            raise HTTPException(status_code=404, detail="Этап не найден")

        if stage.executor != current_user['username'] and current_user['role'] not in ['admin', 'manager']:
            raise HTTPException(status_code=403, detail="Нет доступа к этому атрибуту")

        if stage.status not in ['in_progress', 'rework']:
            raise HTTPException(
                status_code=400,
                detail="Нельзя редактировать атрибуты завершенного этапа"
            )

        if attribute.user_file_path:
            try:
                get_s3_storage().delete_file(attribute.user_file_path)
            except Exception as file_error:
                pass

        attribute.user_file_path = None
        db.commit()

        return {"message": "Файл удален из атрибута"}

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка при удалении атрибута: {str(e)}")


@app.get("/users/{username}/cases", response_model=List[CaseResponse])
def get_user_cases(
        username: str,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    cases = db.query(DBCase).join(DBStage).filter(
        DBStage.executor == username
    ).all()
    return cases


@app.get("/my-cases/", response_model=List[CaseResponse])
def get_my_cases(
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    cases = db.query(DBCase).join(DBStage).filter(
        DBStage.executor == current_user['username']
    ).all()
    return cases


@app.post("/cases/{case_id}/advance")
def advance_case(
        case_id: int,
        condition_result: Optional[str] = None,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    case = db.query(DBCase).filter(DBCase.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Дело не найдено")

    current_stage = db.query(DBStage).filter(
        DBStage.case_id == case_id,
        DBStage.stage_template_id == case.current_stage
    ).first()

    if not current_stage:
        raise HTTPException(status_code=404, detail="Текущий этап не найден")

    if current_stage.status != 'completed':
        raise HTTPException(status_code=400, detail="Текущий этап не завершен")

    next_stage_id = None

    if current_stage.next_stage_rule:
        if current_stage.next_stage_rule.startswith('condition:'):
            condition_str = current_stage.next_stage_rule.replace('condition:', '').strip()
            try:
                if condition_result and validate_stage_format(condition_result):
                    next_stage_id = condition_result
                else:
                    next_stage_id = get_next_stage_number(case.current_stage)
            except:
                next_stage_id = get_next_stage_number(case.current_stage)
        else:
            next_stage_id = current_stage.next_stage_rule
    else:
        next_stage_id = get_next_stage_number(case.current_stage)

    next_stage = db.query(DBStage).filter(
        DBStage.case_id == case_id,
        DBStage.stage_template_id == next_stage_id
    ).first()

    if not next_stage:
        case.status = 'completed'
        case.current_stage = None
        message = "Дело завершено (следующий этап не найден)"
    else:
        case.current_stage = next_stage_id
        next_stage.status = 'in_progress'
        message = f"Дело переведено на этап {next_stage_id}"

    db.commit()
    db.refresh(case)

    return {
        "message": message,
        "current_stage": case.current_stage,
        "case_status": case.status
    }


def validate_stage_format(stage: str) -> bool:
    return bool(re.match(r'^\d+(\.\d+)*$', stage))


@app.get("/cases/{case_id}/hierarchy")
def get_case_hierarchy(
        case_id: int,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    case = db.query(DBCase).filter(DBCase.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Дело не найдено")

    stages = db.query(DBStage).filter(DBStage.case_id == case_id).all()
    stage_ids = [stage.stage_template_id for stage in stages]

    hierarchy = get_stage_hierarchy(stage_ids)

    return {
        "case_id": case_id,
        "case_name": case.name,
        "current_stage": case.current_stage,
        "hierarchy": hierarchy
    }


@app.options("/cases/")
async def options_cases():
    return JSONResponse(
        content={"message": "OK"},
        headers={
            "Access-Control-Allow-Origin": "http://localhost:5173",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
            "Access-Control-Allow-Credentials": "true",
        }
    )


@app.options("/stages/{stage_id}/rework-submit/")
async def options_rework_submit():
    return JSONResponse(
        content={"message": "OK"},
        headers={
            "Access-Control-Allow-Origin": "http://localhost:5173",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
            "Access-Control-Allow-Credentials": "true",
        }
    )


@app.get("/stages/{stage_id}/attributes/")
def get_stage_attributes(
        stage_id: int,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    stage = db.query(DBStage).filter(DBStage.id == stage_id).first()
    if not stage:
        raise HTTPException(status_code=404, detail="Этап не найден")

    if stage.executor != current_user['username']:
        raise HTTPException(status_code=403, detail="Нет доступа к этому этапу")

    attributes = db.query(DBAttribute).filter(DBAttribute.stage_id == stage_id).all()
    return attributes


@app.post("/delete-file/")
def delete_file(
        file_data: dict,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    try:
        file_path = file_data.get('file_path')
        if not file_path:
            raise HTTPException(status_code=400, detail="Не указан путь к файлу")

        success = get_s3_storage().delete_file(file_path)

        if success:
            return {"message": "Файл удален"}
        else:
            raise HTTPException(status_code=500, detail="Ошибка при удалении файла")

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка при удалении файла: {str(e)}")


@app.get("/files/{file_path:path}")
def serve_local_file(
        file_path: str,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    try:
        base_path = "uploads"
        full_path = os.path.join(base_path, file_path)

        if not os.path.exists(full_path):
            raise HTTPException(status_code=404, detail="Файл не найден")

        if not os.path.abspath(full_path).startswith(os.path.abspath(base_path)):
            raise HTTPException(status_code=403, detail="Доступ запрещен")

        import mimetypes
        mime_type, _ = mimetypes.guess_type(full_path)
        if not mime_type:
            mime_type = 'application/octet-stream'

        filename = os.path.basename(full_path)

        return FileResponse(
            full_path,
            media_type=mime_type,
            filename=filename
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка при загрузке файла: {str(e)}")


@app.get("/debug/executors")
def debug_executors(db: Session = Depends(get_db)):
    try:
        executors = db.query(DBExecutor).all()
        result = []
        for executor in executors:
            result.append({
                "id": executor.id,
                "login": executor.login,
                "full_name": executor.full_name,
                "expert_area": executor.expert_area,
                "created_by": executor.created_by
            })
        return {"count": len(result), "executors": result}
    except Exception as e:
        return {"error": str(e)}


@app.get("/executor/stages/", response_model=List[StageResponse])
def get_executor_stages(
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    try:
        stages = db.query(DBStage).filter(
            DBStage.executor == current_user['username'],
            DBStage.status.in_(['in_progress', 'waiting_approval', 'rework'])
        ).all()

        result = []
        for stage in stages:
            case = db.query(DBCase).filter(DBCase.id == stage.case_id).first()

            attributes = db.query(DBAttribute).filter(DBAttribute.stage_id == stage.id).all()
            attributes_response = []
            for attr in attributes:
                attributes_response.append(AttributeResponse(
                    id=attr.id,
                    stage_id=attr.stage_id,
                    attribute_template_id=attr.attribute_template_id,
                    user_text=attr.user_text,
                    user_file_path=attr.user_file_path,
                    created_at=attr.created_at,
                    updated_at=attr.updated_at
                ))

            result.append(StageResponse(
                id=stage.id,
                case_id=stage.case_id,
                case_name=case.name if case else f"Дело #{stage.case_id}",
                stage_template_id=stage.stage_template_id,
                executor=stage.executor,
                deadline=stage.deadline,
                closing_rule=stage.closing_rule,
                next_stage_rule=stage.next_stage_rule,
                status=stage.status,
                completed_at=stage.completed_at,
                completed_by=stage.completed_by,
                manager_comment=stage.manager_comment,
                attributes=attributes_response
            ))

        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка при получении этапов исполнителя: {str(e)}")


@app.post("/stages/{stage_id}/complete/")
def complete_stage(
        stage_id: int,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    try:
        stage = db.query(DBStage).filter(DBStage.id == stage_id).first()
        if not stage:
            raise HTTPException(status_code=404, detail="Этап не найден")

        if stage.executor != current_user['username']:
            raise HTTPException(status_code=403, detail="Нет доступа к этому этапу")

        if stage.status == 'completed':
            raise HTTPException(status_code=400, detail="Этап уже завершен")

        if stage.closing_rule == 'manager_closing':
            stage.status = 'waiting_approval'
        else:
            stage.status = 'completed'

        stage.completed_at = datetime.now()
        stage.completed_by = current_user['username']

        case = db.query(DBCase).filter(DBCase.id == stage.case_id).first()
        if not case:
            raise HTTPException(status_code=404, detail="Дело не найдено")

        next_stage_id = None
        if stage.closing_rule == 'executor_closing':
            if stage.next_stage_rule:
                next_stage_id = stage.next_stage_rule
            else:
                parts = stage.stage_template_id.split('.')
                if len(parts) == 2:
                    try:
                        current_stage_num = int(parts[1])
                        next_stage_num = current_stage_num + 1
                        next_stage_id = f"{parts[0]}.{next_stage_num}"
                    except ValueError as e:
                        next_stage_id = None

            if next_stage_id:
                next_stage = db.query(DBStage).filter(
                    DBStage.case_id == stage.case_id,
                    DBStage.stage_template_id == next_stage_id
                ).first()

                if next_stage:
                    next_stage.status = 'in_progress'
                    case.current_stage = next_stage_id
                else:
                    case.status = 'completed'
                    case.current_stage = None
            else:
                case.status = 'completed'
                case.current_stage = None

        db.commit()

        return {
            "message": "Этап успешно завершен" if stage.closing_rule == 'executor_closing' else "Этап отправлен на проверку руководителю",
            "case_status": case.status,
            "next_stage": case.current_stage,
            "stage_status": stage.status
        }

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка при завершении этапа: {str(e)}")


@app.post("/stages/{stage_id}/attributes/batch/")
def create_attributes_batch(
        stage_id: int,
        attributes_data: List[AttributeCreate],
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    try:
        stage = db.query(DBStage).filter(DBStage.id == stage_id).first()
        if not stage:
            raise HTTPException(status_code=404, detail="Этап не найден")

        if stage.executor != current_user['username']:
            raise HTTPException(status_code=403, detail="Нет доступа к этому этапу")

        results = []
        for i, attr_data in enumerate(attributes_data):
            existing_attr = db.query(DBAttribute).filter(
                DBAttribute.stage_id == stage_id,
                DBAttribute.attribute_template_id == attr_data.attribute_template_id
            ).first()

            if existing_attr:
                existing_attr.user_text = attr_data.user_text
                existing_attr.user_file_path = attr_data.user_file_path
                results.append(existing_attr)
            else:
                new_attr = DBAttribute(
                    stage_id=stage_id,
                    attribute_template_id=attr_data.attribute_template_id,
                    user_text=attr_data.user_text,
                    user_file_path=attr_data.user_file_path
                )
                db.add(new_attr)
                results.append(new_attr)

        db.commit()

        for attr in results:
            db.refresh(attr)

        return results

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка при сохранении атрибутов: {str(e)}")


@app.get("/manager/pending-stages/", response_model=List[StageWithCaseInfo])
def get_manager_pending_stages(
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    try:
        if current_user['role'] not in ['admin', 'manager']:
            raise HTTPException(status_code=403, detail="Недостаточно прав")

        from sqlalchemy.orm import joinedload

        stages = db.query(DBStage).options(
            joinedload(DBStage.attributes).joinedload(DBAttribute.attribute_template)
        ).join(DBCase).filter(
            DBStage.status == 'waiting_approval',
            DBStage.closing_rule == 'manager_closing'
        ).all()

        result = []
        for stage in stages:
            attributes_response = []
            for attr in stage.attributes:
                attributes_response.append(AttributeResponse(
                    id=attr.id,
                    stage_id=attr.stage_id,
                    attribute_template_id=attr.attribute_template_id,
                    user_text=attr.user_text,
                    user_file_path=attr.user_file_path,
                    created_at=attr.created_at,
                    updated_at=attr.updated_at
                ))

            stage_data = StageWithCaseInfo(
                id=stage.id,
                case_id=stage.case_id,
                stage_template_id=stage.stage_template_id,
                executor=stage.executor,
                deadline=stage.deadline,
                closing_rule=stage.closing_rule,
                next_stage_rule=stage.next_stage_rule,
                status=stage.status,
                completed_at=stage.completed_at,
                completed_by=stage.completed_by,
                manager_comment=stage.manager_comment,
                case_name=stage.case.name if stage.case else f"Дело #{stage.case_id}",
                attributes=attributes_response
            )
            result.append(stage_data)

        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка при получении этапов: {str(e)}")


@app.post("/stages/{stage_id}/manager-approve/")
def manager_approve_stage(
        stage_id: int,
        approval_data: StageApprovalRequest,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    if current_user['role'] not in ['admin', 'manager']:
        raise HTTPException(status_code=403, detail="Недостаточно прав")

    try:
        stage = db.query(DBStage).filter(DBStage.id == stage_id).first()
        if not stage:
            raise HTTPException(status_code=404, detail="Этап не найден")

        if stage.status != 'waiting_approval':
            raise HTTPException(status_code=400, detail="Этап не ожидает утверждения")

        if stage.closing_rule != 'manager_closing':
            raise HTTPException(status_code=400, detail="Этот этап не требует утверждения менеджера")

        stage.status = 'completed'
        stage.completed_by = current_user['username']
        stage.completed_at = datetime.now()
        stage.manager_comment = approval_data.comment

        case = db.query(DBCase).filter(DBCase.id == stage.case_id).first()
        if case and case.current_stage == stage.stage_template_id:
            next_stage_id = None

            if stage.next_stage_rule:
                next_stage_id = stage.next_stage_rule
            else:
                next_stage_id = get_next_stage_number(stage.stage_template_id)

            if next_stage_id:
                next_stage = db.query(DBStage).filter(
                    DBStage.case_id == stage.case_id,
                    DBStage.stage_template_id == next_stage_id
                ).first()

                if next_stage:
                    next_stage.status = 'in_progress'
                    case.current_stage = next_stage_id
                else:
                    case.status = 'completed'
                    case.current_stage = None
            else:
                case.status = 'completed'
                case.current_stage = None

        db.commit()
        return {"message": "Этап утвержден", "next_stage": next_stage_id}

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка при утверждении этапа: {str(e)}")


@app.get("/attribute-templates/", response_model=List[AttributeTemplateResponse])
def get_all_attribute_templates(
        skip: int = 0,
        limit: int = 1000,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    templates = db.query(DBAttributeTemplate).offset(skip).limit(limit).all()
    return templates


@app.post("/stages/{stage_id}/manager-rework/")
def manager_return_for_rework(
        stage_id: int,
        approval_data: StageApprovalRequest,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    if current_user['role'] not in ['admin', 'manager']:
        raise HTTPException(status_code=403, detail="Недостаточно прав")

    try:
        stage = db.query(DBStage).filter(DBStage.id == stage_id).first()
        if not stage:
            raise HTTPException(status_code=404, detail="Этап не найден")

        if stage.status != 'waiting_approval':
            raise HTTPException(status_code=400, detail="Этап не ожидает утверждения")

        if stage.closing_rule != 'manager_closing':
            raise HTTPException(status_code=400, detail="Этот этап не требует утверждения менеджера")

        if not approval_data.comment:
            raise HTTPException(status_code=400, detail="Комментарий обязателен при возврате на доработку")

        stage.status = 'rework'
        stage.manager_comment = approval_data.comment
        db.commit()

        return {"message": "Этап возвращен на доработку"}

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка при возврате этапа: {str(e)}")


try:
    from minio_setup import setup_minio

    if setup_minio():
        print("MinIO настроен успешно")
    else:
        print("MinIO не доступен, используется локальное хранилище")
except Exception as e:
    print(f"Ошибка настройки MinIO: {e}")

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="debug")