import datetime
import re
from datetime import datetime, timedelta
import datetime as dt
from s3_storage import get_s3_storage

from fastapi import FastAPI, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
import json
from typing import List, Optional
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from datetime import timedelta

from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt

from fastapi import Request


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
from stage_logic import get_next_stage, validate_stage_format
from s3_storage import s3_storage
from fastapi import UploadFile, File, Form

from auth_models import UserCreate, Token, UserResponse
from auth_config import authenticate_user, create_access_token, ACCESS_TOKEN_EXPIRE_HOURS, SECRET_KEY, ALGORITHM, \
    require_admin_or_manager, require_admin_only
from auth_config import get_user
from auth_deps import get_current_active_user, require_role

from fastapi.middleware.cors import CORSMiddleware
from stage_numbering import get_next_stage_number, validate_stage_transition, get_child_stages, get_stage_hierarchy

# Создаем таблицы
Base.metadata.create_all(bind=engine)



app = FastAPI(title="Case Management API")

# Создаем таблицы
Base.metadata.create_all(bind=engine)




# ДОБАВЬТЕ ЭТО ПЕРЕД ВСЕМИ ДРУГИМИ МИДЛВАРАМИ
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://localhost:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
security = HTTPBearer()

# @app.middleware("http")
# async def add_cors_headers(request: Request, call_next):
#     response = await call_next(request)
#
#     response.headers["Access-Control-Allow-Origin"] = "http://localhost:5173"
#     response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
#     response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
#     response.headers["Access-Control-Allow-Credentials"] = "true"
#
#     return response

# ОБНОВЛЕННЫЕ ОБРАБОТЧИКИ OPTIONS С НОВЫМИ URL
@app.options("/case_templates/export/")
@app.options("/case_templates/export-simple/")
@app.options("/case_templates/")
@app.options("/case_templates/{case_id}")
@app.options("/case_templates/{case_id}/stage_templates/")
@app.options("/users/me/")
async def options_handler():
    return JSONResponse(
        content={"message": "OK"},
        headers={
            "Access-Control-Allow-Origin": "http://localhost:5173",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
            "Access-Control-Allow-Credentials": "true",
        }
    )

async def simple_auth(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Упрощенная авторизация для тестирования"""
    print(f"=== SIMPLE_AUTH CALLED ===")
    print(f"Token received: {credentials.credentials}")

    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        print(f"Token decoded successfully: {payload}")

        username = payload.get("sub")
        role = payload.get("role")
        print(f"Username: {username}, Role: {role}")

        return {
            "username": username,
            "role": role,
            "is_active": True
        }
    except jwt.ExpiredSignatureError:
        print("Token expired")
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        print(f"Invalid token: {str(e)}")
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except JWTError as e:
        print(f"JWTError: {str(e)}")
        raise HTTPException(status_code=401, detail=f"Token error: {str(e)}")

# Эндпоинты аутентификации (без изменений)
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

@app.get("/debug/auth-chain")
async def debug_auth_chain(current_user: dict = Depends(simple_auth)):
    """Проверка всей цепочки авторизации"""
    print(f"=== DEBUG AUTH CHAIN ===")
    print(f"User reached endpoint: {current_user}")
    return {
        "message": "Auth chain successful",
        "user": current_user
    }

@app.get("/users/me/", response_model=UserResponse)
async def read_users_me(current_user: dict = Depends(simple_auth)):
    return {
        "id": 1,
        "username": current_user["username"],
        "role": current_user["role"],
        "is_active": current_user.get("is_active", True)
    }

# ОБНОВЛЕННЫЕ ЭНДПОИНТЫ С НОВЫМИ URL

@app.post("/case_templates/export/", response_model=CaseTemplateResponse)
def export_case_template(
        export_data: ExportData,
        db: Session = Depends(get_db),
        current_user: dict = Depends(simple_auth)
):
    """Экспорт данных из фронтенда с проверкой шаблонов атрибутов"""
    print(f"User {current_user} exporting data")

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

        # Создаем шаблон дела
        db_case_template = DBCaseTemplate(
            name=export_data.name,
            description=export_data.description,
            stages_list=json.dumps([stage.id for stage in export_data.stages])
        )
        db.add(db_case_template)
        db.commit()
        db.refresh(db_case_template)

        # Создаем шаблоны этапов
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

        # Сохраняем шаблоны атрибутов
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
        print(f"User {current_user['username']} successfully saved case template: {db_case_template.id}")
        return db_case_template

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print("Error:", str(e))
        raise HTTPException(status_code=500, detail=f"Ошибка при экспорте дела: {str(e)}")

# ЭНДПОИНТЫ ДЛЯ ШАБЛОНОВ АТРИБУТОВ С ОБНОВЛЕННЫМИ URL
@app.post("/stage_templates/{stage_id}/attribute_templates/", response_model=List[AttributeTemplateResponse])
def save_attribute_templates(
        stage_id: str,
        templates: List[AttributeTemplateCreate],
        db: Session = Depends(get_db),
        current_user: dict = Depends(simple_auth)
):
    """Сохранение шаблонов атрибутов для этапа"""
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
    """Получение шаблонов атрибутов для этапа"""
    templates = db.query(DBAttributeTemplate).filter(DBAttributeTemplate.stage_template_id == stage_id).all()
    return templates

# ОСНОВНЫЕ ЭНДПОИНТЫ ДЛЯ ШАБЛОНОВ ДЕЛ
@app.post("/case_templates/", response_model=CaseTemplateResponse)
def create_case_template(
        case_data: CaseTemplateCreate,
        db: Session = Depends(get_db),
        current_user: dict = Depends(require_admin_or_manager)  # ИЗМЕНЕНО
):
    """Создание нового шаблона дела с этапами (для admin и manager)"""
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
    """Получение списка всех шаблонов дел"""
    cases = db.query(DBCaseTemplate).offset(skip).limit(limit).all()
    return cases

@app.get("/case_templates/{case_id}", response_model=CaseTemplateResponse)
def get_case_template(
        case_id: int,
        db: Session = Depends(get_db),
        current_user: dict = Depends(simple_auth)
):
    """Получение шаблона дела по ID"""
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
    """Получение всех шаблонов этапов конкретного дела"""
    stages = db.query(DBStageTemplate).filter(DBStageTemplate.case_template_id == case_id).all()
    return stages

@app.post("/token/refresh")
async def refresh_token(current_user: dict = Depends(simple_auth)):
    """Обновление токена"""
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

# ЭНДПОИНТЫ ДЛЯ АДМИНИСТРИРОВАНИЯ
@app.delete("/case_templates/{case_id}")
def delete_case_template(
        case_id: int,
        db: Session = Depends(get_db),
        current_user: dict = Depends(require_admin_or_manager)  # ИЗМЕНЕНО
):
    """Удаление шаблона дела и всех его этапов (для admin и manager)"""
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

# ЭНДПОИНТЫ ДЛЯ ИСПОЛНИТЕЛЕЙ (без изменений)
@app.post("/executors/", response_model=ExecutorResponse)
def create_executor(
        executor_data: ExecutorCreate,
        db: Session = Depends(get_db),
        current_user: dict = Depends(require_admin_only)  # ИЗМЕНЕНО - ТОЛЬКО ADMIN
):
    """Создание нового исполнителя (только для администраторов)"""
    print(f"Admin {current_user['username']} creating executor: {executor_data.login}")

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

        print(f"Added user to USERS_DATA: {executor_data.login}")

        db_executor = DBExecutor(
            login=executor_data.login,
            full_name=executor_data.full_name,
            expert_area=executor_data.expert_area,
            created_by=current_user["username"]
        )
        db.add(db_executor)
        db.commit()
        db.refresh(db_executor)

        print(f"Executor created successfully: {db_executor.login}")
        return db_executor

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"Error creating executor: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Ошибка при создании исполнителя: {str(e)}")

@app.get("/executors/", response_model=List[ExecutorResponse])
def get_executors(
        skip: int = 0,
        limit: int = 100,
        db: Session = Depends(get_db),
        current_user: dict = Depends(require_admin_or_manager)  # ИЗМЕНЕНО
):
    """Получение списка исполнителей (для admin и manager)"""
    print(f"User {current_user['username']} with role {current_user['role']} viewing executors")
    executors = db.query(DBExecutor).offset(skip).limit(limit).all()
    return executors


# ЭТОТ ЭНДПОИНТ ДОЛЖЕН БЫТЬ ПЕРВЫМ
@app.get("/executors/list", response_model=List[ExecutorResponse])
def get_executors_list(
        skip: int = 0,
        limit: int = 100,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    """Получение списка исполнителей для выбора при создании дела"""
    try:
        print("=== GET_EXECUTORS_LIST CALLED ===")
        executors = db.query(DBExecutor).offset(skip).limit(limit).all()
        print(f"Returning {len(executors)} executors")
        return executors

    except Exception as e:
        print(f"Error in get_executors_list: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка при получении списка исполнителей: {str(e)}")


# ЭТОТ ЭНДПОИНТ ДОЛЖЕН БЫТЬ ПОСЛЕ /executors/list
@app.get("/executors/{executor_id}", response_model=ExecutorResponse)
def get_executor(
        executor_id: int,
        db: Session = Depends(get_db),
        current_user: dict = Depends(require_admin_or_manager)
):
    """Получение исполнителя по ID (для admin и manager)"""
    executor = db.query(DBExecutor).filter(DBExecutor.id == executor_id).first()
    if not executor:
        raise HTTPException(status_code=404, detail="Исполнитель не найден")
    return executor

@app.put("/executors/{executor_id}", response_model=ExecutorResponse)
def update_executor(
        executor_id: int,
        executor_data: ExecutorBase,
        db: Session = Depends(get_db),
        current_user: dict = Depends(require_admin_or_manager)  # ИЗМЕНЕНО - manager может редактировать
):
    """Обновление данных исполнителя (для admin и manager)"""
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

        print(f"User {current_user['username']} with role {current_user['role']} updated executor: {executor.login}")
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
        current_user: dict = Depends(require_admin_only)  # ИЗМЕНЕНО - ТОЛЬКО ADMIN
):
    """Удаление исполнителя (только для администраторов)"""
    executor = db.query(DBExecutor).filter(DBExecutor.id == executor_id).first()
    if not executor:
        raise HTTPException(status_code=404, detail="Исполнитель не найден")

    try:
        from auth_config import USERS_DATA
        if executor.login in USERS_DATA:
            del USERS_DATA[executor.login]
            print(f"Removed user from USERS_DATA: {executor.login}")

        db.delete(executor)
        db.commit()

        print(f"Admin {current_user['username']} deleted executor: {executor.login}")
        return {"message": f"Исполнитель {executor.login} удален"}

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка при удалении: {str(e)}")

@app.get("/")
def read_root():
    return {"message": "Case Management API is running"}

# ОБНОВЛЕННЫЕ OPTIONS ДЛЯ НОВЫХ URL
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
    """Создание нового дела на основе шаблона"""
    try:
        print("=== CREATE CASE CALLED ===")
        print(f"Received case data: {case_data}")
        print(f"Current user: {current_user}")

        # Проверяем существование шаблона дела
        template = db.query(DBCaseTemplate).filter(DBCaseTemplate.id == case_data.case_template_id).first()
        if not template:
            raise HTTPException(status_code=404, detail="Шаблон дела не найден")

        print(f"Template found: {template.name}")

        # Проверяем существование исполнителей
        for stage_data in case_data.stages:
            print(f"Checking executor: {stage_data.executor}")
            executor = db.query(DBExecutor).filter(DBExecutor.login == stage_data.executor).first()
            if not executor:
                raise HTTPException(
                    status_code=404,
                    detail=f"Исполнитель {stage_data.executor} не найден"
                )
            print(f"Executor found: {executor.full_name}")

        # Создаем дело
        db_case = DBCase(
            name=case_data.name,
            case_template_id=case_data.case_template_id,
            current_stage=None
        )
        db.add(db_case)
        db.commit()
        db.refresh(db_case)

        print(f"Case created with ID: {db_case.id}")

        # Получаем этапы шаблона
        template_stages = db.query(DBStageTemplate).filter(
            DBStageTemplate.case_template_id == case_data.case_template_id
        ).all()

        print(f"Found {len(template_stages)} template stages")

        # Создаем этапы на основе шаблона
        stages_by_template_id = {s.stage_template_id: s for s in case_data.stages}

        for template_stage in template_stages:
            stage_data = stages_by_template_id.get(template_stage.id)
            if not stage_data:
                print(f"Skipping stage {template_stage.id} - no data provided")
                continue

            print(f"Creating stage: {template_stage.id}")

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

            print(f"Stage created with ID: {db_stage.id}")

            # Создаем атрибуты на основе шаблонов атрибутов
            attribute_templates = db.query(DBAttributeTemplate).filter(
                DBAttributeTemplate.stage_template_id == template_stage.id
            ).all()

            print(f"Creating {len(attribute_templates)} attributes for stage {db_stage.id}")

            for attr_template in attribute_templates:
                db_attr = DBAttribute(
                    stage_id=db_stage.id,
                    attribute_template_id=attr_template.id,
                    user_text=None,
                    user_file_path=None
                )
                db.add(db_attr)

        # Устанавливаем первый этап как текущий
        if template_stages:
            first_stage = template_stages[0]
            db_case.current_stage = first_stage.id

            # Активируем первый этап
            first_db_stage = db.query(DBStage).filter(
                DBStage.case_id == db_case.id,
                DBStage.stage_template_id == first_stage.id
            ).first()

            if first_db_stage:
                first_db_stage.status = 'in_progress'

            db.commit()
            print(f"Set current stage to: {first_stage.id}")

        db.refresh(db_case)
        print("Case creation completed successfully")
        return db_case

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"Error in create_case: {e}")
        import traceback
        traceback.print_exc()
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
    """Получение списка дел с пагинацией, сортировкой и фильтрацией"""
    from sqlalchemy.orm import joinedload
    from sqlalchemy import and_

    # Базовый запрос с подгрузкой этапов
    query = db.query(DBCase).options(joinedload(DBCase.stages))

    # Применяем фильтры
    if name:
        query = query.filter(DBCase.name.ilike(f"%{name}%"))
    if case_template_id:
        query = query.filter(DBCase.case_template_id == case_template_id)
    if status:
        query = query.filter(DBCase.status == status)

    # ИЗМЕНЕНИЕ: Фильтрация по исполнителю ТЕКУЩЕГО этапа
    if executor and executor != 'all':
        # Создаем подзапрос для поиска дел, где текущий этап имеет указанного исполнителя
        subquery = db.query(DBStage.case_id).filter(
            and_(
                DBStage.stage_template_id == DBCase.current_stage,
                DBStage.executor == executor,
                DBStage.case_id == DBCase.id
            )
        ).exists()
        query = query.filter(subquery)

    # Применяем сортировку
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
        # Сортировка по умолчанию
        query = query.order_by(DBCase.id.desc())

    # Вычисляем пагинацию
    total_count = query.count()
    total_pages = (total_count + page_size - 1) // page_size
    skip = (page - 1) * page_size

    # Применяем пагинацию
    db_cases = query.offset(skip).limit(page_size).all()

    # Преобразуем DBCase в CaseResponse
    cases_response = []
    for db_case in db_cases:
        # Преобразуем этапы
        stages_response = []
        for stage in db_case.stages:
            # Преобразуем атрибуты этапа
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
# Добавим новый эндпоинт для получения общего количества
@app.get("/cases/count/")
def get_cases_count(
        name: Optional[str] = None,
        case_template_id: Optional[int] = None,
        status: Optional[str] = None,
        executor: Optional[str] = None,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    """Получение общего количества дел для пагинации"""
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
    """Получение дела по ID"""
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
    """Обновление дела"""
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
    """Удаление дела и всех связанных данных"""
    case = db.query(DBCase).filter(DBCase.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Дело не найдено")

    try:
        # Удаляем файлы из S3
        stages = db.query(DBStage).filter(DBStage.case_id == case_id).all()
        for stage in stages:
            attributes = db.query(DBAttribute).filter(DBAttribute.stage_id == stage.id).all()
            for attr in attributes:
                if attr.user_file_path:
                    get_s3_storage().delete_file(attr.user_file_path)

        # Удаляем атрибуты и этапы
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


# ЭНДПОИНТЫ ДЛЯ ЗАГРУЗКИ ФАЙЛОВ
@app.post("/upload-file/", response_model=FileUploadResponse)
async def upload_file(
        file: UploadFile = File(...),
        case_id: int = Form(...),
        stage_id: int = Form(...),
        db: Session = Depends(get_db),  # ДОБАВЛЕНО
        current_user: dict = Depends(get_current_active_user)
):
    """Загрузка файла в S3 хранилище"""
    try:
        # Проверяем существование stage и case
        stage = db.query(DBStage).filter(DBStage.id == stage_id).first()
        if not stage or stage.case_id != case_id:
            raise HTTPException(status_code=404, detail="Этап не найден")

        # Загружаем файл в S3
        file_path = get_s3_storage().upload_file(file, case_id, stage_id)
        file_url = get_s3_storage().get_file_url(file_path)

        return FileUploadResponse(
            filename=file.filename,
            file_url=file_url,
            file_path=file_path
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ЭНДПОИНТЫ ДЛЯ ЭТАПОВ (STAGES)
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
    """Получение списка этапов с фильтрацией"""
    query = db.query(DBStage)

    if case_id:
        query = query.filter(DBStage.case_id == case_id)
    if status:
        query = query.filter(DBStage.status == status)
    if executor:
        query = query.filter(DBStage.executor == executor)

    stages = query.offset(skip).limit(limit).all()
    return stages


@app.get("/stages/{stage_id}", response_model=StageResponse)
def get_stage(
        stage_id: int,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    """Получение этапа по ID"""
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
    """Обновление этапа"""
    stage = db.query(DBStage).filter(DBStage.id == stage_id).first()
    if not stage:
        raise HTTPException(status_code=404, detail="Этап не найден")

    # Проверяем права для завершения этапа
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

        # Если этап завершается, устанавливаем время завершения
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
    """Удаление этапа"""
    stage = db.query(DBStage).filter(DBStage.id == stage_id).first()
    if not stage:
        raise HTTPException(status_code=404, detail="Этап не найден")

    try:
        # Удаляем файлы из S3
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


# ЭНДПОИНТЫ ДЛЯ АТРИБУТОВ (ATTRIBUTES)
@app.post("/attributes/", response_model=AttributeResponse)
def create_attribute(
        attribute_data: AttributeCreate,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    """Создание атрибута"""
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
    """Получение списка атрибутов"""
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
    """Обновление атрибута"""
    attribute = db.query(DBAttribute).filter(DBAttribute.id == attribute_id).first()
    if not attribute:
        raise HTTPException(status_code=404, detail="Атрибут не найден")

    # Проверяем права на обновление атрибута
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
        current_user: dict = Depends(require_admin_or_manager)
):
    """Удаление атрибута"""
    attribute = db.query(DBAttribute).filter(DBAttribute.id == attribute_id).first()
    if not attribute:
        raise HTTPException(status_code=404, detail="Атрибут не найден")

    try:
        # Удаляем файл из S3 если есть
        if attribute.user_file_path:
            s3_storage.delete_file(attribute.user_file_path)

        db.delete(attribute)
        db.commit()
        return {"message": f"Атрибут {attribute_id} удален"}

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка при удалении атрибута: {str(e)}")


# СПЕЦИАЛЬНЫЕ МЕТОДЫ
@app.get("/users/{username}/cases", response_model=List[CaseResponse])
def get_user_cases(
        username: str,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    """Получение дел, где пользователь является исполнителем"""
    cases = db.query(DBCase).join(DBStage).filter(
        DBStage.executor == username
    ).all()
    return cases


@app.get("/my-cases/", response_model=List[CaseResponse])
def get_my_cases(
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    """Получение дел текущего пользователя (где он исполнитель)"""
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
    """Переход к следующему этапу дела с правильной логикой нумерации"""
    case = db.query(DBCase).filter(DBCase.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Дело не найдено")

    # Находим текущий активный этап
    current_stage = db.query(DBStage).filter(
        DBStage.case_id == case_id,
        DBStage.stage_template_id == case.current_stage
    ).first()

    if not current_stage:
        raise HTTPException(status_code=404, detail="Текущий этап не найден")

    # Проверяем, что текущий этап завершен
    if current_stage.status != 'completed':
        raise HTTPException(status_code=400, detail="Текущий этап не завершен")

    # Определяем следующий этап
    next_stage_id = None

    if current_stage.next_stage_rule:
        # Если правило задано явно, используем его
        if current_stage.next_stage_rule.startswith('condition:'):
            # Обработка условий ветвления
            # Формат: "condition:value > 100 ? '2.1' : '2.2'"
            condition_str = current_stage.next_stage_rule.replace('condition:', '').strip()
            try:
                # Упрощенная обработка условий - предполагаем, что condition_result уже содержит нужный этап
                if condition_result and validate_stage_format(condition_result):
                    next_stage_id = condition_result
                else:
                    # Если условие не задано, используем логику по умолчанию
                    next_stage_id = get_next_stage_number(case.current_stage)
            except:
                next_stage_id = get_next_stage_number(case.current_stage)
        else:
            # Просто номер следующего этапа
            next_stage_id = current_stage.next_stage_rule
    else:
        # Если правило не задано, используем автоматическую логику нумерации
        next_stage_id = get_next_stage_number(case.current_stage)

    # Проверяем существование следующего этапа
    next_stage = db.query(DBStage).filter(
        DBStage.case_id == case_id,
        DBStage.stage_template_id == next_stage_id
    ).first()

    if not next_stage:
        # Если следующего этапа нет, завершаем дело
        case.status = 'completed'
        case.current_stage = None
        message = "Дело завершено (следующий этап не найден)"
    else:
        # Переходим к следующему этапу
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


# Вспомогательная функция для проверки формата этапа
def validate_stage_format(stage: str) -> bool:
    """Проверяет корректность формата номера этапа"""
    return bool(re.match(r'^\d+(\.\d+)*$', stage))


# Новый эндпоинт для получения иерархии этапов дела
@app.get("/cases/{case_id}/hierarchy")
def get_case_hierarchy(
        case_id: int,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    """Получение иерархии этапов дела"""
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



@app.delete("/attributes/{attribute_id}")
def delete_attribute(
        attribute_id: int,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    """Удаление атрибута"""
    attribute = db.query(DBAttribute).filter(DBAttribute.id == attribute_id).first()
    if not attribute:
        raise HTTPException(status_code=404, detail="Атрибут не найден")

    # Проверяем права доступа через этап
    stage = db.query(DBStage).filter(DBStage.id == attribute.stage_id).first()
    if not stage:
        raise HTTPException(status_code=404, detail="Этап не найден")

    if stage.executor != current_user['username']:
        raise HTTPException(status_code=403, detail="Нет доступа к этому атрибуту")

    try:
        # Удаляем файл из хранилища если есть
        if attribute.user_file_path:
            get_s3_storage().delete_file(attribute.user_file_path)

        db.delete(attribute)
        db.commit()

        return {"message": "Атрибут удален"}

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка при удалении атрибута: {str(e)}")


@app.get("/stages/{stage_id}/attributes/")
def get_stage_attributes(
        stage_id: int,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    """Получение атрибутов этапа"""
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
    """Удаление файла из хранилища"""
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


@app.get("/debug/executors")
def debug_executors(db: Session = Depends(get_db)):
    """Диагностический эндпоинт для проверки исполнителей"""
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








# @app.get("/executor/stages/", response_model=List[StageResponse])
@app.get("/executor/stages/", response_model=List[StageResponse])
def get_executor_stages(
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    """Получение этапов текущего исполнителя - in_progress, waiting_approval и rework"""
    try:
        print(f"Getting stages for executor: {current_user['username']}")

        # ФИЛЬТРАЦИЯ: этапы со статусом in_progress, waiting_approval и rework
        stages = db.query(DBStage).filter(
            DBStage.executor == current_user['username'],
            DBStage.status.in_(['in_progress', 'waiting_approval', 'rework'])
        ).all()

        print(f"Found {len(stages)} stages for executor {current_user['username']}")

        result = []
        for stage in stages:
            case = db.query(DBCase).filter(DBCase.id == stage.case_id).first()
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
                completed_by=stage.completed_by
            ))

        return result

    except Exception as e:
        print(f"Error in get_executor_stages: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка при получении этапов исполнителя: {str(e)}")

@app.post("/stages/{stage_id}/complete/")
def complete_stage(
        stage_id: int,
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    """Завершение этапа исполнителем"""
    try:
        print(f"=== DEBUG: Starting complete_stage ===")
        print(f"Stage ID: {stage_id}")
        print(f"Current user: {current_user}")

        # Находим этап
        stage = db.query(DBStage).filter(DBStage.id == stage_id).first()
        if not stage:
            print(f"DEBUG: Stage {stage_id} not found")
            raise HTTPException(status_code=404, detail="Этап не найден")

        print(f"DEBUG: Stage found - ID: {stage.id}, Executor: {stage.executor}, Status: {stage.status}")
        print(f"DEBUG: Stage template ID: {stage.stage_template_id}, Closing rule: {stage.closing_rule}")

        # Проверяем права доступа
        if stage.executor != current_user['username']:
            print(f"DEBUG: Access denied - stage executor {stage.executor} != current user {current_user['username']}")
            raise HTTPException(status_code=403, detail="Нет доступа к этому этапу")

        # ОБНОВЛЕНО: Разрешаем повторную отправку для этапов в waiting_approval
        if stage.status == 'completed':
            print(f"DEBUG: Stage already completed")
            raise HTTPException(status_code=400, detail="Этап уже завершен")

        # ОБНОВЛЕНО: Устанавливаем статус в зависимости от правила закрытия
        if stage.closing_rule == 'manager_closing':
            stage.status = 'waiting_approval'
            print(f"DEBUG: Stage set to waiting_approval (manager_closing)")
        else:
            stage.status = 'completed'
            print(f"DEBUG: Stage set to completed (executor_closing)")

        stage.completed_at = datetime.now()
        stage.completed_by = current_user['username']

        # Находим связанное дело
        case = db.query(DBCase).filter(DBCase.id == stage.case_id).first()
        if not case:
            print(f"DEBUG: Case {stage.case_id} not found")
            raise HTTPException(status_code=404, detail="Дело не найдено")

        print(f"DEBUG: Case found - ID: {case.id}, Name: {case.name}, Current stage: {case.current_stage}")

        # ОБНОВЛЕНО: Логика перехода только для executor_closing
        next_stage_id = None
        if stage.closing_rule == 'executor_closing':  # ТОЛЬКО для executor_closing
            if stage.next_stage_rule:
                next_stage_id = stage.next_stage_rule
                print(f"DEBUG: Using next_stage_rule: {next_stage_id}")
            else:
                parts = stage.stage_template_id.split('.')
                print(f"DEBUG: Stage template parts: {parts}")
                if len(parts) == 2:
                    try:
                        current_stage_num = int(parts[1])
                        next_stage_num = current_stage_num + 1
                        next_stage_id = f"{parts[0]}.{next_stage_num}"
                        print(f"DEBUG: Auto next stage: {next_stage_id}")
                    except ValueError as e:
                        print(f"DEBUG: Error parsing stage number: {e}")
                        next_stage_id = None

            if next_stage_id:
                next_stage = db.query(DBStage).filter(
                    DBStage.case_id == stage.case_id,
                    DBStage.stage_template_id == next_stage_id
                ).first()

                if next_stage:
                    print(f"DEBUG: Next stage found - ID: {next_stage.id}, Status: {next_stage.status}")
                    next_stage.status = 'in_progress'
                    case.current_stage = next_stage_id
                    print(f"DEBUG: Activated next stage: {next_stage_id}")
                else:
                    print(f"DEBUG: Next stage not found for stage_template_id: {next_stage_id}")
                    case.status = 'completed'
                    case.current_stage = None
                    print(f"DEBUG: Case completed - no next stage")
            else:
                print("DEBUG: No next stage id determined")
                case.status = 'completed'
                case.current_stage = None
                print(f"DEBUG: Case completed - no next stage id")
        else:
            print(f"DEBUG: manager_closing - no automatic stage transition")

        db.commit()
        print(f"DEBUG: Stage {stage_id} completed successfully")
        print(f"DEBUG: Case status: {case.status}, Current stage: {case.current_stage}")

        return {
            "message": "Этап успешно завершен" if stage.closing_rule == 'executor_closing' else "Этап отправлен на проверку руководителю",
            "case_status": case.status,
            "next_stage": case.current_stage,
            "stage_status": stage.status  # ДОБАВЛЕНО: возвращаем новый статус этапа
        }

    except HTTPException:
        print(f"DEBUG: HTTPException in complete_stage")
        raise
    except Exception as e:
        print(f"DEBUG: Unexpected error in complete_stage: {str(e)}")
        import traceback
        traceback.print_exc()
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка при завершении этапа: {str(e)}")


@app.post("/stages/{stage_id}/attributes/batch/")
def create_attributes_batch(
        stage_id: int,
        attributes_data: List[AttributeCreate],
        db: Session = Depends(get_db),
        current_user: dict = Depends(get_current_active_user)
):
    """Пакетное создание/обновление атрибутов для этапа"""
    try:
        print(f"=== DEBUG: Starting create_attributes_batch ===")
        print(f"Stage ID: {stage_id}")
        print(f"Current user: {current_user['username']}")
        print(f"Attributes data count: {len(attributes_data)}")

        # Проверяем, что этап существует и пользователь имеет к нему доступ
        stage = db.query(DBStage).filter(DBStage.id == stage_id).first()
        if not stage:
            print(f"DEBUG: Stage {stage_id} not found")
            raise HTTPException(status_code=404, detail="Этап не найден")

        print(f"DEBUG: Stage found - Executor: {stage.executor}")

        # Проверяем, что текущий пользователь является исполнителем этапа
        if stage.executor != current_user['username']:
            print(f"DEBUG: Access denied - stage executor {stage.executor} != current user {current_user['username']}")
            raise HTTPException(status_code=403, detail="Нет доступа к этому этапу")

        results = []
        for i, attr_data in enumerate(attributes_data):
            print(f"DEBUG: Processing attribute {i + 1}: template_id={attr_data.attribute_template_id}")

            # Проверяем, существует ли уже атрибут для данного шаблона и этапа
            existing_attr = db.query(DBAttribute).filter(
                DBAttribute.stage_id == stage_id,
                DBAttribute.attribute_template_id == attr_data.attribute_template_id
            ).first()

            if existing_attr:
                print(f"DEBUG: Updating existing attribute ID: {existing_attr.id}")
                # Обновляем существующий атрибут
                existing_attr.user_text = attr_data.user_text
                existing_attr.user_file_path = attr_data.user_file_path
                results.append(existing_attr)
            else:
                print(f"DEBUG: Creating new attribute for template: {attr_data.attribute_template_id}")
                # Создаем новый атрибут
                new_attr = DBAttribute(
                    stage_id=stage_id,
                    attribute_template_id=attr_data.attribute_template_id,
                    user_text=attr_data.user_text,
                    user_file_path=attr_data.user_file_path
                )
                db.add(new_attr)
                results.append(new_attr)

        db.commit()
        print(f"DEBUG: Successfully saved {len(results)} attributes")

        # Обновляем объекты из БД, чтобы получить их ID (для новых атрибутов)
        for attr in results:
            db.refresh(attr)

        return results

    except HTTPException:
        print(f"DEBUG: HTTPException in create_attributes_batch")
        raise
    except Exception as e:
        print(f"DEBUG: Unexpected error in create_attributes_batch: {str(e)}")
        import traceback
        traceback.print_exc()
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка при сохранении атрибутов: {str(e)}")


@app.get("/manager/pending-stages/", response_model=List[StageWithCaseInfo])
def get_manager_pending_stages(
        db: Session = Depends(get_db),
        current_user: dict = Depends(require_admin_or_manager)
):
    """Получение этапов, ожидающих утверждения менеджера"""
    try:
        # Находим этапы со статусом waiting_approval и правилом manager_closing
        stages = db.query(DBStage).join(DBCase).filter(
            DBStage.status == 'waiting_approval',
            DBStage.closing_rule == 'manager_closing'
        ).all()

        result = []
        for stage in stages:
            stage_data = StageWithCaseInfo(
                **stage.__dict__,
                case_name=stage.case.name,
                case_id=stage.case.id
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
        current_user: dict = Depends(require_admin_or_manager)
):
    """Утверждение этапа менеджером"""
    try:
        stage = db.query(DBStage).filter(DBStage.id == stage_id).first()
        if not stage:
            raise HTTPException(status_code=404, detail="Этап не найден")

        if stage.status != 'waiting_approval':
            raise HTTPException(status_code=400, detail="Этап не ожидает утверждения")

        if stage.closing_rule != 'manager_closing':
            raise HTTPException(status_code=400, detail="Этот этап не требует утверждения менеджера")

        # Утверждаем этап
        stage.status = 'completed'
        stage.completed_by = current_user['username']
        stage.completed_at = datetime.now()
        stage.manager_comment = approval_data.comment

        # Логика перехода к следующему этапу
        case = db.query(DBCase).filter(DBCase.id == stage.case_id).first()
        if case and case.current_stage == stage.stage_template_id:
            next_stage_id = None

            if stage.next_stage_rule:
                next_stage_id = stage.next_stage_rule
            else:
                # Автоматический переход к следующему этапу
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
                    # Если следующего этапа нет - завершаем дело
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
    """Получение всех шаблонов атрибутов"""
    templates = db.query(DBAttributeTemplate).offset(skip).limit(limit).all()
    return templates


@app.post("/stages/{stage_id}/manager-rework/")
def manager_return_for_rework(
        stage_id: int,
        approval_data: StageApprovalRequest,  # Тот же самый класс
        db: Session = Depends(get_db),
        current_user: dict = Depends(require_admin_or_manager)
):
    """Возврат этапа на доработку менеджером"""
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

        # Возвращаем на доработку
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

