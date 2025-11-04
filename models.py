from sqlalchemy import Column, Integer, String, Text, ForeignKey, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from pydantic import BaseModel, field_validator
from typing import List, Optional
from datetime import datetime

Base = declarative_base()

class DBCaseTemplate(Base):
    __tablename__ = "case_templates"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(Text)
    stages_list = Column(Text)

    stages = relationship("DBStageTemplate", back_populates="case_template")


class DBStageTemplate(Base):
    __tablename__ = "stage_templates"

    id = Column(String, primary_key=True, index=True)
    case_template_id = Column(Integer, ForeignKey('case_templates.id'))
    name_stage = Column(String, nullable=False)
    file_fields = Column(Integer, default=0)
    text_fields = Column(Integer, default=0)
    desc = Column(Text)
    duration = Column(String)
    condition = Column(Text, nullable=True)

    case_template = relationship("DBCaseTemplate", back_populates="stages")
    attribute_templates = relationship("DBAttributeTemplate", back_populates="stage_template")


class DBAttributeTemplate(Base):
    __tablename__ = "attribute_templates"

    id = Column(Integer, primary_key=True, index=True)
    stage_template_id = Column(String, ForeignKey('stage_templates.id'))
    field_type = Column(String)
    field_index = Column(Integer)
    label = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

    stage_template = relationship("DBStageTemplate", back_populates="attribute_templates")


class DBCase(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    case_template_id = Column(Integer, ForeignKey('case_templates.id'))
    current_stage = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="active")

    # Связи
    case_template = relationship("DBCaseTemplate")
    stages = relationship("DBStage", back_populates="case")


class DBStage(Base):
    __tablename__ = "stages"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey('cases.id'))
    stage_template_id = Column(String, ForeignKey('stage_templates.id'))
    executor = Column(String)  # Логин исполнителя
    deadline = Column(DateTime)
    closing_rule = Column(String)
    next_stage_rule = Column(Text)
    status = Column(String, default="pending")
    completed_at = Column(DateTime, nullable=True)
    completed_by = Column(String, nullable=True)
    manager_comment = Column(Text, nullable=True)

    # Связи
    case = relationship("DBCase", back_populates="stages")
    stage_template = relationship("DBStageTemplate")
    attributes = relationship("DBAttribute", back_populates="stage")



class DBAttribute(Base):
    __tablename__ = "attributes"

    id = Column(Integer, primary_key=True, index=True)
    stage_id = Column(Integer, ForeignKey('stages.id'))
    attribute_template_id = Column(Integer, ForeignKey('attribute_templates.id'))
    user_text = Column(Text, nullable=True)
    user_file_path = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Связи
    stage = relationship("DBStage", back_populates="attributes")
    attribute_template = relationship("DBAttributeTemplate")

class DBExecutor(Base):
    __tablename__ = "executors"

    id = Column(Integer, primary_key=True, index=True)
    login = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=False)
    expert_area = Column(String)
    created_by = Column(String)

class AttributeTemplateBase(BaseModel):
    field_type: str
    field_index: int
    label: str


class AttributeTemplateCreate(AttributeTemplateBase):
    stage_template_id: str


class AttributeTemplateResponse(AttributeTemplateBase):
    id: int
    stage_template_id: str


class StageTemplateBase(BaseModel):
    id: str
    name_stage: str
    file_fields: int = 0
    text_fields: int = 0
    desc: str
    duration: str
    condition: Optional[str] = None
    children: Optional[List[str]] = None

    @field_validator('file_fields', 'text_fields')
    @classmethod
    def validate_non_negative(cls, v):
        if v < 0:
            raise ValueError('Значение должно быть неотрицательным')
        return v

    @field_validator('name_stage', 'desc', 'duration')
    @classmethod
    def validate_not_empty(cls, v):
        if not v or not v.strip():
            raise ValueError('Поле не может быть пустым')
        return v

    class Config:
        from_attributes = True


class StageTemplateWithTemplates(StageTemplateBase):
    attribute_templates: List[AttributeTemplateResponse] = []


class StageTemplateCreate(StageTemplateBase):
    pass


class StageTemplateResponse(StageTemplateBase):
    case_template_id: int


class CaseTemplateBase(BaseModel):  # БЫЛО: CaseBase
    name: str
    description: str

class CaseTemplateCreate(CaseTemplateBase):
    stages: List[StageTemplateBase]


class CaseTemplateResponse(CaseTemplateBase):
    id: int
    stages_list: str


class ExportData(BaseModel):
    name: str
    description: str
    stages: List[StageTemplateWithTemplates]

class ExecutorBase(BaseModel):
    login: str
    full_name: str
    expert_area: Optional[str] = None

class ExecutorCreate(ExecutorBase):
    password: str

class ExecutorResponse(ExecutorBase):
    id: int
    created_by: str

    class Config:
        from_attributes = True

class CaseSimple(BaseModel):
    id: int
    name: str
    status: str

    class Config:
        from_attributes = True

class AttributeBase(BaseModel):
    attribute_template_id: int
    user_text: Optional[str] = None
    user_file_path: Optional[str] = None

class AttributeCreate(AttributeBase):
    pass

class AttributeResponse(AttributeBase):
    id: int
    stage_id: int
    created_at: datetime
    updated_at: datetime

class StageBase(BaseModel):
    stage_template_id: str
    executor: str  # Обязательное поле
    deadline: datetime  # Обязательное поле
    closing_rule: str  # 'executor_closing' или 'manager_closing'
    next_stage_rule: str

class StageCreate(StageBase):
    pass

class CaseSimple(BaseModel):
    id: int
    name: str
    status: str

    class Config:
        from_attributes = True

class StageResponse(StageBase):
    id: int
    case_id: int
    status: str
    completed_at: Optional[datetime] = None
    completed_by: Optional[str] = None
    manager_comment: Optional[str] = None  # Убедитесь, что это поле есть
    attributes: List[AttributeResponse] = []
    case: Optional[CaseSimple] = None

    class Config:
        from_attributes = True

class StageApprovalRequest(BaseModel):
    approved: bool
    comment: Optional[str] = None

class StageWithCaseInfo(StageResponse):
    case_name: Optional[str] = None
    # case_id: Optional[int] = None

    class Config:
        from_attributes = True


class CaseBase(BaseModel):
    name: str
    case_template_id: int

class CaseCreate(CaseBase):
    stages: List[StageCreate] = []

class CaseResponse(CaseBase):
    id: int
    current_stage: Optional[str] = None
    status: str
    created_at: datetime
    stages: List[StageResponse] = []

    class Config:
        from_attributes = True

class CaseUpdate(BaseModel):
    name: Optional[str] = None
    current_stage: Optional[str] = None
    status: Optional[str] = None

class StageUpdate(BaseModel):
    executor: Optional[str] = None
    deadline: Optional[datetime] = None
    status: Optional[str] = None
    completed_by: Optional[str] = None

class AttributeUpdate(BaseModel):
    user_text: Optional[str] = None
    user_file_path: Optional[str] = None

class CaseFilter(BaseModel):
    name: Optional[str] = None
    case_template_id: Optional[int] = None
    status: Optional[str] = None
    executor: Optional[str] = None

class StageFilter(BaseModel):
    case_id: Optional[int] = None
    status: Optional[str] = None
    executor: Optional[str] = None

class FileUploadResponse(BaseModel):
    filename: str
    file_url: str
    file_path: str

class PaginatedCaseResponse(BaseModel):
    cases: List[CaseResponse]
    total_count: int
    page: int
    page_size: int
    total_pages: int

    class Config:
        from_attributes = True

DBCaseTemplate.case_instances = relationship("DBCase", back_populates="case_template")


