# from sqlalchemy import Column, Integer, String, Text, ForeignKey
# from sqlalchemy.ext.declarative import declarative_base
# from sqlalchemy.orm import relationship
# from pydantic import BaseModel, field_validator
# from typing import List, Optional
#
# Base = declarative_base()
#
# # SQLAlchemy модели для БД
# class DBCase(Base):
#     __tablename__ = "cases"
#
#     id = Column(Integer, primary_key=True, index=True)
#     name = Column(String, nullable=False)
#     description = Column(Text)
#     stages_list = Column(Text)  # JSON список ID этапов
#
#     stages = relationship("DBStage", back_populates="case")
#
#
# class DBStage(Base):
#     __tablename__ = "stages"
#
#     id = Column(String, primary_key=True, index=True)  # формат: {case_id}.{stage_number}
#     case_id = Column(Integer, ForeignKey('cases.id'))
#     name_stage = Column(String, nullable=False)
#     text_doc = Column(Integer, default=0)
#     png_doc = Column(Integer, default=0)
#     text_fields = Column(Integer, default=3)
#     desc = Column(Text)
#     duration = Column(String)
#     condition = Column(Text, nullable=True)
#
#     case = relationship("DBCase", back_populates="stages")
#
#
# # Pydantic модели для API
# class StageBase(BaseModel):
#     id: str
#     name_stage: str
#     text_doc: int = 0
#     png_doc: int = 0
#     text_fields: int = 3
#     desc: str
#     duration: str
#     condition: Optional[str] = None
#     children: Optional[List[str]] = None  # Добавляем поле children
#
#     @field_validator('text_doc', 'png_doc', 'text_fields')
#     @classmethod
#     def validate_non_negative(cls, v):
#         if v < 0:
#             raise ValueError('Значение должно быть неотрицательным')
#         return v
#
#     @field_validator('name_stage', 'desc', 'duration')
#     @classmethod
#     def validate_not_empty(cls, v):
#         if not v or not v.strip():
#             raise ValueError('Поле не может быть пустым')
#         return v
#
#     class Config:
#         from_attributes = True
#
#
# class StageCreate(StageBase):
#     pass
#
#
# class StageResponse(StageBase):
#     case_id: int
#
#
# class CaseBase(BaseModel):
#     name: str
#     description: str
#
#
# class CaseCreate(CaseBase):
#     stages: List[StageBase]
#
#
# class CaseResponse(CaseBase):
#     id: int
#     stages_list: str
#
#
# class ExportData(BaseModel):
#     name: str
#     description: str
#     stages: List[StageBase]