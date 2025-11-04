import boto3
from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError
import os
from fastapi import UploadFile, HTTPException
import uuid
from datetime import datetime
import logging


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Настройки S3 с fallback значениями
S3_CONFIG = {
    'endpoint_url': os.getenv('S3_ENDPOINT', 'http://localhost:9000'),
    'aws_access_key_id': os.getenv('S3_ACCESS_KEY', 'minioadmin'),
    'aws_secret_access_key': os.getenv('S3_SECRET_KEY', 'minioadmin'),
    'region_name': os.getenv('S3_REGION', 'us-east-1'),
    'config': boto3.session.Config(signature_version='s3v4')
}

S3_BUCKET = os.getenv('S3_BUCKET', 'case-files')


class S3Storage:
    def __init__(self):
        self.s3_client = None
        self.bucket = S3_BUCKET
        self.available = False
        self._initialize()

    def _initialize(self):

        try:
            logger.info("Инициализация S3 клиента...")
            self.s3_client = boto3.client('s3', **S3_CONFIG)
            self.s3_client.list_buckets()
            logger.info("S3 клиент успешно инициализирован")

            # Создаем bucket если не существует
            self._ensure_bucket_exists()
            self.available = True

        except (EndpointConnectionError, ConnectionRefusedError) as e:
            logger.warning(f"Не удалось подключиться к MinIO: {e}")
            logger.info("Используется локальное файловое хранилище")
            self.available = False
            self.s3_client = None

        except NoCredentialsError as e:
            logger.error(f"Ошибка аутентификации MinIO: {e}")
            self.available = False
            self.s3_client = None

        except Exception as e:
            logger.error(f"Неизвестная ошибка при инициализации S3: {e}")
            self.available = False
            self.s3_client = None

    def _ensure_bucket_exists(self):
        """Создает bucket если он не существует"""
        if not self.available:
            return

        try:
            self.s3_client.head_bucket(Bucket=self.bucket)
            logger.info(f"Bucket '{self.bucket}' существует")
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == '404':
                # Bucket не существует, создаем
                try:
                    self.s3_client.create_bucket(Bucket=self.bucket)
                    logger.info(f"Bucket '{self.bucket}' создан")
                except Exception as create_error:
                    logger.error(f"Ошибка создания bucket: {create_error}")
                    self.available = False
            else:
                logger.error(f"Ошибка доступа к bucket: {e}")
                self.available = False

    def upload_file(self, file: UploadFile, case_id: int, stage_id: int) -> str:
        """Загружает файл в S3 или локальное хранилище"""
        try:
            if self.available and self.s3_client:
                # Загружаем в S3
                return self._upload_to_s3(file, case_id, stage_id)
            else:
                # Используем локальное хранилище
                return self._upload_local(file, case_id, stage_id)

        except Exception as e:
            logger.error(f"Ошибка загрузки файла: {e}")
            # Fallback на локальное хранилище
            return self._upload_local(file, case_id, stage_id)

    def _upload_to_s3(self, file: UploadFile, case_id: int, stage_id: int) -> str:
        """Загружает файл в S3"""
        try:
            file_extension = os.path.splitext(file.filename)[1] if file.filename else ''
            unique_filename = f"{uuid.uuid4()}{file_extension}"
            s3_path = f"cases/{case_id}/{stage_id}/{unique_filename}"

            self.s3_client.upload_fileobj(
                file.file,
                self.bucket,
                s3_path,
                ExtraArgs={'ContentType': file.content_type or 'application/octet-stream'}
            )

            logger.info(f"Файл загружен в S3: {s3_path}")
            return s3_path

        except Exception as e:
            logger.error(f"Ошибка загрузки в S3: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Ошибка загрузки файла в S3: {str(e)}"
            )

    def _upload_local(self, file: UploadFile, case_id: int, stage_id: int) -> str:
        """Загружает файл в локальное хранилище"""
        try:
            # Создаем директории если не существуют
            upload_dir = f"uploads/cases/{case_id}/{stage_id}"
            os.makedirs(upload_dir, exist_ok=True)

            file_extension = os.path.splitext(file.filename)[1] if file.filename else ''
            unique_filename = f"{uuid.uuid4()}{file_extension}"
            file_path = os.path.join(upload_dir, unique_filename)

            # Сохраняем файл
            with open(file_path, 'wb') as f:
                content = file.file.read()
                f.write(content)

            logger.info(f"Файл сохранен локально: {file_path}")
            return file_path

        except Exception as e:
            logger.error(f"Ошибка локального сохранения: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Ошибка сохранения файла: {str(e)}"
            )

    def get_file_url(self, file_path: str) -> str:
        """Генерирует URL для доступа к файлу"""
        try:
            if self.available and self.s3_client and file_path.startswith('cases/'):
                # Генерируем presigned URL для S3
                url = self.s3_client.generate_presigned_url(
                    'get_object',
                    Params={'Bucket': self.bucket, 'Key': file_path},
                    ExpiresIn=3600
                )
                return url
            else:
                # Локальный файл
                return f"/files/{file_path}"

        except Exception as e:
            logger.error(f"Ошибка генерации URL: {e}")
            return f"/files/{file_path}"

    def delete_file(self, file_path: str) -> bool:
        """Удаляет файл"""
        try:
            if self.available and self.s3_client and file_path.startswith('cases/'):
                # Удаляем из S3
                self.s3_client.delete_object(Bucket=self.bucket, Key=file_path)
                return True
            else:

                if os.path.exists(file_path):
                    os.remove(file_path)
                    return True
                return False

        except Exception as e:
            logger.error(f"Ошибка удаления файла: {e}")
            return False


s3_storage = None


def get_s3_storage():
    """Получает экземпляр S3Storage с отложенной инициализацией"""
    global s3_storage
    if s3_storage is None:
        s3_storage = S3Storage()
    return s3_storage