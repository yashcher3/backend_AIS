# import os
# import subprocess
# import time
# import requests
# from minio import Minio
# from minio.error import S3Error
#
#
# def setup_minio():
#     """Установка и настройка MinIO"""
#     try:
#         # Проверяем, запущен ли уже MinIO
#         response = requests.get("http://localhost:9000/minio/health/live", timeout=5)
#         if response.status_code == 200:
#             print("MinIO уже запущен")
#             return True
#     except:
#         print("MinIO не запущен, запускаем...")
#
#     try:
#         # Запускаем MinIO в фоновом режиме
#         minio_process = subprocess.Popen([
#             "minio", "server",
#             "--address", ":9000",
#             "--console-address", ":9001",
#             "/tmp/minio-data"
#         ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#
#         # Ждем запуска
#         time.sleep(3)
#
#         # Проверяем запуск
#         for i in range(10):
#             try:
#                 response = requests.get("http://localhost:9000/minio/health/live", timeout=5)
#                 if response.status_code == 200:
#                     print("MinIO успешно запущен")
#
#                     # Создаем клиент MinIO
#                     client = Minio(
#                         "localhost:9000",
#                         access_key="minioadmin",
#                         secret_key="minioadmin",
#                         secure=False
#                     )
#
#                     # Создаем bucket если не существует
#                     bucket_name = "case-files"
#                     if not client.bucket_exists(bucket_name):
#                         client.make_bucket(bucket_name)
#                         print(f"Bucket '{bucket_name}' создан")
#                     else:
#                         print(f"Bucket '{bucket_name}' уже существует")
#
#                     return True
#             except:
#                 print(f"Попытка {i + 1}/10: Ожидаем запуск MinIO...")
#                 time.sleep(2)
#
#         print("Не удалось запустить MinIO")
#         return False
#
#     except Exception as e:
#         print(f"Ошибка при запуске MinIO: {e}")
#         return False
#
#
# def install_minio():
#     """Установка MinIO если не установлен"""
#     try:
#         # Проверяем, установлен ли MinIO
#         result = subprocess.run(["which", "minio"], capture_output=True, text=True)
#         if result.returncode == 0:
#             print("MinIO уже установлен")
#             return True
#
#         print("Устанавливаем MinIO...")
#
#         # Для Linux (Ubuntu/Debian)
#         if os.name == 'posix':
#             # Скачиваем MinIO
#             subprocess.run([
#                 "wget", "https://dl.min.io/server/minio/release/linux-amd64/minio",
#                 "-O", "/usr/local/bin/minio"
#             ], check=True)
#
#             # Даем права на выполнение
#             subprocess.run(["chmod", "+x", "/usr/local/bin/minio"], check=True)
#
#             print("MinIO успешно установлен")
#             return True
#
#     except Exception as e:
#         print(f"Ошибка установки MinIO: {e}")
#         return False
#
#
# if __name__ == "__main__":
#     print("=== Настройка MinIO ===")
#
#     # Устанавливаем MinIO если нужно
#     if install_minio():
#         # Запускаем MinIO
#         if setup_minio():
#             print("MinIO готов к использованию!")
#         else:
#             print("Не удалось запустить MinIO")
#     else:
#         print("Не удалось установить MinIO")


import os
import subprocess
import time
import requests
from minio import Minio
import urllib.request
import tempfile


def setup_minio():
    """Установка и настройка MinIO на NixOS"""
    try:
        # Проверяем, запущен ли уже MinIO
        response = requests.get("http://localhost:9000/minio/health/live", timeout=5)
        if response.status_code == 200:
            print("MinIO уже запущен")
            return True
    except:
        print("MinIO не запущен, запускаем...")

    try:
        # Способ 1: Пытаемся установить MinIO через nix-env
        print("Пытаемся установить MinIO через Nix...")
        result = subprocess.run([
            "nix-env", "-i", "minio"
        ], capture_output=True, text=True)

        if result.returncode != 0:
            # Способ 2: Пытаемся установить через nix-shell
            print("Пытаемся установить через nix-shell...")
            result = subprocess.run([
                "nix-shell", "-p", "minio", "--run", "which minio"
            ], capture_output=True, text=True)

            if result.returncode == 0:
                minio_path = result.stdout.strip()
                print(f"MinIO найден по пути: {minio_path}")
            else:
                raise Exception("Не удалось установить MinIO через Nix")
        else:
            # Находим путь к установленному MinIO
            result = subprocess.run(["which", "minio"], capture_output=True, text=True)
            minio_path = result.stdout.strip()

        # Запускаем MinIO
        print("Запускаем MinIO...")
        minio_process = subprocess.Popen([
            minio_path, "server",
            "--address", ":9000",
            "--console-address", ":9001",
            "/tmp/minio-data"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Ждем запуска
        time.sleep(3)

        # Проверяем запуск
        for i in range(10):
            try:
                response = requests.get("http://localhost:9000/minio/health/live", timeout=5)
                if response.status_code == 200:
                    print("MinIO успешно запущен")

                    # Создаем клиент MinIO
                    client = Minio(
                        "localhost:9000",
                        access_key="minioadmin",
                        secret_key="minioadmin",
                        secure=False
                    )

                    # Создаем bucket если не существует
                    bucket_name = "case-files"
                    if not client.bucket_exists(bucket_name):
                        client.make_bucket(bucket_name)
                        print(f"Bucket '{bucket_name}' создан")
                    else:
                        print(f"Bucket '{bucket_name}' уже существует")

                    return True
            except Exception as e:
                print(f"Попытка {i + 1}/10: Ожидаем запуск MinIO... ({e})")
                time.sleep(2)

        print("Не удалось запустить MinIO")
        return False

    except Exception as e:
        print(f"Ошибка при запуске MinIO: {e}")
        print("Пробуем альтернативный метод...")
        return setup_minio_alternative()


def setup_minio_alternative():
    """Альтернативный метод установки MinIO"""
    try:
        # Скачиваем бинарник MinIO напрямую
        print("Скачиваем MinIO бинарник...")
        minio_url = "https://dl.min.io/server/minio/release/linux-amd64/minio"

        # Создаем временную директорию в /tmp
        temp_dir = "/tmp/minio-bin"
        os.makedirs(temp_dir, exist_ok=True)
        minio_path = os.path.join(temp_dir, "minio")

        # Скачиваем с помощью urllib
        urllib.request.urlretrieve(minio_url, minio_path)

        # Даем права на выполнение
        os.chmod(minio_path, 0o755)

        # Запускаем MinIO
        print("Запускаем MinIO из временной директории...")
        minio_process = subprocess.Popen([
            minio_path, "server",
            "--address", ":9000",
            "--console-address", ":9001",
            "/tmp/minio-data"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Остальная логика такая же...
        time.sleep(3)

        for i in range(10):
            try:
                response = requests.get("http://localhost:9000/minio/health/live", timeout=5)
                if response.status_code == 200:
                    print("MinIO успешно запущен через альтернативный метод")

                    client = Minio(
                        "localhost:9000",
                        access_key="minioadmin",
                        secret_key="minioadmin",
                        secure=False
                    )

                    bucket_name = "case-files"
                    if not client.bucket_exists(bucket_name):
                        client.make_bucket(bucket_name)
                        print(f"Bucket '{bucket_name}' создан")

                    return True
            except:
                print(f"Альтернативный метод - попытка {i + 1}/10...")
                time.sleep(2)

        return False

    except Exception as e:
        print(f"Альтернативный метод также не сработал: {e}")
        return False


def install_minio_nixos():
    """Установка MinIO на NixOS"""
    try:
        # Проверяем, установлен ли уже MinIO
        result = subprocess.run(["which", "minio"], capture_output=True, text=True)
        if result.returncode == 0:
            print("MinIO уже установлен")
            return True

        print("Устанавливаем MinIO через Nix...")

        # Пробуем разные способы установки
        methods = [
            ["nix-env", "-i", "minio"],
            ["nix-shell", "-p", "minio", "--run", "echo 'minio installed'"]
        ]

        for method in methods:
            try:
                result = subprocess.run(method, capture_output=True, text=True, timeout=60)
                if result.returncode == 0:
                    print("MinIO успешно установлен через Nix")
                    return True
            except:
                continue

        print("Не удалось установить MinIO через Nix")
        return False

    except Exception as e:
        print(f"Ошибка установки MinIO: {e}")
        return False


if __name__ == "__main__":
    print("=== Настройка MinIO на NixOS ===")

    # Для NixOS используем специальную установку
    if install_minio_nixos():
        # Запускаем MinIO
        if setup_minio():
            print("MinIO готов к использованию на NixOS!")
        else:
            print("Не удалось запустить MinIO")
    else:
        print("Пробуем альтернативный метод без установки...")
        if setup_minio_alternative():
            print("MinIO запущен через альтернативный метод!")
        else:
            print("Не удалось запустить MinIO")