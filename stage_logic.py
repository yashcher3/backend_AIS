import re
from typing import Optional


def get_next_stage(current_stage: str, condition_result: Optional[str] = None) -> str:
    """
    Определяет следующий этап на основе текущего этапа и результата условия

    Args:
        current_stage: Текущий этап в формате "1.2.3"
        condition_result: Результат условия (если есть)

    Returns:
        Следующий этап в формате "1.2.4"
    """
    if not current_stage:
        return "1"

    # Разбиваем этап на компоненты
    parts = list(map(int, current_stage.split('.')))

    if condition_result:
        # Если есть условие, парсим его для определения следующего этапа
        # Формат условия: "value > 100 ? '2.1' : '2.2'"
        try:
            # Простая реализация - предполагаем, что condition_result уже содержит следующий этап
            if re.match(r'^\d+(\.\d+)*$', condition_result):
                return condition_result
        except:
            pass

    # Если нет условий, увеличиваем последний номер
    # Например: 4.1.2 -> 5.1.2
    if len(parts) == 1:
        return str(parts[0] + 1)
    else:
        # Увеличиваем первый номер, остальные сохраняем
        return f"{parts[0] + 1}.{'.'.join(map(str, parts[1:]))}"


def validate_stage_format(stage: str) -> bool:
    """Проверяет корректность формата номера этапа"""
    return bool(re.match(r'^\d+(\.\d+)*$', stage))