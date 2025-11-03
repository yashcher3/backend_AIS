import re
from typing import List, Optional, Tuple


def parse_stage_number(stage: str) -> List[int]:
    """Парсит номер этапа в список чисел"""
    return [int(x) for x in stage.split('.')]


def format_stage_number(parts: List[int]) -> str:
    """Форматирует список чисел в строку номера этапа"""
    return '.'.join(map(str, parts))


def get_next_stage_number(current_stage: str, condition_result: Optional[str] = None) -> str:
    """
    Определяет следующий номер этапа на основе текущего этапа.

    Логика:
    - Первое число - основной номер этапа (увеличивается на 1)
    - Остальные числа - глубина вложенности и номер в ветвлении
    - Если есть condition_result, используется для определения ветвления

    Примеры:
    - "1" -> "2"
    - "2.1" -> "3.1"
    - "2.2" -> "3.2"
    - "3.2.1" -> "4.2.1"
    - "3.2.2" -> "4.2.2"
    - "3.2.3" -> "4.2.3"
    """
    if not current_stage:
        return "1"

    parts = parse_stage_number(current_stage)

    # Увеличиваем основной номер этапа (первое число)
    parts[0] += 1

    # Сохраняем остальные числа (глубину вложенности и ветвление)
    return format_stage_number(parts)


def get_child_stages(parent_stage: str, num_children: int) -> List[str]:
    """
    Генерирует номера для дочерних этапов.

    Примеры:
    - get_child_stages("2", 2) -> ["3.1", "3.2"]
    - get_child_stages("3.2", 3) -> ["4.2.1", "4.2.2", "4.2.3"]
    """
    parent_parts = parse_stage_number(parent_stage)

    # Основной номер следующего этапа
    main_number = parent_parts[0] + 1

    children = []
    for i in range(1, num_children + 1):
        if len(parent_parts) == 1:
            # Дети первого уровня: 3.1, 3.2 и т.д.
            child_parts = [main_number, i]
        else:
            # Дети более глубоких уровней: 4.2.1, 4.2.2 и т.д.
            child_parts = [main_number] + parent_parts[1:] + [i]

        children.append(format_stage_number(child_parts))

    return children


def get_stage_hierarchy(stages: List[str]) -> dict:
    """
    Строит иерархию этапов для визуализации.

    Возвращает словарь вида:
    {
        "1": {"children": ["2.1", "2.2"]},
        "2.1": {"children": ["3.1.1", "3.1.2"]},
        "2.2": {"children": ["3.2.1", "3.2.2", "3.2.3"]},
    }
    """
    hierarchy = {}

    for stage in stages:
        parts = parse_stage_number(stage)

        if len(parts) == 1:
            # Корневой уровень
            hierarchy[stage] = {"children": []}
        else:
            # Находим родителя
            parent_parts = parts[:-1]
            parent = format_stage_number(parent_parts)

            if parent not in hierarchy:
                hierarchy[parent] = {"children": []}

            hierarchy[parent]["children"].append(stage)

    return hierarchy


def validate_stage_transition(current_stage: str, next_stage: str) -> bool:
    """
    Проверяет корректность перехода между этапами.

    Правила:
    - Основной номер должен увеличиться на 1
    - Путь вложенности (все кроме первого числа) должен сохраниться
    """
    current_parts = parse_stage_number(current_stage)
    next_parts = parse_stage_number(next_stage)

    # Проверяем увеличение основного номера
    if next_parts[0] != current_parts[0] + 1:
        return False

    # Проверяем сохранение пути вложенности
    if len(current_parts) > 1:
        if len(next_parts) < 2:
            return False
        if current_parts[1:] != next_parts[1:len(current_parts)]:
            return False

    return True


# Тестовые примеры
if __name__ == "__main__":
    # Тестирование логики
    test_cases = [
        ("1", "2"),
        ("2.1", "3.1"),
        ("2.2", "3.2"),
        ("3.2.1", "4.2.1"),
        ("3.2.2", "4.2.2"),
        ("3.2.3", "4.2.3")
    ]

    for current, expected in test_cases:
        result = get_next_stage_number(current)
        print(f"{current} -> {result} (expected: {expected}) - {'OK' if result == expected else 'FAIL'}")

    # Тестирование генерации детей
    print("\nChild generation:")
    print(f"Children of '2': {get_child_stages('2', 2)}")
    print(f"Children of '3.2': {get_child_stages('3.2', 3)}")