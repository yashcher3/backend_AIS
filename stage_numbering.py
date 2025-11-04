import re
from typing import List, Optional, Tuple


def parse_stage_number(stage: str) -> List[int]:
    return [int(x) for x in stage.split('.')]


def format_stage_number(parts: List[int]) -> str:
    return '.'.join(map(str, parts))


def get_next_stage_number(current_stage: str, condition_result: Optional[str] = None) -> str:

    if not current_stage:
        return "1"

    parts = parse_stage_number(current_stage)
    parts[0] += 1
    return format_stage_number(parts)


def get_child_stages(parent_stage: str, num_children: int) -> List[str]:

    parent_parts = parse_stage_number(parent_stage)

    main_number = parent_parts[0] + 1

    children = []
    for i in range(1, num_children + 1):
        if len(parent_parts) == 1:
            child_parts = [main_number, i]
        else:
            child_parts = [main_number] + parent_parts[1:] + [i]

        children.append(format_stage_number(child_parts))

    return children


def get_stage_hierarchy(stages: List[str]) -> dict:

    hierarchy = {}

    for stage in stages:
        parts = parse_stage_number(stage)

        if len(parts) == 1:
            # Корневой уровень
            hierarchy[stage] = {"children": []}
        else:
            parent_parts = parts[:-1]
            parent = format_stage_number(parent_parts)

            if parent not in hierarchy:
                hierarchy[parent] = {"children": []}

            hierarchy[parent]["children"].append(stage)

    return hierarchy


def validate_stage_transition(current_stage: str, next_stage: str) -> bool:

    current_parts = parse_stage_number(current_stage)
    next_parts = parse_stage_number(next_stage)


    if next_parts[0] != current_parts[0] + 1:
        return False

    if len(current_parts) > 1:
        if len(next_parts) < 2:
            return False
        if current_parts[1:] != next_parts[1:len(current_parts)]:
            return False

    return True


