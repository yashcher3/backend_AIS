import re
from typing import Optional


def get_next_stage(current_stage: str, condition_result: Optional[str] = None) -> str:

    if not current_stage:
        return "1"

    parts = list(map(int, current_stage.split('.')))

    if condition_result:

        try:
            # Простая реализация - предполагаем, что condition_result уже содержит следующий этап
            if re.match(r'^\d+(\.\d+)*$', condition_result):
                return condition_result
        except:
            pass

    if len(parts) == 1:
        return str(parts[0] + 1)
    else:
        return f"{parts[0] + 1}.{'.'.join(map(str, parts[1:]))}"


def validate_stage_format(stage: str) -> bool:
    return bool(re.match(r'^\d+(\.\d+)*$', stage))
# /home/maxim/PycharmProjects/Backend_AIS/data/flowchart.db
