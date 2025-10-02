def precision(tp: int, fp: int) -> float:
    return tp / (tp + fp) if (tp + fp) else 0.0
