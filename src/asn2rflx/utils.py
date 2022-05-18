from typing import Any


def pub_vars(obj: Any) -> dict[str, Any]:
    return {v: k for v, k in vars(obj).items() if not v.startswith("_")}
