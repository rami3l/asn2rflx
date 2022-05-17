from typing import Any, Dict


def pub_vars(obj: Any) -> Dict[str, Any]:
    return {v: k for v, k in vars(obj).items() if not v.startswith("_")}
