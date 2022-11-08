from typing import Optional, Union

from set_valued_decision_diagram.node import Node
from set_valued_decision_diagram.terminal_node import TerminalNode

# Special index for the terminal node
__TRUE_TERMINAL_INDEX = 0
__FALSE_TERMINAL_INDEX = 1
# List for all the created decision diagrams, no duplicates
__UNIQUE_LIST: list[Node] = [TerminalNode(True), TerminalNode(False)]
# Dictionary for quick searching __UNIQUE_LIST
__NODE_TO_UNIQUE_ID_MAP: dict[Node, int] = {}
# Map from (operation, *args (indices)) -> index of result in UNIQUE_LIST
__COMPUTE_CACHE: dict[tuple, int] = {}


def search_compute_cache(compute_cache_key: tuple) -> tuple[Optional[Union[int, bool]], bool]:
    value = __COMPUTE_CACHE.get(compute_cache_key)
    if value is None:
        return value, False
    else:
        return value, True


def node_to_id(node: Node):
    unique_id = __NODE_TO_UNIQUE_ID_MAP.get(node)
    if unique_id is None:
        unique_id = len(__UNIQUE_LIST)
        __UNIQUE_LIST.append(node)
        __NODE_TO_UNIQUE_ID_MAP[node] = unique_id
    return unique_id


def get_true_terminal() -> tuple[Node, int]:
    return __UNIQUE_LIST[__TRUE_TERMINAL_INDEX], __TRUE_TERMINAL_INDEX


def get_false_terminal() -> tuple[Node, int]:
    return __UNIQUE_LIST[__FALSE_TERMINAL_INDEX], __FALSE_TERMINAL_INDEX


def update_compute_cache(compute_cache_key, unique_id: int):
    __COMPUTE_CACHE[compute_cache_key] = unique_id


def id_to_node(node_id: int) -> Node:
    return __UNIQUE_LIST[node_id]
