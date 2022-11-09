from typing import Optional, Union

from set_valued_decision_diagram.node import Node
from set_valued_decision_diagram.terminal_node import TerminalNode, FALSE_TERMINAL_ID, TRUE_TERMINAL_ID

# Special index for the terminal node
# List for all the created decision diagrams, no duplicates
__UNIQUE_LIST: list[Node] = [TerminalNode(False), TerminalNode(True)]
# Dictionary for quick searching __UNIQUE_LIST
__NODE_TO_UNIQUE_ID_MAP: dict[Node, int] = {}
# Map from (operation, *args (indices)) -> index of result in UNIQUE_LIST
__COMPUTE_CACHE: dict[tuple, Union[int, bool]] = {}


def search_compute_cache(compute_cache_key: tuple) -> tuple[Optional[Union[int, bool]], bool]:
    value = __COMPUTE_CACHE.get(compute_cache_key)
    if value is None:
        return value, False
    else:
        return value, True


def allocate_new_node_id(node: Node):
    node_id = __NODE_TO_UNIQUE_ID_MAP.get(node)
    if node_id is None:
        node_id = len(__UNIQUE_LIST)
        __UNIQUE_LIST.append(node)
        __NODE_TO_UNIQUE_ID_MAP[node] = node_id
    return node_id


def get_true_terminal() -> Node:
    return __UNIQUE_LIST[TRUE_TERMINAL_ID]


def get_false_terminal() -> Node:
    return __UNIQUE_LIST[FALSE_TERMINAL_ID]


def update_compute_cache(compute_cache_key, result: Union[int, bool]):
    __COMPUTE_CACHE[compute_cache_key] = result


def id_to_node(node_id: int) -> Node:
    return __UNIQUE_LIST[node_id]
