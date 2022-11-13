from decision_diagram.node import Node


FALSE_TERMINAL_ID = 0
TRUE_TERMINAL_ID = 1


class TerminalNode(Node):
    def __init__(self, value: bool):
        self.value = value
        node_id = TRUE_TERMINAL_ID if value else FALSE_TERMINAL_ID
        super().__init__(node_id)

    def is_empty(self):
        return not self.value

    def is_all(self):
        return self.value

    def __and__(self, other: Node):
        if self.value:
            return other
        else:
            return self

    def __or__(self, other: Node):
        if self.value:
            return self
        else:
            return other

    def __sub__(self, other: Node):
        if self.value:
            return other.complement()
        else:
            return self

    def __eq__(self, other: Node):
        if isinstance(other, TerminalNode):
            return self.value == other.value
        else:
            return False

    def contained_in(self, other: Node):
        if self.value:
            return isinstance(other, TerminalNode) and other.value
        else:
            return True

    def __repr__(self):
        if self.value:
            return 'All'
        else:
            return 'Empty'

    def __contains__(self, item):
        return self.value

    def __hash__(self):
        return hash(self.value)

    def complement(self):
        return TerminalNode(not self.value)
