from set_valued_decision_diagram.node import Node
# TODO: make sure that this module does not depend on internal_node.py


class TerminalNode(Node):
    def is_empty(self):
        return not self.value

    def __init__(self, value: bool):
        self.value = value

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

    def complement(self):
        return TerminalNode(not self.value)

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
        return f'<Terminal={self.value}>'

    def __contains__(self, item):
        return self.value

    def __hash__(self):
        return hash(self.value)
