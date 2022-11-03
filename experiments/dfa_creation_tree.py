class CreationTree:
    def __init__(self, value: str = '', children: list = None):
        self.value = value
        self.children = children

    def serialize(self):
        if self.children is None:
            return self.value
        else:
            return {
                'operation': self.value,
                'children': [child.serialize() for child in self.children]
            }

