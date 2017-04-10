from exceptions import Exception


# An entity of 'model' with the unique 'field' already exists
class ExistsError(Exception):
    def __init__(self, model, field):
        self.model = model
        self.field = field

    def json_dict(self):
        return {'exists_error': {'model': self.model, 'field': self.field}}
