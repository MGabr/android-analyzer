from exceptions import Exception


class FormError(Exception):
    def __init__(self, field_errors):
        self.field_errors = field_errors

    def json_dict(self):
        field_errors = [field_error.json_dict() for field_error in self.field_errors]
        return {'form_error': {'field_errors': field_errors}}


class FieldRequiredError:
    def __init__(self, fieldname):
        self.fieldname = fieldname

    def json_dict(self):
        return {'fieldname': self.fieldname}

