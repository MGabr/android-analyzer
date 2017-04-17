from exceptions import Exception


# An entity of 'model' with the unique 'field' already exists
class FieldExistsError(Exception):
    def __init__(self, model, field):
        self.model = model
        self.field = field

    def json_dict(self):
        return {'field_exists_error': {'model': self.model, 'field': self.field}}


class LoginError(Exception):
    def json_dict(self):
        return {'login_error': {}}


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


def check_form(form, required_fields):
    field_errors = list()
    for required_field in required_fields:
        # check if key exists and not empty string
        if required_field not in form or not form[required_field]:
            field_errors += [FieldRequiredError(required_field)]
    if field_errors:
        raise FormError(field_errors)


class EntityNotExistsError(Exception):
    def __init__(self, model, id):
        self.model = model
        self.id = id

    def json_dict(self):
        return  {'entity_not_exists_error': {'model': self.model, 'id': self.id}}
