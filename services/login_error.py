from exceptions import Exception


class LoginError(Exception):
    def json_dict(self):
        return {'login_error': {}}
