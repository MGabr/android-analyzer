class DictObject:
    def __init__(self, d):
        self.d = d

        if d:
            for k, v in d.items():
                setattr(self, k, DictObject.from_nested(v))

    @staticmethod
    def from_nested(val):
        if isinstance(val, dict):
            val = DictObject(val)
        elif isinstance(val, list):
            val = [DictObject.from_nested(v) for v in val]
        return val

    # to also allow dictionary access
    def __getitem__(self, item):
        return self.__dict__[item]

    def __setitem__(self, key, value):
        setattr(self, key, value)

    # to also allow dictionary get access
    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def __json__(self):
        # return old dict, so changes are not reflected
        return self.d
