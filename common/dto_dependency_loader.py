class DtoDependencyLoader:
    # session has to be set before load_if_none is called
    # session has to be closed later
    session = None

    @classmethod
    def load_if_none(cls, instance, instance_id, clazz):
        if instance is None:
            return cls.session.query(clazz).filter(clazz.id == instance_id).one()
        else:
            return instance


# create instance from dict if not already instance, needed for nested objects to be created from (json) dict
def asinstanceof(instance, clazz):
    if isinstance(instance, clazz):
        return instance
    else:
        return clazz(**instance)


# create instances from dict if not already instances, needed for nested objects to be created from (json) dict
def asinstancesof(instances, clazz):
    if all(isinstance(instance, clazz) for instance in instances):
        return instances
    else:
        return [clazz(**instance) for instance in instances]