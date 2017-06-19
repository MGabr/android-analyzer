def get_of_user(id, current_user):
    scenarios = [s for s in current_user.scenarios if s.id == id]
    return scenarios[0] if scenarios else None


def get_all_enabled_of_user(current_user):
    return [s for s in current_user.scenarios if s.enabled]
