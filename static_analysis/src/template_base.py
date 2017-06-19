import jinja2
from src.definitions import COMMON_TEMPLATES_DIR

env = jinja2.Environment(loader=jinja2.FileSystemLoader(COMMON_TEMPLATES_DIR))


def render_template(file_name, **context):
    return env.get_template(file_name).render(context)
