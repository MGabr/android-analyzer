from src.app import app
from src.definitions import COMMON_TEMPLATES_DIR
from flask import render_template
import jinja2

loader = jinja2.ChoiceLoader([
    app.jinja_loader,
    jinja2.FileSystemLoader([COMMON_TEMPLATES_DIR])])
app.jinja_loader = loader

env = app.jinja_env
