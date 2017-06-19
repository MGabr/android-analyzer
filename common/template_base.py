from common.services.template_functions import all_template_functions_dict

# during docker build common is copied into each subproject

# specify the render_template method
# for flask this will the imported render_template instead of a standalone jinja2 render_template function
from src.template_base import render_template

# jinjaenv used, required to add functions used in templates to globals
from src.template_base import env

env.globals.update(all_template_functions_dict)
