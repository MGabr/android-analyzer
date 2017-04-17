import logging

from dynamic.dynamic_analysis import analyze_dynamically
from src.analysis.logs.log_analysis import analyse_logs
from src.analysis.static.apk_disassembly import disassemble_apk
from static.smart_input import generate_smart_input
from static.static_analysis import StaticAnalyzer


def analyse(apk_name):
    logging.basicConfig(level=logging.DEBUG)
    disassembled_path = disassemble_apk(apk_name)
    static_analysis_results = StaticAnalyzer().analyze_statically(disassembled_path)
    smart_input_results = generate_smart_input(apk_name)
    dynamic_analysis_results = analyze_dynamically(apk_name, static_analysis_results, smart_input_results)
    return analyse_logs(dynamic_analysis_results)

