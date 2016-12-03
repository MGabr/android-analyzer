from apk_disassembly import disassemble_apk
from static_analysis import StaticAnalyzer
from dynamic_analysis import analyze_dynamically
import logging


def analyse(apk_name):
    logging.basicConfig(level=logging.DEBUG)
    disassembled_path = disassemble_apk(apk_name)
    static_analysis_results = StaticAnalyzer().analyze_statically(disassembled_path)
    analyze_dynamically(apk_name, static_analysis_results)


if __name__ == "__main__":
    analyse("acceptallcertificates-release")
