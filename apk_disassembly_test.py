import unittest
import shutil

from apk_disassembly import disassemble_apk


class TestStaticAnalysis(unittest.TestCase):

    def tearDown(self):
        shutil.rmtree("decoded_apks/acceptallcertificates-release-unsigned")

    def test_disassemble_apk(self):
        disassemble_apk("input_apks/acceptallcertificates-release-unsigned.apk")
