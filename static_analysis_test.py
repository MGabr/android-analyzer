import unittest
import shutil

from apk_disassembly import disassemble_apk
from static_analysis import StaticAnalyzer


class TestStaticAnalysis(unittest.TestCase):

    vuln_tm_hn_apk_path = "input_apks/acceptallcertificates-release.apk"
    vuln_tm_hn_decoded_path = "decoded_apks/acceptallcertificates-release"

    vuln_wv_apk_path = "input_apks/acceptallcertificateswebview-release.apk"
    vuln_wv_decoded_path = "decoded_apks/acceptallcertificateswebview-release"

    @classmethod
    def setUpClass(cls):
        disassemble_apk(cls.vuln_tm_hn_apk_path)
        disassemble_apk(cls.vuln_wv_apk_path)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.vuln_tm_hn_decoded_path)
        shutil.rmtree(cls.vuln_wv_decoded_path)

    def test_vuln_trustmanager(self):
        results = StaticAnalyzer().analyze_statically(self.vuln_tm_hn_decoded_path)
        result = results[1]
        self.assertEqual(self.vuln_tm_hn_decoded_path, result.apk_folder)
        self.assertEqual("Lcom/example/markus/acceptallcertificatestestapp/InsecureTrustManager;-><init>()V",
                         result.vuln_entry)
        self.assertEqual("com.example.markus.acceptallcertificatestestapp.MainActivity", result.meth_nm)
        self.assertEqual("activity", result.tag)
        self.assertEqual("trustmanager", result.vuln_type)

    def test_vuln_hostnameverifier(self):
        results = StaticAnalyzer().analyze_statically(self.vuln_tm_hn_decoded_path)
        result = results[0]
        self.assertEqual(self.vuln_tm_hn_decoded_path, result.apk_folder)
        self.assertEqual("Lcom/example/markus/acceptallcertificatestestapp/InsecureHostnameVerifier;-><init>()V",
                         result.vuln_entry)
        self.assertEqual("com.example.markus.acceptallcertificatestestapp.MainActivity", result.meth_nm)
        self.assertEqual("activity", result.tag)
        self.assertEqual("hostnameverifier", result.vuln_type)

    def test_vuln_webviewclient(self):
        results = StaticAnalyzer().analyze_statically(self.vuln_wv_decoded_path)
        result = results[0]
        self.assertEqual(self.vuln_wv_decoded_path, result.apk_folder)
        self.assertEqual("Lcom/example/markus/acceptallcertificateswebviewtestapp/InsecureWebViewClient;-><init>()V",
                         result.vuln_entry)
        self.assertEqual("com.example.markus.acceptallcertificateswebviewtestapp.MainActivity", result.meth_nm)
        self.assertEqual("activity", result.tag)
        self.assertEqual("webviewclient", result.vuln_type)

    def test_multiple_entrypoints(self):
        # TODO: do multiple entry points work?
        return

    def test_vuln_library(self):
        # TODO: does static analysis detect vulnerable (non-system) libraries?
        return

    def test_vuln_subclass(self):
        # TODO: does static analysis work correctly with subclass relations?
        # (e.g. superclass has vulnerable implementation or subclass of subclass of webviewclient)
        return

if __name__ == '__main__':
    unittest.main()