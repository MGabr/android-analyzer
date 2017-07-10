import logging

from androguard.core.analysis.analysis import VMAnalysis
from androguard.core.analysis.ganalysis import GVMAnalysis
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat

from common.models.static_analysis import StaticAnalysisResult
from common.models.vuln_type import VulnType
from src.definitions import INPUT_APK_DIR
from src.static.smart_input import GetFieldType


logger = logging.getLogger(__name__)


class ApkAnalysis:

    def __init__(self, apk_name):
        self.apk_name = apk_name
        self.apk = INPUT_APK_DIR + self.apk_name + ".apk"

        # analyze the dex file
        self.a = APK(self.apk)

        # get the vm analysis
        self.d = DalvikVMFormat(self.a.get_dex())
        self.dx = VMAnalysis(self.d)
        self.gx = GVMAnalysis(self.dx, None)

        self.d.set_vmanalysis(self.dx)
        self.d.set_gvmanalysis(self.gx)

        # create the cross reference
        self.d.create_xref()
        self.d.create_dref()

    def get_all_activities_results(self):
        activity_names = self.a.get_activities()
        return [StaticAnalysisResult(self.apk_name, None, a, VulnType.selected_activities.value)
                for a in activity_names]

    def get_smart_input(self):
        return GetFieldType(self).analyze()
