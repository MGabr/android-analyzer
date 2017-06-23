import logging

from androguard.core.analysis.analysis import VMAnalysis
from androguard.core.analysis.ganalysis import GVMAnalysis
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat

from common.models.vuln_type import VulnType
from src.definitions import INPUT_APK_DIR
from src.static.smart_input import GetFieldType
from src.static.static_analysis import StaticAnalysisResult


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
        return [StaticAnalysisResult(self.apk_name, None, a, "activity", VulnType.selected_activities.value)
                       for a in activity_names]

    def get_methods_with_http(self):
        tainted_variables_w_s = []
        for tainted_variable, s in self.dx.get_tainted_variables().get_strings():
            if "https://" in s or "http://" in s:
                tainted_variables_w_s += [(tainted_variable, s)]

        clinit_of_class = dict()
        meth_nms_w_s = []
        for tainted_variable, s in tainted_variables_w_s:
            paths = tainted_variable.get_paths()
            for path in paths:
                access, idx = path[0]
                method_idx = path[1]
                method = self.d.get_method_by_idx(method_idx)

                method_name = method.get_name()
                class_name = method.get_class_name()

                if method_name == "<clinit>":
                    clinit_of_class[class_name] = (tainted_variable, s, idx)
                else:
                    # format string so that it fits the same format used in static_analysis
                    meth_nm = "%s->%s%s" % (class_name, method_name, method.get_descriptor())
                    meth_nms_w_s += [(meth_nm, s)]
                    logger.info("Found HTTP/S URL in method " + meth_nm)

        field_nms_w_s = []
        for tainted_variable, f in self.dx.get_tainted_fields():
            class_name = f.split(";")[0] + ";"
            if class_name in clinit_of_class:
                s_tainted_variable, s, s_idx = clinit_of_class[class_name]

                paths = tainted_variable.get_paths()
                for path in paths:

                    method_idx = path[1]
                    method = self.d.get_method_by_idx(method_idx)
                    method_name = method.get_name()
                    if method_name == "<clinit>":
                        access, idx = path[0]

                        # if the field is set right after the string is created (const-string/sget-object, sput-object)
                        # this does not check that both instructions refer to the same var (e.g. v0)
                        # therefore there might be some false positives / negatives
                        # this is however better than just using ALL static fields of a clinit with a HTTP/s string
                        if idx == s_idx + 4:
                            field_name = f.split(";")[2]
                            descriptor = f.split(";")[1] + ";"
                            # format string so that it fits the same format used in static_analysis
                            field_nm = "%s->%s:%s" % (class_name, field_name, descriptor)
                            field_nms_w_s += [(field_nm, s)]
                            logger.info("Found HTTP/S URL in static field " + field_nm)

        return meth_nms_w_s + field_nms_w_s

    def get_smart_input(self):
        return GetFieldType(self).analyze()
