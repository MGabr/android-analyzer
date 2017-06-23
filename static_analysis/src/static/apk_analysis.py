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

    def get_methods_with_https(self):
        tainted_variables_w_s = []
        for tainted_variable, s in self.dx.get_tainted_variables().get_strings():
            if "https://" in s:
                tainted_variables_w_s += [(tainted_variable, s)]

        meth_nms_w_s = []
        field_nms_w_s = []
        for tainted_variable, s in tainted_variables_w_s:
            paths = tainted_variable.get_paths()
            for path in paths:
                method_idx = path[1]
                method = self.d.get_method_by_idx(method_idx)

                method_name = method.get_name()
                class_name = method.get_class_name()

                if method_name == "<clinit>":
                    # this might lead to false positives, since we return all static String fields
                    fields = self.d.get_fields_class(class_name)
                    for field in fields:
                        if field.get_descriptor() == "Ljava/lang/String;" and "static" in field.get_access_flags_string():
                            # format string so that it fits the same format used in static_analysis
                            field_nm = "%s->%s:%s" % (class_name, field.get_name(), field.get_descriptor())
                            field_nms_w_s += [(field_nm, s)]
                            logger.info("Maybe found HTTPS URL in static field " + field_nm)
                else:
                    # format string so that it fits the same format used in static_analysis
                    meth_nm = "%s->%s%s" % (class_name, method_name, method.get_descriptor())
                    meth_nms_w_s += [(meth_nm, s)]
                    logger.info("Found HTTPS URL in method " + meth_nm)

        return meth_nms_w_s + field_nms_w_s

    def get_smart_input(self):
        return GetFieldType(self).analyze()
