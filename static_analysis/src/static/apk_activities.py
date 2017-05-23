import logging

from androguard.core.analysis.analysis import VMAnalysis
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat

from src.definitions import INPUT_APK_DIR
from src.static.static_analysis import StaticAnalysisResult, StaticAnalysisResults


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class GetApkActivities:

    def __init__(self, apk_name):
        self.apk_name = apk_name
        self.apk = INPUT_APK_DIR + self.apk_name + ".apk"

        logger.debug("Analyzing " + self.apk)

        # analyze the dex file
        self.a = APK(self.apk)

        # get the vm analysis
        self.d = DalvikVMFormat(self.a.get_dex())
        self.dx = VMAnalysis(self.d)

    def get_all_activities(self):
        activity_names = self.a.get_activities()
        return [StaticAnalysisResult(self.apk_name, None, a, "activity", "SelectedActivities")
                       for a in activity_names]

    # def get_activities_by_str(self, str):
    #     for tv, candidate in self.dx.get_tainted_variables().get_strings():
    #         if str in candidate:
    #             # at this point we have the method in which the string is used
    #             # how to find the calling method, and then finally the activity?
    #             tv.show_paths(self.d)

