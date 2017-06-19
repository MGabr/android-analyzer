from common.dto_dependency_loader import asinstancesof


class StaticAnalysisResults:
    def __init__(self, apk_filename, package, min_sdk_version, target_sdk_version, result_list):
        self.apk_filename = apk_filename
        self.package = package
        self.min_sdk_version = min_sdk_version
        self.target_sdk_version = target_sdk_version
        self.result_list = asinstancesof(result_list, StaticAnalysisResult)

    def __json__(self):
        return {
            'apk_filename': self.apk_filename,
            'package': self.package,
            'min_sdk_version': self.min_sdk_version,
            'target_sdk_version': self.target_sdk_version,
            'result_list': self.result_list}


class StaticAnalysisResult:
    def __init__(self, apk_folder, vuln_entry, activity_name, tag, vuln_type):
        self.apk_folder = apk_folder
        self.vuln_entry = vuln_entry
        self.activity_name = activity_name
        self.tag = tag
        self.vuln_type = vuln_type

    def __json__(self):
        return {
            'apk_folder': self.apk_folder,
            'vuln_entry': self.vuln_entry,
            'activity_name': self.activity_name,
            'tag': self.tag,
            'vuln_type': {
                'value': self.vuln_type
            }}

    def __key(self):
        return (self.apk_folder, self.vuln_entry, self.activity_name, self.tag, self.vuln_type)

    def __eq__(self, other):
        return self.__key() == other.__key()

    def __hash__(self):
        return hash(self.__key())
