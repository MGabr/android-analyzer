from sqlalchemy import Column, Integer, String, ForeignKey, Boolean
from sqlalchemy.orm import relationship

from common.db_base import Base
from common.dto_dependency_loader import asinstancesof


class StaticAnalysisResults(Base):
    __tablename__ = 'staticanalysisresults'
    apk_filename = Column(String(2048), primary_key=True)
    package = Column(String(2048))
    min_sdk_version = Column(String(64))
    target_sdk_version = Column(String(64))
    result_list = relationship('StaticAnalysisResult')

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


class StaticAnalysisResult(Base):
    __tablename__ = 'staticanalysisresult'
    id = Column(Integer, primary_key=True)
    apk_folder = Column(String(2048))
    vuln_entry = Column(String(2048))
    activity_name = Column(String(2048))
    vuln_type = Column(String(64))
    results_id = Column(String(2048), ForeignKey('staticanalysisresults.apk_filename'))
    exported = Column(Boolean)

    def __init__(self, apk_folder, vuln_entry, activity_name, vuln_type, exported):
        self.apk_folder = apk_folder
        self.vuln_entry = vuln_entry
        self.activity_name = activity_name
        self.vuln_type = vuln_type
        self.exported = exported

    def __json__(self):
        return {
            'apk_folder': self.apk_folder,
            'vuln_entry': self.vuln_entry,
            'activity_name': self.activity_name,
            'vuln_type': {
                'value': self.vuln_type
            },
            'exported': self.exported
        }

    def __key(self):
        return (self.apk_folder, self.activity_name, self.vuln_type)

    def __eq__(self, other):
        return self.__key() == other.__key()

    def __hash__(self):
        return hash(self.__key())
