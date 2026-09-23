"""脱敏策略定义（A 保守 / B 激进）"""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum


class Profile(Enum):
    """A 保守：保留性别/年龄/身高体重/日期 | B 激进：全部清除"""
    Conservative = "a"
    Aggressive = "b"

    @classmethod
    def from_str(cls, s: str) -> "Profile":
        m = s.strip().lower()
        if m in ("a", "conservative", "保守"):
            return cls.Conservative
        if m in ("b", "aggressive", "激进"):
            return cls.Aggressive
        raise ValueError(f"未知策略 '{s}'，可选: a / b")

    @property
    def label(self) -> str:
        return {"a": "A 保守", "b": "B 激进"}[self.value]

    @property
    def method_text(self) -> str:
        if self == Profile.Conservative:
            return "Hermes Basic Profile A: ids cleared, clinical kept, UID remap"
        return "Hermes Basic Profile B: all identifiers cleared, UID remap"


@dataclass
class Policy:
    profile: Profile
    rename_files: bool = True
    jobs: int = 0  # 0 = 自动

    # ---- 两档都清的标签 ----

    def __post_init__(self):
        if not hasattr(self, '_base_clear_initialized'):
            self._base_clear_initialized = True
            self._base_clear = [
                # 患者标识
                "PatientName", "PatientID", "PatientBirthDate",
                "OtherPatientIDs", "OtherPatientNames", "PatientAddress",
                "PatientTelephoneNumbers", "PatientBirthName", "PatientMotherBirthName",
                # 检查/机构标识
                "AccessionNumber", "StudyID", "InstitutionName", "InstitutionAddress",
                "InstitutionalDepartmentName", "InstitutionCodeSequence",
                "StationName", "DeviceSerialNumber", "StudyDescription",
                # 人员姓名
                "ReferringPhysicianName", "PerformingPhysicianName", "OperatorsName",
                "PhysiciansOfRecord", "NameOfPhysiciansReadingStudy", "RequestingPhysician",
                "ReferringPhysicianAddress", "ReferringPhysicianTelephoneNumbers",
                # 流程标识
                "PerformedProcedureStepID", "PerformedProcedureStepDescription",
                "PerformedStationName", "ScheduledProcedureStepID",
                "ScheduledPerformingPhysicianName", "ScheduledStationName",
                "ScheduledProcedureStepDescription", "ScheduledProcedureStepLocation",
                "RequestedProcedureID", "RequestedProcedureDescription",
                "CommentsOnThePerformedProcedureStep",
                "PlacerOrderNumberImagingServiceRequest",
                "FillerOrderNumberImagingServiceRequest",
                "AdmissionID", "CurrentPatientLocation", "RequestingService",
                "OrderCallbackPhoneNumber", "PersonAddress", "PersonTelephoneNumbers",
            ]

    def clear_keywords(self) -> set[str]:
        ks = set(self._base_clear)
        if self.profile == Profile.Aggressive:
            ks |= {
                "PatientSex", "PatientAge", "PatientSize", "PatientWeight",
                "StudyDate", "StudyTime", "SeriesDate", "SeriesTime",
                "ContentDate", "ContentTime", "AcquisitionDate", "AcquisitionTime",
                "AcquisitionDateTime", "InstanceCreationDate", "InstanceCreationTime",
                "InstanceCreationDateTime",
            }
        return ks

    # ---- 需要长度保持重映射的 UID 标签 ----
    @staticmethod
    def uid_keywords() -> set[str]:
        return {
            "StudyInstanceUID", "SeriesInstanceUID", "SOPInstanceUID",
            "FrameOfReferenceUID", "ReferencedSOPInstanceUID",
            "ReferencedSOPInstanceUIDInFile", "ReferencedFrameOfReferenceUID",
            "ReferencedStudyInstanceUID", "ReferencedSeriesInstanceUID",
            "RelatedFrameOfReferenceUID", "ConcatenationUID",
            "SynchronizationFrameOfReferenceUID", "MediaStorageSOPInstanceUID",
        }

    @staticmethod
    def uid_skip() -> set[str]:
        return {
            "SOPClassUID", "TransferSyntaxUID", "ReferencedSOPClassUID",
            "MediaStorageSOPClassUID", "ImplementationClassUID",
            "CodingSchemeUID", "ContextGroupExtensionCreatorUID",
            "PrivateInformationCreatorUID",
        }

    @staticmethod
    def kept_clinical(profile: Profile) -> list[str]:
        if profile == Profile.Conservative:
            return [
                "PatientSex", "PatientAge", "PatientSize", "PatientWeight",
                "BodyPartExamined", "StudyDate", "StudyTime", "SeriesDate",
                "SeriesTime", "SeriesDescription", "Modality",
            ]
        return ["BodyPartExamined", "SeriesDescription", "Modality"]