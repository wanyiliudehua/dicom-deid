"""脱敏策略定义（A 保守 / B 激进）"""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum


def _audit_flagged_keywords() -> set[str]:
    """与审计同一判定规则（关键词命中且不在误报白名单）——
    审计认定的 PHI 必须被脱敏清除，判定规则只维护 audit.py 一处。"""
    from pydicom.datadict import keyword_dict
    from .audit import PHI_KEYWORDS, FALSE_POSITIVES
    return {kw for kw in keyword_dict
            if any(k in kw.lower() for k in PHI_KEYWORDS) and kw not in FALSE_POSITIVES}


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


# ---- 两档都清的标签 ----
_BASE_CLEAR = [
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

# ---- B 激进额外清：临床身份属性 + 全部日期时间 ----
_AGGRESSIVE_EXTRA = {
    "PatientSex", "PatientAge", "PatientSize", "PatientWeight",
    "StudyDate", "StudyTime", "SeriesDate", "SeriesTime",
    "ContentDate", "ContentTime", "AcquisitionDate", "AcquisitionTime",
    "AcquisitionDateTime", "InstanceCreationDate", "InstanceCreationTime",
    "InstanceCreationDateTime",
}


@dataclass
class Policy:
    profile: Profile
    rename_files: bool = True

    def clear_keywords(self) -> set[str]:
        # 审计判定的 PHI 全部清除（含 ImageComments/AdditionalPatientHistory 等自由文本），
        # 再按策略保留 kept_clinical——审计报警的字段绝不允许留在产物里
        ks = set(_BASE_CLEAR) | _audit_flagged_keywords()
        if self.profile == Profile.Aggressive:
            ks |= _AGGRESSIVE_EXTRA
        return ks - set(self.kept_clinical(self.profile))

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
    def kept_clinical(profile: Profile) -> list[str]:
        if profile == Profile.Conservative:
            return [
                "PatientSex", "PatientAge", "PatientSize", "PatientWeight",
                "BodyPartExamined", "StudyDate", "StudyTime", "SeriesDate",
                "SeriesTime", "SeriesDescription", "Modality",
            ]
        return ["BodyPartExamined", "SeriesDescription", "Modality"]