"""
Cac enum dung chung cho toan bo project.
Tach rieng de tranh import cheo giua cac model.
"""
import enum


class UserRole(str, enum.Enum):
    USER = "user"
    ADMIN = "admin"


class InputType(str, enum.Enum):
    TEXT = "text"      # doan chat / tin nhan
    PHONE = "phone"    # so dien thoai
    EMAIL = "email"
    URL = "url"
    IMAGE = "image"    # hinh anh / anh chup man hinh


class RiskLevel(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class ContentType(str, enum.Enum):
    TEXT = "text"
    URL = "url"
    PHONE = "phone"
    BANK_ACCOUNT = "bank_account"


class ReportStatus(str, enum.Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
