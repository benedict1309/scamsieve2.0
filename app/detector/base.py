"""
Cau truc du lieu dung chung cho tat ca cac rule trong detector.
"""
from dataclasses import dataclass


@dataclass
class RuleMatch:
    """Ket qua khi 1 rule khop voi noi dung nguoi dung dan vao."""
    rule_id: str        # id ngan gon, duy nhat cho rule (vd "imp_police_court")
    category: str        # ten nhom hien thi cho nguoi dung (tieng Viet)
    snippet: str          # doan van ban goc lien quan (de nguoi dung doi chieu)
    score: int              # diem dong gop vao tong diem rui ro
    explanation: str          # giai thich bang tieng Viet vi sao bi gan co
