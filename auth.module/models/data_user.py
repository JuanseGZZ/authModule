from typing import Optional
from pydantic import BaseModel

class DataUser(BaseModel):
    def __init__(
        self,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        phone: Optional[str] = None,
        doc_type: Optional[str] = None,
        doc_number: Optional[str] = None,
        extra: dict | None = None
    ):
        self.first_name = first_name
        self.last_name = last_name
        self.phone = phone
        self.doc_type = doc_type
        self.doc_number = doc_number
        self.extra = extra or {}
