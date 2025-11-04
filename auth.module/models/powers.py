from uuid import UUID
from pydantic import BaseModel

class Power(BaseModel):
    def __init__(self, id: UUID, path: str):
        self.id = id
        self.path = path  # string tipo "/events/create" o "tickets.validate"
