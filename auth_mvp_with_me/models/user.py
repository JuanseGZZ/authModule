
# Representación mínima; no es un ORM.
from dataclasses import dataclass

@dataclass
class User:
    id: str
    email: str
