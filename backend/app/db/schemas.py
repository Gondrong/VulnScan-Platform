from pydantic import BaseModel
from typing import Optional, Any

class LoginIn(BaseModel):
    email: str
    password: str

class LoginOut(BaseModel):
    token: str

class ProfileIn(BaseModel):
    name: str
    plugin_selection_json: str = "{}"
    options_json: str = "{}"

class ProfileOut(ProfileIn):
    id: int
    class Config:
        from_attributes = True

class JobIn(BaseModel):
    target: str
    profile_id: int

class JobOut(BaseModel):
    id: int
    target: str
    profile_id: int
    status: str
    class Config:
        from_attributes = True

class FindingOut(BaseModel):
    id: int
    plugin_id: str
    title: str
    severity: str
    evidence: str
    risk_score: Optional[float] = None
    cvss_base: Optional[float] = None
    is_kev: bool
    compliance_json: Optional[str] = None
    class Config:
        from_attributes = True

class CredentialIn(BaseModel):
    name: str
    kind: str = "ssh"
    username: str
    secret_type: str = "password"  # password|ssh_key
    secret: str
    passphrase: Optional[str] = None

class CredentialOut(BaseModel):
    id: int
    name: str
    kind: str
    username: str
    secret_type: str
    class Config:
        from_attributes = True

class DatasetOut(BaseModel):
    id: int
    name: str
    kind: str
    enabled: bool
    class Config:
        from_attributes = True