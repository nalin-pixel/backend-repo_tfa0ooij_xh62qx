import os
from datetime import datetime, timezone
from typing import List, Optional, Literal

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from pydantic import field_validator
from jose import jwt, JWTError
from passlib.context import CryptContext
from dotenv import load_dotenv
from email_validator import validate_email, EmailNotValidError

from database import db, create_document, get_documents
from schemas import (
    User, Penduduk, Keluarga, Surat, Bansos, PenerimaBansos, Keuangan, Asetdesa, Auditlog
)

# Load environment variables from .env if present
load_dotenv()

# ---------- Security Config ----------
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ---------- FastAPI App ----------
app = FastAPI(title="Smart Desa API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- Helpers ----------
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def validate_email_relaxed(cls, v: str) -> str:
        try:
            info = validate_email(v, allow_smtputf8=True, allow_special_use=True)
            return info.normalized
        except EmailNotValidError as e:
            raise ValueError(str(e))


class RegisterRequest(BaseModel):
    name: str
    email: str
    password: str
    role: Literal["warga", "admin", "staf", "kepala_desa"] = "warga"

    @field_validator("email")
    @classmethod
    def validate_email_relaxed(cls, v: str) -> str:
        try:
            info = validate_email(v, allow_smtputf8=True, allow_special_use=True)
            return info.normalized
        except EmailNotValidError as e:
            raise ValueError(str(e))


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    to_encode.update({"exp": datetime.now(timezone.utc).timestamp() + ACCESS_TOKEN_EXPIRE_MINUTES * 60})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def log_action(request: Request, user_id: Optional[str], action: str, module: str, detail: Optional[dict] = None):
    try:
        log = Auditlog(user_id=user_id, action=action, module=module, detail=detail, ip=request.client.host if request.client else None)
        create_document("auditlog", log)
    except Exception:
        pass


async def get_current_user(request: Request) -> dict:
    auth = request.headers.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = auth.split()[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    email = payload.get("sub")
    if not email:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    user = db["user"].find_one({"email": email})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def require_roles(*roles: str):
    async def wrapper(user=Depends(get_current_user)):
        if user.get("role") not in roles:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return user
    return wrapper


# ---------- Startup seed (default admin) ----------
@app.on_event("startup")
def seed_default_admin():
    try:
        admin_email = os.getenv("ADMIN_EMAIL", "admin@desa.test")
        admin_password = os.getenv("ADMIN_PASSWORD", "Admin123!")
        if not db["user"].find_one({"email": admin_email}):
            user = User(
                name="Administrator",
                email=admin_email,
                password_hash=hash_password(admin_password),
                role="admin",
            )
            create_document("user", user)
            # simple console log
            print(f"[seed] Created default admin: {admin_email}")
        else:
            print("[seed] Admin already exists")
    except Exception as e:
        print(f"[seed] Error seeding admin: {e}")


# ---------- Base Endpoints ----------
@app.get("/")
def root():
    return {"message": "Smart Desa API running"}


@app.get("/test")
def test_database():
    try:
        collections = db.list_collection_names() if db else []
        return {"backend": "ok", "database": "ok" if db else "not_configured", "collections": collections}
    except Exception as e:
        return {"backend": "ok", "database": f"error: {str(e)}"}


# ---------- Auth ----------
@app.post("/auth/register", response_model=Token)
async def register(payload: RegisterRequest, request: Request):
    # unique email
    if db["user"].find_one({"email": payload.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(name=payload.name, email=payload.email, password_hash=hash_password(payload.password), role=payload.role)
    create_document("user", user)
    token = create_access_token({"sub": user.email, "role": user.role})
    await log_action(request, user_id=user.email, action="register", module="auth")
    return Token(access_token=token)


@app.post("/auth/login", response_model=Token)
async def login(payload: LoginRequest, request: Request):
    user = db["user"].find_one({"email": payload.email})
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": user["email"], "role": user.get("role", "warga")})
    await log_action(request, user_id=user["email"], action="login", module="auth")
    return Token(access_token=token)


# ---------- Penduduk & Keluarga (Admin/Staf/Kepala) ----------
@app.get("/penduduk")
async def list_penduduk(user=Depends(require_roles("admin", "staf", "kepala_desa"))):
    items = get_documents("penduduk")
    return items


class PendudukCreate(Penduduk):
    pass


@app.post("/penduduk")
async def create_penduduk(payload: PendudukCreate, request: Request, user=Depends(require_roles("admin", "staf", "kepala_desa"))):
    # Unique NIK
    if db["penduduk"].find_one({"nik": payload.nik}):
        raise HTTPException(status_code=400, detail="NIK sudah terdaftar")
    _id = create_document("penduduk", payload)
    await log_action(request, user_id=user.get("email"), action="create", module="penduduk", detail={"nik": payload.nik})
    return {"inserted_id": _id}


@app.put("/penduduk/{nik}")
async def update_penduduk(nik: str, payload: Penduduk, request: Request, user=Depends(require_roles("admin", "staf", "kepala_desa"))):
    found = db["penduduk"].find_one({"nik": nik})
    if not found:
        raise HTTPException(status_code=404, detail="Data tidak ditemukan")
    data = payload.model_dump()
    data["updated_at"] = datetime.now(timezone.utc)
    db["penduduk"].update_one({"nik": nik}, {"$set": data})
    await log_action(request, user_id=user.get("email"), action="update", module="penduduk", detail={"nik": nik})
    return {"status": "ok"}


@app.delete("/penduduk/{nik}")
async def delete_penduduk(nik: str, request: Request, user=Depends(require_roles("admin", "staf", "kepala_desa"))):
    res = db["penduduk"].delete_one({"nik": nik})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Data tidak ditemukan")
    await log_action(request, user_id=user.get("email"), action="delete", module="penduduk", detail={"nik": nik})
    return {"status": "ok"}


# ---------- Surat Digital ----------
class SuratCreate(Surat):
    pass


@app.post("/surat")
async def ajukan_surat(payload: SuratCreate, request: Request, user=Depends(require_roles("warga", "admin", "staf", "kepala_desa"))):
    # Only warga can submit for themselves; admin/staf can submit on behalf
    if user.get("role") == "warga" and payload.pemohon_user_id != user.get("email"):
        raise HTTPException(status_code=403, detail="Tidak boleh mengajukan untuk orang lain")
    _id = create_document("surat", payload)
    await log_action(request, user_id=user.get("email"), action="ajukan", module="surat", detail={"jenis": payload.jenis})
    return {"inserted_id": _id}


@app.get("/surat")
async def list_surat(user=Depends(require_roles("admin", "staf", "kepala_desa"))):
    return get_documents("surat")


@app.get("/surat/saya")
async def list_surat_saya(user=Depends(require_roles("warga", "admin", "staf", "kepala_desa"))):
    return get_documents("surat", {"pemohon_user_id": user.get("email")})


class SuratStatusUpdate(BaseModel):
    status: Literal["diajukan", "diverifikasi", "ditolak", "disetujui"]
    catatan: Optional[str] = None
    nomor_surat: Optional[str] = None


@app.put("/surat/{surat_id}/status")
async def update_status_surat(surat_id: str, payload: SuratStatusUpdate, request: Request, user=Depends(require_roles("admin", "staf", "kepala_desa"))):
    data = payload.model_dump(exclude_unset=True)
    data.update({"updated_at": datetime.now(timezone.utc), "approved_by": user.get("email")})
    from bson import ObjectId
    try:
        res = db["surat"].update_one({"_id": ObjectId(surat_id)}, {"$set": data})
    except Exception:
        raise HTTPException(status_code=400, detail="ID tidak valid")
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Surat tidak ditemukan")
    await log_action(request, user_id=user.get("email"), action="update_status", module="surat", detail={"surat_id": surat_id, **data})
    return {"status": "ok"}


# Placeholder PDF generation endpoint (returns simple HTML-as-PDF content URL)
@app.get("/surat/{surat_id}/pdf")
async def generate_pdf_surat(surat_id: str, user=Depends(require_roles("warga", "admin", "staf", "kepala_desa"))):
    # In this environment we simulate PDF generation by returning HTML content for preview.
    # In real deployment you can integrate WeasyPrint/ReportLab or an external PDF service.
    return {"url": f"/api/mock-pdf/surat/{surat_id}"}


# ---------- Bansos ----------
@app.get("/bansos")
async def list_bansos(user=Depends(require_roles("admin", "staf", "kepala_desa"))):
    return get_documents("bansos")


@app.post("/bansos")
async def create_bansos(payload: Bansos, request: Request, user=Depends(require_roles("admin", "staf", "kepala_desa"))):
    _id = create_document("bansos", payload)
    await log_action(request, user_id=user.get("email"), action="create", module="bansos", detail={"bansos_id": _id})
    return {"inserted_id": _id}


@app.post("/bansos/penerima")
async def add_penerima_bansos(payload: PenerimaBansos, request: Request, user=Depends(require_roles("admin", "staf", "kepala_desa"))):
    _id = create_document("penerimabansos", payload)
    await log_action(request, user_id=user.get("email"), action="create", module="penerima_bansos", detail={"id": _id})
    return {"inserted_id": _id}


# ---------- Keuangan ----------
@app.get("/keuangan")
async def list_keuangan(user=Depends(require_roles("admin", "staf", "kepala_desa"))):
    return get_documents("keuangan")


@app.post("/keuangan")
async def create_keuangan(payload: Keuangan, request: Request, user=Depends(require_roles("admin", "staf", "kepala_desa"))):
    _id = create_document("keuangan", payload)
    await log_action(request, user_id=user.get("email"), action="create", module="keuangan", detail={"id": _id})
    return {"inserted_id": _id}


# ---------- Aset Desa ----------
@app.get("/aset")
async def list_aset(user=Depends(require_roles("admin", "staf", "kepala_desa"))):
    return get_documents("asetdesa")


@app.post("/aset")
async def create_aset(payload: Asetdesa, request: Request, user=Depends(require_roles("admin", "staf", "kepala_desa"))):
    _id = create_document("asetdesa", payload)
    await log_action(request, user_id=user.get("email"), action="create", module="aset", detail={"id": _id})
    return {"inserted_id": _id}


# ---------- Dashboard Metrics ----------
@app.get("/dashboard/metrics")
async def dashboard_metrics(user=Depends(require_roles("admin", "staf", "kepala_desa"))):
    penduduk_count = db["penduduk"].count_documents({}) if db else 0
    surat_count = db["surat"].count_documents({}) if db else 0
    bansos_count = db["bansos"].count_documents({}) if db else 0
    keu_in = sum([d.get("jumlah", 0) for d in get_documents("keuangan", {"kategori": "pemasukan"})]) if db else 0
    keu_out = sum([d.get("jumlah", 0) for d in get_documents("keuangan", {"kategori": "pengeluaran"})]) if db else 0
    return {
        "penduduk": penduduk_count,
        "surat": surat_count,
        "bansos": bansos_count,
        "keuangan": {"pemasukan": keu_in, "pengeluaran": keu_out},
    }


# ---------- Audit Logs ----------
@app.get("/audit")
async def list_audit(user=Depends(require_roles("admin", "kepala_desa"))):
    return get_documents("auditlog", limit=200)


# ---------- Backup (export) ----------
@app.get("/backup/export")
async def export_backup(user=Depends(require_roles("admin", "kepala_desa"))):
    collections = [
        "user", "penduduk", "keluarga", "surat", "bansos", "penerimabansos", "keuangan", "asetdesa", "auditlog"
    ]
    data = {}
    for c in collections:
        data[c] = get_documents(c)
    return data
