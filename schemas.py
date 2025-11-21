"""
Database Schemas for Smart Village System (Smart Desa)

Each Pydantic model represents a MongoDB collection. The collection name
is the lowercase of the class name, e.g., class User -> "user".

These models are used for request validation and documentation. Persistence
is handled through the database helper functions.
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Literal
from datetime import datetime

# -----------------------------
# Auth / Users
# -----------------------------
class User(BaseModel):
    name: str = Field(..., description="Nama lengkap")
    email: EmailStr = Field(..., description="Email")
    password_hash: str = Field(..., description="Hash kata sandi dengan salt")
    role: Literal["warga", "admin", "staf", "kepala_desa"] = Field("warga", description="Peran pengguna")
    is_active: bool = Field(True)


# -----------------------------
# Kependudukan
# -----------------------------
class Keluarga(BaseModel):
    no_kk: str = Field(..., description="Nomor Kartu Keluarga", min_length=8)
    alamat: str
    rt: Optional[str] = None
    rw: Optional[str] = None
    desa: Optional[str] = None
    kecamatan: Optional[str] = None
    kabupaten: Optional[str] = None
    provinsi: Optional[str] = None


class Penduduk(BaseModel):
    nik: str = Field(..., description="Nomor Induk Kependudukan", min_length=8)
    nama: str
    tempat_lahir: Optional[str] = None
    tanggal_lahir: Optional[str] = None
    jenis_kelamin: Optional[Literal["L", "P"]] = None
    alamat: Optional[str] = None
    agama: Optional[str] = None
    status_perkawinan: Optional[str] = None
    pekerjaan: Optional[str] = None
    pendidikan: Optional[str] = None
    no_kk: Optional[str] = Field(None, description="Relasi ke nomor KK")


# -----------------------------
# Surat Digital
# -----------------------------
class Surat(BaseModel):
    pemohon_user_id: str = Field(..., description="_id user pemohon (string)")
    jenis: Literal["sku", "domisili", "tidak_mampu", "lainnya"]
    data: dict = Field({}, description="Payload isian tambahan sesuai jenis surat")
    status: Literal["diajukan", "diverifikasi", "ditolak", "disetujui"] = "diajukan"
    catatan: Optional[str] = None
    nomor_surat: Optional[str] = None
    approved_by: Optional[str] = None  # user id admin yang menyetujui


# -----------------------------
# Bansos
# -----------------------------
class Bansos(BaseModel):
    nama: str
    deskripsi: Optional[str] = None
    periode: Optional[str] = None  # misal: 2025-Q1


class PenerimaBansos(BaseModel):
    bansos_id: str
    penduduk_nik: str
    tanggal_distribusi: Optional[str] = None
    keterangan: Optional[str] = None


# -----------------------------
# Keuangan Desa
# -----------------------------
class Keuangan(BaseModel):
    kategori: Literal["pemasukan", "pengeluaran"]
    jumlah: float
    tanggal: Optional[str] = None
    keterangan: Optional[str] = None


# -----------------------------
# Aset Desa
# -----------------------------
class Asetdesa(BaseModel):
    nama: str
    kategori: Optional[str] = None
    jumlah: int = 1
    lokasi: Optional[str] = None
    kondisi: Optional[str] = None


# -----------------------------
# Audit Log
# -----------------------------
class Auditlog(BaseModel):
    user_id: Optional[str] = None
    action: str
    module: str
    detail: Optional[dict] = None
    ip: Optional[str] = None
    created_at: Optional[datetime] = None
