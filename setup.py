import sys
from cx_Freeze import setup, Executable

build_exe_options = {
    "packages": ["flet", "cryptography", "json", "os", "base64", "hashlib", "re", "datetime"],
    "include_files": [],
}

base = None
if sys.platform == "win32":
    base = "Win32GUI"

setup(
    name="Vaultron",
    version="1.0",
    description="Secure Password Manager",
    options={"build_exe": build_exe_options},
    executables=[Executable("main.py", base=base, target_name="Vaultron.exe")]
)