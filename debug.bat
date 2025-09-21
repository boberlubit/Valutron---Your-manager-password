@echo off
pip install pyinstaller
pyinstaller --onefile --windowed --name Vaultron --hidden-import=flet --hidden-import=cryptography --hidden-import=json --hidden-import=os --hidden-import=base64 --hidden-import=hashlib --hidden-import=re --hidden-import=datetime --collect-all=flet --collect-all=cryptography main.py
pause