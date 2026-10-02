@echo off
REM Build mbprobe.exe (single file) di Windows. Jalankan dari root repo.
REM Hasil: dist\mbprobe.exe
python -m venv .venv-build || goto :err
call .venv-build\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt pyinstaller || goto :err
pyinstaller --noconfirm --onefile --console --name mbprobe --collect-submodules serial.tools mbprobe\__main__.py || goto :err
dist\mbprobe.exe version || goto :err
dist\mbprobe.exe ports
echo.
echo OK: dist\mbprobe.exe
exit /b 0
:err
echo BUILD GAGAL
exit /b 1
