# Build on the target OS: python -m PyInstaller --clean --noconfirm standalone.spec
from pathlib import Path

root = Path(SPECPATH)
web = root / "frontend" / "dist"
if not (web / "index.html").is_file():
    raise RuntimeError("Run npm ci && npm run build in frontend before packaging.")

a = Analysis(
    [str(root / "backend" / "standalone.py")],
    pathex=[str(root / "backend")],
    binaries=[],
    datas=[(str(web), "web")],
    hiddenimports=["uvicorn.logging", "uvicorn.loops.asyncio", "uvicorn.protocols.http.h11_impl", "uvicorn.lifespan.on"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name="IntunePolicyAnalyzer",
    debug=False,
    strip=False,
    upx=False,
    console=True,
)
