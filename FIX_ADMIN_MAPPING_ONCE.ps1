$ErrorActionPreference = "Stop"

function Find-ProjectRoot {
    param([string]$StartPath)

    $current = (Resolve-Path $StartPath).Path
    for ($i = 0; $i -lt 10; $i++) {
        $frontendIndex = Join-Path $current "frontend\index.html"
        $backendMain = Join-Path $current "backend\app\main.py"
        if ((Test-Path $frontendIndex) -and (Test-Path $backendMain)) {
            return $current
        }

        $parent = Split-Path $current -Parent
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $current) {
            break
        }
        $current = $parent
    }

    throw "Could not find project root. Run this script from the main project folder OR from inside the backend folder. The root must contain both frontend\index.html and backend\app\main.py."
}

function Patch-FrontendIndex {
    param([string]$IndexPath)

    $content = Get-Content -Raw -Encoding UTF8 $IndexPath
    $original = $content

    # 1) Make sure the React Role constant has ADMIN.
    if ($content -notmatch 'ADMIN\s*:\s*["'']ADMIN["'']') {
        $content = $content -replace '(const\s+Role\s*=\s*\{[^}]*ASSISTANT\s*:\s*["'']ASSISTANT["'']\s*)\}', '$1, ADMIN: "ADMIN" }'
    }

    # 2) Make sure the registration dropdown contains Admin.
    $adminOption = '<option value={Role.ADMIN}>Admin</option>'
    if ($content -notmatch [regex]::Escape($adminOption)) {
        $content = $content -replace '(<option\s+value=\{Role\.ASSISTANT\}>Assistant</option>)', "`$1`r`n                          $adminOption"
    }

    # 3) Remove/soften old helper text that said admins cannot register, if present.
    $content = $content -replace 'Admin accounts are created by existing admins only\.', 'Admin accounts can be created here for assignment demo purposes.'

    if ($content -ne $original) {
        Set-Content -Path $IndexPath -Value $content -Encoding UTF8
        Write-Host "Frontend patched:" $IndexPath -ForegroundColor Green
    } else {
        Write-Host "Frontend already had Admin option:" $IndexPath -ForegroundColor Yellow
    }

    $check = Get-Content -Raw -Encoding UTF8 $IndexPath
    if ($check -notmatch [regex]::Escape($adminOption)) {
        throw "Patch failed: Admin option still not found in frontend index.html"
    }
}

function Patch-BackendMain {
    param([string]$MainPath)

    $content = Get-Content -Raw -Encoding UTF8 $MainPath
    $original = $content

    # Import FileResponse so root can directly serve the current frontend/index.html.
    if ($content -match 'from fastapi\.responses import RedirectResponse' -and $content -notmatch 'FileResponse') {
        $content = $content -replace 'from fastapi\.responses import RedirectResponse', 'from fastapi.responses import RedirectResponse, FileResponse'
    }

    # Make root serve the actual frontend file directly instead of relying on an older redirect/cache.
    $content = $content -replace 'return\s+RedirectResponse\(url=["'']/frontend/index\.html["'']\)', 'return FileResponse(frontend_dir / "index.html", headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"})'

    # Add a tiny debug endpoint so you can prove which frontend file the backend is serving.
    if ($content -notmatch '__frontend_debug') {
        $debugBlock = @'

@app.get("/__frontend_debug")
def frontend_debug():
    """Debug endpoint for assignment demo only: confirms which frontend file is being served."""
    index_path = frontend_dir / "index.html"
    text = index_path.read_text(encoding="utf-8") if index_path.exists() else ""
    return {
        "frontend_index_path": str(index_path),
        "admin_option_present": "Role.ADMIN" in text and "Admin</option>" in text,
    }
'@
        $content = $content.TrimEnd() + $debugBlock + "`r`n"
    }

    if ($content -ne $original) {
        Set-Content -Path $MainPath -Value $content -Encoding UTF8
        Write-Host "Backend main.py patched:" $MainPath -ForegroundColor Green
    } else {
        Write-Host "Backend main.py already patched:" $MainPath -ForegroundColor Yellow
    }
}

$root = Find-ProjectRoot (Get-Location).Path
$frontendIndex = Join-Path $root "frontend\index.html"
$backendMain = Join-Path $root "backend\app\main.py"

Write-Host "Project root detected:" $root -ForegroundColor Cyan
Patch-FrontendIndex $frontendIndex
Patch-BackendMain $backendMain

# Remove Python cache so the edited main.py is definitely reloaded.
$backendApp = Join-Path $root "backend\app"
Get-ChildItem -Path $backendApp -Recurse -Directory -Filter "__pycache__" -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "`nVerification inside frontend/index.html:" -ForegroundColor Cyan
Select-String -Path $frontendIndex -Pattern "Role.ADMIN|Admin</option>" | ForEach-Object { Write-Host $_.Line }

Write-Host "`nNow restart the backend from THIS folder:" -ForegroundColor Magenta
Write-Host "cd `"$(Join-Path $root 'backend')`""
Write-Host ".\.venv\Scripts\Activate.ps1"
Write-Host "python -m uvicorn app.main:app --reload"

Write-Host "`nAfter the server starts, open this exact URL:" -ForegroundColor Magenta
Write-Host "http://127.0.0.1:8000/?v=adminfix#/register"

Write-Host "`nOptional backend proof command:" -ForegroundColor Magenta
Write-Host "Invoke-WebRequest 'http://127.0.0.1:8000/__frontend_debug' -UseBasicParsing | Select-Object -ExpandProperty Content"
