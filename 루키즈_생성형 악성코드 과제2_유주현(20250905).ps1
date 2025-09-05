# ============================================
# 랜섬웨어 동작 시뮬레이션 스크립트 (훈련용)
# 작성일: 2025-09-05
# 목적: AES-256 암호화, MBR 조작 모방, 권한 상승 시뮬레이션
# ============================================

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host "============================================" -ForegroundColor DarkCyan
Write-Host "  ⚠ 이 스크립트는 랜섬웨어 시뮬레이션입니다." -ForegroundColor Yellow
Write-Host "  실제 악성 행위는 수행되지 않습니다." -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor DarkCyan

# ============================
# 1. AES-256 암호화 시뮬레이션
# ============================

# 암호화 대상 파일 경로 설정
$targetFile = "C:\Training\sample.txt"
$encryptedFile = "C:\Training\sample.locked"

Function Encrypt-File {
    param (
        [string]$inputFile,
        [string]$outputFile
    )

    # 1) 훈련용 키(256bit)와 IV(128bit) 생성
    $key = New-Object byte[] 32
    $iv = New-Object byte[] 16
    (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($key)
    (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($iv)

    # 2) AES 객체 생성 및 키/IV 설정
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $key
    $aes.IV = $iv

    # 3) 암호화기(Encryptor) 생성
    $encryptor = $aes.CreateEncryptor()

    try {
        # 4) 파일 읽기 → 암호화 → 저장
        $inputBytes = [System.IO.File]::ReadAllBytes($inputFile)
        $encryptedBytes = $encryptor.TransformFinalBlock($inputBytes, 0, $inputBytes.Length)
        [System.IO.File]::WriteAllBytes($outputFile, $encryptedBytes)

        Write-Host "✅ 파일이 AES-256 방식으로 암호화되어 .locked 확장자로 저장되었습니다." -ForegroundColor Green
    } catch {
        Write-Host "❌ 암호화 대상 파일을 찾을 수 없습니다. C:\Training\sample.txt 파일을 확인하세요." -ForegroundColor Red
    } finally {
        $aes.Dispose()
    }
}

Encrypt-File -inputFile $targetFile -outputFile $encryptedFile

# ============================
# 2. MBR 손상 시뮬레이션
# ============================

Function Simulate-MBRBlock {
    Write-Host "`n[MBR 조작]" -ForegroundColor Cyan
    Write-Host "MBR 복구 명령어 차단 시뮬레이션 중..." -ForegroundColor Yellow
    Write-Host "bootrec /fixmbr 명령어가 차단되었습니다." -ForegroundColor Red
}

Simulate-MBRBlock

Function Simulate-SystemAccess {
    $sensitivePath = "C:\Windows\System32\config\SAM"
    Write-Host "`n시스템 파일 접근 시뮬레이션: $sensitivePath" -ForegroundColor Yellow

    try {
        if (Test-Path $sensitivePath) {
            Write-Host "파일 존재 확인됨. (접근 시도 로그 기록됨)" -ForegroundColor Magenta
        } else {
            Write-Host "파일이 존재하지 않거나 접근 불가." -ForegroundColor Magenta
        }
    } catch {
        Write-Host "접근 권한이 없어 시뮬레이션만 수행합니다." -ForegroundColor DarkYellow
    }
}

Simulate-SystemAccess

# ============================
# 3. 관리자 권한 요청 시뮬레이션
# ============================

Write-Host "`n[권한 확인]" -ForegroundColor Cyan
whoami /priv

Function Simulate-PrivilegeEscalation {
    Write-Host "`nSeTakeOwnershipPrivilege 활성화 시뮬레이션 중..." -ForegroundColor Yellow
    Write-Host "권한 상승이 시뮬레이션되었습니다." -ForegroundColor Green
}

Simulate-PrivilegeEscalation

# ============================
# 4. 종료 메시지
# ============================

Write-Host "`n============================================" -ForegroundColor DarkCyan
Write-Host "  랜섬웨어 시뮬레이션이 완료되었습니다." -ForegroundColor Cyan
Write-Host "  안전하게 데이터를 보호해 주세요." -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor DarkCyan
Write-Host "`n창을 닫으려면 아무 키나 누르세요." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
