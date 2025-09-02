# PowerShell 스크립트 파일 (test_script.ps1)

# Windows Forms 어셈블리 로드
Add-Type -AssemblyName System.Windows.Forms

# 현재 시간 가져오기
$currentTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# 시스템 정보 가져오기
$computerName = $env:COMPUTERNAME
$userName = $env:USERNAME
$osVersion = (Get-WmiObject Win32_OperatingSystem).Caption

# 메시지 내용 구성
$message = @"
PowerShell 연동 테스트 성공!

실행 정보:
• 실행 시간: $currentTime
• 컴퓨터명: $computerName  
• 사용자명: $userName
• OS 버전: $osVersion

Excel 매크로에서 PowerShell 스크립트가 성공적으로 실행되었습니다.
"@

# 메시지 박스 표시
[System.Windows.Forms.MessageBox]::Show(
    $message, 
    "Excel-PowerShell 연동 테스트", 
    [System.Windows.Forms.MessageBoxButtons]::OK, 
    [System.Windows.Forms.MessageBoxIcon]::Information
)

# 로그 파일 생성 (선택사항)
$logPath = "$env:USERPROFILE\Desktop\powershell_test_log.txt"
$logContent = "PowerShell 연동 테스트 실행됨 - $currentTime"
$logContent | Out-File -FilePath $logPath -Append

Write-Host "PowerShell 스크립트 실행 완료!" -ForegroundColor Green