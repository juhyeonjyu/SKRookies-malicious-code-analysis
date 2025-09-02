/*
 * 이 YARA 룰은 AES-256 암호화, MBR(Master Boot Record) 훼손,
 * 그리고 관리자 권한 획득 시도와 관련된 특정 패턴을 탐지하여
 * 랜섬웨어를 식별하는 것을 목적으로 합니다.
 */

// pe 모듈을 import하여 PE 파일 관련 속성을 조건문에서 사용할 수 있도록 합니다.
import "pe"

rule RansomwareDetection
{
    meta:
        description = "AES-256 암호화, MBR 훼손, 관리자 권한 상승 패턴을 탐지하는 랜섬웨어 YARA 룰"
        author = "유주현"
        date = "2025-09-02"

    strings:
        // AES-256 및 암호화 관련
        $aes1 = "AES-256" nocase
        $aes2 = "EVP_EncryptInit_ex" nocase
        $aes3 = "EVP_CipherInit_ex" nocase
        $aes4 = "CryptEncrypt" nocase
        $aes5 = "CryptAcquireContext" nocase

        // MBR 훼손 관련
        $mbr1 = "\\\\PhysicalDrive0" nocase
        $mbr2 = "\\\\Device\\\\Harddisk0\\\\DR0" nocase
        $mbr3 = "WriteFile" nocase
        $mbr4 = "DeviceIoControl" nocase

        // 관리자 권한 상승 관련
        $priv1 = "SeDebugPrivilege" nocase
        $priv2 = "SeShutdownPrivilege" nocase
        $priv3 = "TokenPrivileges" nocase

    condition:
        // PE 파일만 탐지 + 파일 크기 제한
        pe.is_pe
        and filesize > 100KB and filesize < 5MB

        // AES 관련 문자열이 존재하고
        and any of ($aes*)

        // (MBR 접근 문자열 + API 호출) 또는 (권한 상승 문자열) 조건
        and (
            (any of ($mbr1, $mbr2) and any of ($mbr3, $mbr4))
            or any of ($priv*)
        )
}