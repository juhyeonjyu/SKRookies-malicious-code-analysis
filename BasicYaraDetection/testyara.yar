import "pe"

rule Detect_Custom_PE_File
{
    meta:
        description = "Detects a PE file with a .text section and size less than 5KB"
        author = "Grok"
        date = "2025-09-01"

    condition:
        // PE 파일 시그니처 확인
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and

        // 조건 1: .text 섹션 이름 확인
        pe.section_index(".text") >= 0 and

        // 조건 2: 섹션 수 조건을 주석 처리
        // pe.number_of_sections == 3 and

        // 조건 3: 파일 크기가 5KB 미만
        filesize < 5120
}