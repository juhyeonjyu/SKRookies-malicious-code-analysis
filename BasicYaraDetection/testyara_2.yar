import "pe"

rule Detect_Custom_PE_File
{
    meta:
	title = "testyara"
        desc = "Detects a PE file with a .text section and size less than 5KB"
        author = "Grok"
        date = "2025-09-01"

    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and

        pe.section_index(".text") >= 0 and

        pe.number_of_sections == 3 and

        filesize < 5120
}