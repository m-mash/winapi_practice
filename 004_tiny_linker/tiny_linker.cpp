/**
 * Tiny Linker
 * Windows APT Warfare
 * by aaaddress1@chroot.org
 */
#include <iostream>
#include <Windows.h>
#pragma warning(disable : 4996)

// Alignしてこのサイズに揃えたい
#define file_align 0x200
#define sect_align 0x1000

// Alignしたサイズを返す
#define P2ALIGNUP(size, align) ((((size) / align) + 1) * (align))

// 挿入したいShellCode
char x86_nullfree_msgbox[] =
    "\x31\xd2\xb2\x30\x64\x8b\x12\x8b\x52\x0c\x8b\x52\x1c\x8b\x42"
    "\x08\x8b\x72\x20\x8b\x12\x80\x7e\x0c\x33\x75\xf2\x89\xc7\x03"
    "\x78\x3c\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01\xc7\x31\xed\x8b"
    "\x34\xaf\x01\xc6\x45\x81\x3e\x46\x61\x74\x61\x75\xf2\x81\x7e"
    "\x08\x45\x78\x69\x74\x75\xe9\x8b\x7a\x24\x01\xc7\x66\x8b\x2c"
    "\x6f\x8b\x7a\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01\xc7\x68\x79\x74"
    "\x65\x01\x68\x6b\x65\x6e\x42\x68\x20\x42\x72\x6f\x89\xe1\xfe"
    "\x49\x0b\x31\xc0\x51\x50\xff\xd7";

int main()
{
    // ヘッダ全体のサイズは各ヘッダの合計値をfile_alignでAlignUpしたもの
    size_t peHeaderSize = P2ALIGNUP(sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER), file_align);
    // セクションデータのサイズはShellCodeのサイズをfile_alignでAlighUpしたもの
    size_t sectionDataSize = P2ALIGNUP(sizeof(x86_nullfree_msgbox), file_align);
    // callocでPEファイル全体の領域を確保して0で埋める
    char *peData = (char *)calloc(peHeaderSize + sectionDataSize, 1);

    // PEファイルの最初はDOSヘッダ
    PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)peData;
    // マジックナンバー＝"MZ"
    dosHdr->e_magic = IMAGE_DOS_SIGNATURE;
    // NTヘッダの位置（オフセット）＝DOSヘッダのサイズ
    dosHdr->e_lfanew = sizeof(IMAGE_DOS_HEADER);

    // 次はNTヘッダ、PEファイルのアドレスからe_lfanewだけオフセットしたアドレス
    PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)(peData + dosHdr->e_lfanew);
    // マジックナンバー＝"PE"
    ntHdr->Signature = IMAGE_NT_SIGNATURE;
    // x86
    ntHdr->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
    // IMAGE_FILE_EXECUTABLE_IMAGE : The file is executable (there are no unresolved external references).
    // IMAGE_FILE_32BIT_MACHINE :  The computer supports 32-bit words.
    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header
    ntHdr->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE;
    // Optionalヘッダのサイズ
    ntHdr->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER);
    // セクションの数はShellCodeが挿入される1セクションだけ
    ntHdr->FileHeader.NumberOfSections = 1;

    // セクションヘッダはNTヘッダのアドレスからNTヘッダのサイズだけオフセットしたアドレス
    PIMAGE_SECTION_HEADER sectHdr = (PIMAGE_SECTION_HEADER)((char *)ntHdr + sizeof(IMAGE_NT_HEADERS));
    // セクションの名前
    memcpy(&(sectHdr->Name), "30cm.tw", 8);
    // セクションのRVA
    sectHdr->VirtualAddress = 0x1000;
    // セクションのサイズはAlignUpしたもの
    sectHdr->Misc.VirtualSize = P2ALIGNUP(sizeof(x86_nullfree_msgbox), sect_align);
    // ファイル上のセクションのサイズはそのままsizeof
    sectHdr->SizeOfRawData = sizeof(x86_nullfree_msgbox);
    // ファイル上のセクションのオフセット＝PEヘッダのサイズ
    sectHdr->PointerToRawData = peHeaderSize;
    // ShellCodeをセクション開始位置にコピー
    memcpy(peData + peHeaderSize, x86_nullfree_msgbox, sizeof(x86_nullfree_msgbox));
    // IMAGE_SCN_MEM_EXECUTE: The section can be executed as code.
    // IMAGE_SCN_MEM_READ: The section can be read.
    // IMAGE_SCN_MEM_WRITE: The section can be written to.
    // https://learn.microsoft.com/ja-jp/windows/win32/api/winnt/ns-winnt-image_section_header
    sectHdr->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    // エントリポイントはShellCodeのRVA
    ntHdr->OptionalHeader.AddressOfEntryPoint = sectHdr->VirtualAddress;

    // PE32
    ntHdr->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    // コード領域（.text）のRVA
    ntHdr->OptionalHeader.BaseOfCode = sectHdr->VirtualAddress;
    // データ領域（.data）のRVA
    ntHdr->OptionalHeader.BaseOfData = 0x0000;
    // ファイルがロードされるアドレス
    ntHdr->OptionalHeader.ImageBase = 0x400000;
    // Alignment
    ntHdr->OptionalHeader.FileAlignment = file_align;
    ntHdr->OptionalHeader.SectionAlignment = sect_align;
    // IMAGE_SUBSYSTEM_WINDOWS_GUI: Windows graphical user interface (GUI) subsystem.
    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32
    ntHdr->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
    // メモリ上にロードするのに必要なサイズはセクションのRVA＋サイズ
    ntHdr->OptionalHeader.SizeOfImage = sectHdr->VirtualAddress + sectHdr->Misc.VirtualSize;
    // PEヘッダサイズ
    ntHdr->OptionalHeader.SizeOfHeaders = peHeaderSize;
    ntHdr->OptionalHeader.MajorSubsystemVersion = 5;
    ntHdr->OptionalHeader.MinorSubsystemVersion = 1;

    // メモリ上に作成したPEファイルをファイルに書き出し
    FILE *fp = fopen("poc.exe", "wb");
    fwrite(peData, peHeaderSize + sectionDataSize, 1, fp);
}