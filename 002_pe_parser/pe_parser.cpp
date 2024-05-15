// Referenced: https://github.com/PacktPublishing/Windows-APT-Warfare

#include <stdio.h>
#include <windows.h>
#pragma warning(disable : 4996)

bool readBinFile(const char *fileName, char *&bufPtr, DWORD &length)
{
    // ファイルを読み込んでポインタを取得
    if (FILE *fp = fopen(fileName, "rb"))
    {
        // ファイルポインタを終端に移動
        fseek(fp, 0, SEEK_END);

        // 先頭からの位置（＝すなわちサイズ）を取得
        length = ftell(fp);

        // 終端文字を含めてlength+1のchar配列を用意
        bufPtr = new char[length + 1];

        // ポインタを先頭に移動
        fseek(fp, 0, SEEK_SET);

        // fpからcharのサイズ x lengthを読み取ってbufPtrに格納する
        // 読み取れた数がlengthだけ返ってきていれば成功
        if (fread(bufPtr, sizeof(char), length, fp) == length)
            return true;
    }

    return false;
}

void peParser(const char *ptrToPeBinary, const int binarySize)
{
    // DOSヘッダ
    IMAGE_DOS_HEADER *dosHdr = (IMAGE_DOS_HEADER *)ptrToPeBinary;

    printf("\n[+] DOS Header: size = %d bytes\n", sizeof(*dosHdr));
    printf("    ├ e_magic / Magic Number                       : %04x\n", dosHdr->e_magic);
    printf("    ├ e_cblp / Bytes on last page of file          : %04x\n", dosHdr->e_cblp);
    printf("    ├ e_cp / Pages in file                         : %04x\n", dosHdr->e_cp);
    printf("    ├ e_crlc / Relocations                         : %04x\n", dosHdr->e_crlc);
    printf("    ├ e_cparhdr / Size of header in paragraphs     : %04x\n", dosHdr->e_cparhdr);
    printf("    ├ e_minalloc / Minimum extra paragraphs needed : %04x\n", dosHdr->e_minalloc);
    printf("    ├ e_maxalloc / Maximum extra paragraphs needed : %04x\n", dosHdr->e_maxalloc);
    printf("    ├ e_ss / Initial (relative) SS value           : %04x\n", dosHdr->e_ss);
    printf("    ├ e_sp / Initial SP value                      : %04x\n", dosHdr->e_sp);
    printf("    ├ e_csum / Checksum                            : %04x\n", dosHdr->e_csum);
    printf("    ├ e_ip / Initial IP value                      : %04x\n", dosHdr->e_ip);
    printf("    ├ e_cs / Initial (relative) CS value           : %04x\n", dosHdr->e_cs);
    printf("    ├ e_lfarlc / File address of relocation table  : %04x\n", dosHdr->e_lfarlc);
    printf("    ├ e_ovno / Overlay number                      : %04x\n", dosHdr->e_ovno);
    printf("    ├ e_res[0] / Reserved words                    : %04x\n", dosHdr->e_res[0]);
    printf("    ├ e_res[1] / Reserved words                    : %04x\n", dosHdr->e_res[1]);
    printf("    ├ e_res[2] / Reserved words                    : %04x\n", dosHdr->e_res[2]);
    printf("    ├ e_res[3] / Reserved words                    : %04x\n", dosHdr->e_res[3]);
    printf("    ├ e_oemid / OEM identifier (for e_oeminfo)     : %04x\n", dosHdr->e_oemid);
    printf("    ├ e_oeminfo / OEM information; e_oemid specific: %04x\n", dosHdr->e_oeminfo);
    printf("    ├ e_res2[0] / Reserved words                   : %04x\n", dosHdr->e_res2[0]);
    printf("    ├ e_res2[1] / Reserved words                   : %04x\n", dosHdr->e_res2[1]);
    printf("    ├ e_res2[2] / Reserved words                   : %04x\n", dosHdr->e_res2[2]);
    printf("    ├ e_res2[3] / Reserved words                   : %04x\n", dosHdr->e_res2[3]);
    printf("    ├ e_res2[4] / Reserved words                   : %04x\n", dosHdr->e_res2[4]);
    printf("    ├ e_res2[5] / Reserved words                   : %04x\n", dosHdr->e_res2[5]);
    printf("    ├ e_res2[6] / Reserved words                   : %04x\n", dosHdr->e_res2[6]);
    printf("    ├ e_res2[7] / Reserved words                   : %04x\n", dosHdr->e_res2[7]);
    printf("    ├ e_res2[8] / Reserved words                   : %04x\n", dosHdr->e_res2[8]);
    printf("    ├ e_res2[9] / Reserved words                   : %04x\n", dosHdr->e_res2[9]);
    printf("    ├ e_res2[10] / Reserved words                  : %04x\n", dosHdr->e_res2[10]);
    printf("    └ e_lfanew / File address of new exe header    : %08lx\n", dosHdr->e_lfanew);

    // NTヘッダ
    IMAGE_NT_HEADERS *ntHdrs = (IMAGE_NT_HEADERS *)((size_t)dosHdr + dosHdr->e_lfanew);
    if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE || ntHdrs->Signature != IMAGE_NT_SIGNATURE)
    {
        fprintf(stderr, "[!] PE binary broken or invalid?");
        return;
    }
    printf("\n\n[+] NT Header: size = %d bytes\n", sizeof(*ntHdrs));
    printf("    ├ Signature                       : %08x\n", ntHdrs->Signature);

    // NTヘッダ > Fileヘッダ
    IMAGE_FILE_HEADER *fileHdr = &ntHdrs->FileHeader;
    printf("    ├ File Header\n");
    printf("    │   ├ Machine                     : %04x\n", fileHdr->Machine);
    printf("    │   ├ NumberOfSections            : %04x\n", fileHdr->NumberOfSections);
    printf("    │   ├ TimeDateStamp               : %08x\n", fileHdr->TimeDateStamp);
    printf("    │   ├ PointerToSymbolTable        : %08x\n", fileHdr->PointerToSymbolTable);
    printf("    │   ├ NumberOfSymbols             : %08x\n", fileHdr->NumberOfSymbols);
    printf("    │   ├ SizeOfOptionalHeader        : %04x\n", fileHdr->SizeOfOptionalHeader);
    printf("    │   └ Characteristics             : %04x\n", fileHdr->Characteristics);

    // NTヘッダ > Optionalヘッダ
    IMAGE_OPTIONAL_HEADER *optHdr = &ntHdrs->OptionalHeader;
    printf("    └ Optional Header\n");
    printf("        ├ Magic                       : %04x\n", optHdr->Magic);
    printf("        ├ MajorLinkerVersion          : %02x\n", optHdr->MajorLinkerVersion);
    printf("        ├ MinorLinkerVersion          : %02x\n", optHdr->MinorLinkerVersion);
    printf("        ├ SizeOfCode                  : %08x\n", optHdr->SizeOfCode);
    printf("        ├ SizeOfInitializedData       : %08x\n", optHdr->SizeOfInitializedData);
    printf("        ├ SizeOfUninitializedData     : %08x\n", optHdr->SizeOfUninitializedData);
    printf("        ├ AddressOfEntryPoint         : %08x\n", optHdr->AddressOfEntryPoint);
    printf("        ├ BaseOfCode                  : %08x\n", optHdr->BaseOfCode);
    printf("        ├ ImageBase                   : %08x\n", optHdr->ImageBase);
    printf("        ├ SectionAlignment            : %08x\n", optHdr->SectionAlignment);
    printf("        ├ FileAlignment               : %08x\n", optHdr->FileAlignment);
    printf("        ├ MajorOperatingSystemVersion : %04x\n", optHdr->MajorOperatingSystemVersion);
    printf("        ├ MinorOperatingSystemVersion : %04x\n", optHdr->MinorOperatingSystemVersion);
    printf("        ├ MajorImageVersion           : %04x\n", optHdr->MajorImageVersion);
    printf("        ├ MinorImageVersion           : %04x\n", optHdr->MinorImageVersion);
    printf("        ├ MajorSubsystemVersion       : %04x\n", optHdr->MajorSubsystemVersion);
    printf("        ├ MinorSubsystemVersion       : %04x\n", optHdr->MinorSubsystemVersion);
    printf("        ├ Win32VersionValue           : %08x\n", optHdr->Win32VersionValue);
    printf("        ├ SizeOfImage                 : %08x\n", optHdr->SizeOfImage);
    printf("        ├ SizeOfHeaders               : %08x\n", optHdr->SizeOfHeaders);
    printf("        ├ CheckSum                    : %08x\n", optHdr->CheckSum);
    printf("        ├ Subsystem                   : %04x\n", optHdr->Subsystem);
    printf("        ├ DllCharacteristics          : %04x\n", optHdr->DllCharacteristics);
    printf("        ├ SizeOfStackReserve          : %08x\n", optHdr->SizeOfStackReserve);
    printf("        ├ SizeOfStackCommit           : %08x\n", optHdr->SizeOfStackCommit);
    printf("        ├ SizeOfHeapReserve           : %08x\n", optHdr->SizeOfHeapReserve);
    printf("        ├ SizeOfHeapCommit            : %08x\n", optHdr->SizeOfHeapCommit);
    printf("        ├ LoaderFlags                 : %08x\n", optHdr->LoaderFlags);
    printf("        ├ NumberOfRvaAndSizes         : %08x\n", optHdr->NumberOfRvaAndSizes);
    for (size_t i = 0; i < optHdr->NumberOfRvaAndSizes - 1; i++)
        printf("        ├ DataDirectory[%d]            : VirtualAddress=%08x, Size=%08x\n", i, optHdr->DataDirectory[i].VirtualAddress, optHdr->DataDirectory[i].Size);
    printf("        └ DataDirectory[%d]           : VirtualAddress=%08x, Size=%08x\n", optHdr->NumberOfRvaAndSizes - 1, optHdr->DataDirectory[optHdr->NumberOfRvaAndSizes - 1].VirtualAddress, optHdr->DataDirectory[optHdr->NumberOfRvaAndSizes - 1].Size);

    // セクションヘッダ
    IMAGE_SECTION_HEADER *sectHdr = (IMAGE_SECTION_HEADER *)((size_t)ntHdrs + sizeof(*ntHdrs));
    printf("\n\n[+] Section Headers: size = %d bytes * %d sections = %d bytes\n", sizeof(*sectHdr), ntHdrs->FileHeader.NumberOfSections, sizeof(*sectHdr) * ntHdrs->FileHeader.NumberOfSections);
    for (size_t i = 0; i < ntHdrs->FileHeader.NumberOfSections - 1; i++)
    {
        printf("    ├ %s\n", sectHdr[i].Name);
        printf("    │   ├ VirtualAddress               : %08x\n", sectHdr[i].VirtualAddress);
        printf("    │   ├ SizeOfRawData                : %08x\n", sectHdr[i].SizeOfRawData);
        printf("    │   ├ PointerToRawData             : %08x\n", sectHdr[i].PointerToRawData);
        printf("    │   ├ PointerToRelocations         : %08x\n", sectHdr[i].PointerToRelocations);
        printf("    │   ├ PointerToLinenumbers         : %08x\n", sectHdr[i].PointerToLinenumbers);
        printf("    │   ├ NumberOfRelocations          : %08x\n", sectHdr[i].NumberOfRelocations);
        printf("    │   ├ NumberOfLinenumbers          : %08x\n", sectHdr[i].NumberOfLinenumbers);
        printf("    │   └ Characteristics              : %08x\n", sectHdr[i].Characteristics);
    }
    printf("    └ %s\n", sectHdr[ntHdrs->FileHeader.NumberOfSections - 1].Name);
    printf("        ├ VirtualAddress               : %08x\n", sectHdr[ntHdrs->FileHeader.NumberOfSections - 1].VirtualAddress);
    printf("        ├ SizeOfRawData                : %08x\n", sectHdr[ntHdrs->FileHeader.NumberOfSections - 1].SizeOfRawData);
    printf("        ├ PointerToRawData             : %08x\n", sectHdr[ntHdrs->FileHeader.NumberOfSections - 1].PointerToRawData);
    printf("        ├ PointerToRelocations         : %08x\n", sectHdr[ntHdrs->FileHeader.NumberOfSections - 1].PointerToRelocations);
    printf("        ├ PointerToLinenumbers         : %08x\n", sectHdr[ntHdrs->FileHeader.NumberOfSections - 1].PointerToLinenumbers);
    printf("        ├ NumberOfRelocations          : %08x\n", sectHdr[ntHdrs->FileHeader.NumberOfSections - 1].NumberOfRelocations);
    printf("        ├ NumberOfLinenumbers          : %08x\n", sectHdr[ntHdrs->FileHeader.NumberOfSections - 1].NumberOfLinenumbers);
    printf("        └ Characteristics              : %08x\n", sectHdr[ntHdrs->FileHeader.NumberOfSections - 1].Characteristics);

    printf("\n");
}

// コマンドライン引数として1つのファイルパスを受け入れる
int main(int argc, char **argv)
{
    // ファイルを読み込んだデータ列をcharの配列として
    char *binaryData;
    // ファイルのサイズをDWORDとして
    DWORD binarySize;

    // 引数の数が正しくなかったら
    if (argc != 2)
        fprintf(stderr, "[!] usage: peParser.exe [path/to/exe]");
    // 指定されたファイルをバッファに読み込んで、成功したら
    else if (readBinFile(argv[1], binaryData, binarySize))
    {
        printf("[+] PE binary is loaded at %s\n", argv[1]);
        printf("[+] Try to parse PE binary...\n\n");
        peParser(binaryData, binarySize);
    }
    // 失敗したら
    else
        fprintf(stderr, "[!] Reading PE file has failed.");

    return 0;
}