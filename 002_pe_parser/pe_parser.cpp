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

void peParser(char *ptrToPeBinary)
{
    // DOS Headerの各フィールドを表示
    IMAGE_DOS_HEADER *dosHdr = (IMAGE_DOS_HEADER *)ptrToPeBinary;
    printf("\n====================== DOS Header ======================\n");
    printf("[+]   e_magic / Magic Number                       : %04x\n", dosHdr->e_magic);
    printf("[+]   e_cblp / Bytes on last page of file          : %04x\n", dosHdr->e_cblp);
    printf("[+]   e_cp / Pages in file                         : %04x\n", dosHdr->e_cp);
    printf("[+]   e_crlc / Relocations                         : %04x\n", dosHdr->e_crlc);
    printf("[+]   e_cparhdr / Size of header in paragraphs     : %04x\n", dosHdr->e_cparhdr);
    printf("[+]   e_minalloc / Minimum extra paragraphs needed : %04x\n", dosHdr->e_minalloc);
    printf("[+]   e_maxalloc / Maximum extra paragraphs needed : %04x\n", dosHdr->e_maxalloc);
    printf("[+]   e_ss / Initial (relative) SS value           : %04x\n", dosHdr->e_ss);
    printf("[+]   e_sp / Initial SP value                      : %04x\n", dosHdr->e_sp);
    printf("[+]   e_csum / Checksum                            : %04x\n", dosHdr->e_csum);
    printf("[+]   e_ip / Initial IP value                      : %04x\n", dosHdr->e_ip);
    printf("[+]   e_cs / Initial (relative) CS value           : %04x\n", dosHdr->e_cs);
    printf("[+]   e_lfarlc / File address of relocation table  : %04x\n", dosHdr->e_lfarlc);
    printf("[+]   e_ovno / Overlay number                      : %04x\n", dosHdr->e_ovno);
    printf("[+]   e_res[0] / Reserved words                    : %04x\n", dosHdr->e_res[0]);
    printf("[+]   e_res[1] / Reserved words                    : %04x\n", dosHdr->e_res[1]);
    printf("[+]   e_res[2] / Reserved words                    : %04x\n", dosHdr->e_res[2]);
    printf("[+]   e_res[3] / Reserved words                    : %04x\n", dosHdr->e_res[3]);
    printf("[+]   e_oemid / OEM identifier (for e_oeminfo)     : %04x\n", dosHdr->e_oemid);
    printf("[+]   e_oeminfo / OEM information; e_oemid specific: %04x\n", dosHdr->e_oeminfo);
    printf("[+]   e_res2[0] / Reserved words                   : %04x\n", dosHdr->e_res2[0]);
    printf("[+]   e_res2[1] / Reserved words                   : %04x\n", dosHdr->e_res2[1]);
    printf("[+]   e_res2[2] / Reserved words                   : %04x\n", dosHdr->e_res2[2]);
    printf("[+]   e_res2[3] / Reserved words                   : %04x\n", dosHdr->e_res2[3]);
    printf("[+]   e_res2[4] / Reserved words                   : %04x\n", dosHdr->e_res2[4]);
    printf("[+]   e_res2[5] / Reserved words                   : %04x\n", dosHdr->e_res2[5]);
    printf("[+]   e_res2[6] / Reserved words                   : %04x\n", dosHdr->e_res2[6]);
    printf("[+]   e_res2[7] / Reserved words                   : %04x\n", dosHdr->e_res2[7]);
    printf("[+]   e_res2[8] / Reserved words                   : %04x\n", dosHdr->e_res2[8]);
    printf("[+]   e_res2[9] / Reserved words                   : %04x\n", dosHdr->e_res2[9]);
    printf("[+]   e_res2[10] / Reserved words                  : %04x\n", dosHdr->e_res2[10]);
    printf("[+]   e_lfanew / File address of new exe header    : %08lx\n", dosHdr->e_lfanew);

    IMAGE_NT_HEADERS *ntHdrs = (IMAGE_NT_HEADERS *)((size_t)dosHdr + dosHdr->e_lfanew);
    if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE || ntHdrs->Signature != IMAGE_NT_SIGNATURE)
    {
        puts("[!] PE binary broken or invalid?");
        return;
    }

    // display infornamtion of optional header
    if (auto optHdr = &ntHdrs->OptionalHeader)
    {
        printf("[+] ImageBase prefer @ %p\n", (void *)optHdr->ImageBase);
        printf("[+] Dynamic Memory Usage: %x bytes.\n", optHdr->SizeOfImage);
        printf("[+] Dynamic EntryPoint @ %p\n", (void *)(optHdr->ImageBase + optHdr->AddressOfEntryPoint));
    }

    // enumerate section data
    puts("[+] Section Info");
    IMAGE_SECTION_HEADER *sectHdr = (IMAGE_SECTION_HEADER *)((size_t)ntHdrs + sizeof(*ntHdrs));
    for (size_t i = 0; i < ntHdrs->FileHeader.NumberOfSections; i++)
        printf("\t#%.2x - %8s - %.8x - %.8x \n", i, sectHdr[i].Name, sectHdr[i].PointerToRawData, sectHdr[i].SizeOfRawData);
}

// コマンドライン引数として1つのファイルパスを受け入れる
int main(int argc, char **argv)
{
    // ファイルを読み込んだデータ列をcharの配列として
    char *binaryData;
    // ファイルのサイズをDWORDとして
    DWORD binarySize;

    if (argc != 2)
        puts("[!] usage: peParser.exe [path/to/exe]");
    else if (readBinFile(argv[1], binaryData, binarySize))
    {
        printf("[+] try to parse PE binary @ %s\n", argv[1]);
        peParser(binaryData);
    }
    else
        puts("[!] read file failure.");

    return 0;
}