# PE Patcher

## 説明

- 悪意のないEXEファイルに、悪意のあるシェルコードを含んだセクションを挿入する。
- 挿入したシェルコードから実行されるよう、プログラムのエントリポイントを変更する。
- そのほか、をセクション挿入後の状態を示すようにPEヘッダ各所を修正する。

## 使い方

```
.\pe_patcher.exe  .\xxx.exe

.\xxx_infected.exe
```

## 参考

https://github.com/PacktPublishing/Windows-APT-Warfare