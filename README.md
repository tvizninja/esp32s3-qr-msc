# QRTransfer firmware 2.4.6

AtomS3 Lite + M5Stack Atomic QRCode2 Base を USB MSC デバイスとして使用し、scanner が読み取ったコードをファイルとして取得し、Analyzer モードでは scanner-native image を独立解析する firmware です。

この README は変更履歴ではなく、**現時点で確認できている仕様・実測結果・設計方針・今後の判断基準**を記録します。

## 設計原則

- **Normal モードを製品基準**とし、Analyzer の追加機能で通常読取・履歴・USB MSC の安定性を悪化させない。
- 本文の一次情報は **QRCode2 scanner 自身の decode result** とする。Analyzer 側が失敗しても scanner が読めた raw payload は失わない。
- 履歴は commit-last で更新し、不完全なデータを最新結果として公開しない。
- QRCode2 の UART は Normal / Analyzer とも **115200 baud** を基準とする。
- Analyzer は速度より診断忠実度を優先する。ただし 640x480 GRAY8 全体を heap に保持しない。
- barcode detection / geometry / perspective correction / ECC / Reed-Solomon / payload decode は **ZXing-C++ 等の成熟した既存実装**へ任せる。独自 detector のパラメータ調整へ寄らない。
- 独自に工夫する範囲は Flash streaming、二値化、packed 1bpp、必要に応じた縮小/RLE 等の**データ表現とメモリ節約**までとする。

## 現在の結論: Analyzer の主系は ZXing-C++ へ

現在の実機評価では、将来の Analyzer は **ZXing-C++ のみを解析 engine とし、quirc は削除する方針**です。

### ZXing-C++ packed 1bpp の実測

- scanner-native 640x480 の空間解像度を維持したまま、binary input を **307200 bytes -> 38400 bytes** に削減できた。
- ESP32-S3 実機で packed 1bpp を ZXing QR detector / perspective sampler / Reed-Solomon / decoder へ直接入力し、scanner payload と byte 単位一致する decode を確認した。
- Global Otsu / Compact Hybrid の双方で decode 成功を確認した。
- Compact Hybrid は ZXing-C++ `HybridBinarizer` の local-threshold 方針を参考にし、8x8 block / local dynamic range / 5x5 threshold smoothing を使用する。
- 実機例では ZXing packed decode は約 100--115 ms。二値化を含めても scanner RAW 転送時間約 27 s に対して小さい。
- version / ECC / mask / segment mode / ECI / Structured Append / format information / corners / symbology identifier / UEC / decode error など Analyzer 向け metadata が豊富。
- PC の stress test では、同一 Compact Hybrid binary image に対する stock byte matrix と packed matrix で decode 成否差は観測されなかった。

### quirc の評価と将来の削除

quirc は QR 専用・C 実装・依存が軽いという利点があり、320x240 GRAY8 resolution ladder は実機で安定しています。ただし native VGA では 1 pixel = 1 byte の contiguous RAM 要求が大きく、metadata と多形式拡張性も ZXing より限定されます。

現在の比較結果では ZXing packed の利点が大きいため、**将来版では Analyzer から quirc を削除**します。削除時には以下を確認します。

- 十分な実画像 corpus で ZXing-Hybrid が継続して安定すること。
- firmware image size / heap / largest block / stack が許容範囲であること。
- crash diagnostics と error metadata が quirc なしでも十分であること。

## QRCode2 scanner の対応形式と将来 architecture

M5Stack Atomic QRCode2 Base の製品仕様では、scanner 本体は次を読み取れます。

### 2D

- QR Code
- Data Matrix
- PDF417

### 1D

- Code11
- Code39
- Code93
- Code128
- EAN-13
- EAN-8
- UPC-A
- UPC-E
- Codabar
- Interleaved 2 of 5
- Matrix 2 of 5
- Industrial 2 of 5
- MSI
- GS1

scanner protocol Format 3 は payload と Code ID を返すため、symbology 名の判定とは独立に raw payload を保持できます。

### Normal モードの目標

**QRCode2 scanner が製品仕様上対応する形式は、すべて Normal モードで保存可能にする**方針です。

Normal では画像再解析を行わず、scanner の decode result を正とします。そのため、多形式対応で最も重要なのは decoder 追加ではなく次です。

- Code ID -> symbology name の正式 mapping
- text / binary / encoding を壊さない raw byte 保存
- LATEST / LOG のファイル形式設計
- 1 scan に複数 barcode が含まれる場合の表現

現在の Format 3 parser は `barcode_count` を読めますが、product path は先頭 1 件のみを保持し、Analyzer 経路では安全のため `barcode_count != 1` を拒否しています。**複数 barcode 同時読取は別仕様として設計する必要があります。**

将来の Normal 用ファイル名・本文形式は未確定です。`.TXT` のみへ raw bytes を直接押し込むと NUL / binary / encoding で扱いにくいため、表示用 text と raw bytes、metadata の分離も検討します。

### Analyzer モードの目標

Analyzer では **QRCode2 と ZXing-C++ の両方が対応する symbology**について、scanner result と image decode result を比較し、詳細 metadata を `INFO.TXT` に出力する方針です。

将来 `QRINFO.TXT` は **`INFO.TXT`** へ改名します。内容 schema は multi-symbology を前提に今後整理します。

現行 ZXing-C++ upstream の対応形式のうち QRCode2 と明確に重なるものは、おおむね次です。

- QR Code
- Data Matrix
- PDF417
- Code39
- Code93
- Code128
- EAN-13 / EAN-8
- UPC-A / UPC-E
- Codabar
- Interleaved 2 of 5
- GS1 DataBar 系は scanner 側の `GS1` 定義・Code ID を確認した上で対応判断する

QRCode2 が対応する一方、現行 ZXing-C++ の公式対応一覧に明示されない **Code11 / Matrix 2 of 5 / Industrial 2 of 5 / MSI** は、Analyzer の独立画像 decode 対象には現時点で含めません。Normal では scanner result を保存できます。

ZXing-C++ はさらに Aztec / Micro QR / rMQR / MaxiCode 等も持ちますが、QRCode2 製品仕様との共通集合ではない形式を Analyzer の主目的にはしません。

## packed 1bpp を他形式へ使えるか

**見通しは良いが、symbology ごとの検証が必要**です。

今回 QR では、GRAY8 から binary image へ変換した後の ZXing detector/decoder に packed 1bpp view を渡せることを実証しました。一般に barcode reader は二値化後の画像を使うため、同じ考え方を Data Matrix / PDF417 / 1D readers へ展開できる可能性は高いです。

ただし以下は形式ごとに確認します。

- ZXing reader が `BitMatrix` / row access をどのように使用するか。
- packed view 用 accessor だけで済むか、byte-contiguous row を前提にした高速経路があるか。
- Compact Hybrid の local threshold がその symbology に適するか。
- 1D は細い bar/space 幅を保持する必要があり、binary threshold と row sampling の影響を評価する。
- PDF417 / Data Matrix は detector / perspective / alignment の追加 work memory を測る。
- reader を追加した際の firmware text size、heap、largest block、task stack を実機で測る。

したがって、**QR で成功した 38.4KB packed input をそのまま全形式へ適用できるとは仮定しません。** QR と同じ「画像コンテナを compact 化し、decode algorithm は upstream ZXing のまま」という原則で個別評価します。

## Raw payload と metadata

scanner が返した raw payload は、encoding に依存せず保存します。Analyzer metadata では raw payload の HEX 表記を保持し、NUL / non-UTF-8 / ECI / Kanji / binary byte mode 等で情報を失わないようにします。

現行 `QRINFO.TXT` では `scanner_metadata.payload_hex` を一次 raw record とします。ZXing payload が scanner と byte 一致した場合は、decoder block にも一致を明示します。不一致時に scanner payload を ZXing output と偽装しません。

将来の `INFO.TXT` では少なくとも次を symbology 共通項目として検討します。

- scanner Code ID / symbology
- raw payload length / HEX
- text representation（安全に表現できる場合のみ）
- scanner / ZXing payload match
- image size / binarizer / threshold statistics
- position / orientation
- decode status / error type
- symbology 固有 metadata

## 現行 Analyzer の処理

現行実験版では QR Code に対して次を実行します。

1. QRCode2 Format 3 metadata と scanner payload を取得。
2. scanner-native 640x480 GRAY8 / 307200 bytes を 1 回取得して Flash へ commit。
3. Global Otsu packed 1bpp (38400 bytes) を生成し ZXing QR で解析。
4. 同じ RAW から Compact Hybrid packed 1bpp を生成し ZXing QR で解析。
5. 現行比較用として quirc 320x240 -> 480x360 ladder も実行。
6. scanner / ZXing / quirc payload を byte 単位で比較。

将来版では 5 の quirc 経路を削除し、Analyzer は ZXing 系のみへ整理します。

Analyzer 実行中は約 0.5 秒周期で緑 / 紫を交互表示し、データ処理・解析が継続中であることを示します。 LED heartbeat は decoder / Flash loop の hook 頻度に依存せず、独立した `esp_timer` で駆動します。

## RAM / performance の考え方

- Scanner RAW 307200 bytes は Flash に置き、VGA 全体を heap に保持しない。
- packed 1bpp は 640x480 = 38400 bytes。
- ZXing decode の間だけ 38.4KB を RAM に読み、終了後に解放する。
- Compact Hybrid の threshold/work buffer は Analyzer 専用領域として保持する。
- Normal モードでは Analyzer 画像処理を実行しない。
- Analyzer stack は実測 high-water mark を確認しながら将来縮小する。

## USB MSC ファイル

### 現行

- `LATEST.TXT`: 最新 scanner payload。
- `QRINFO.TXT`: Analyzer metadata JSON。
- `LATEST.BMP`: scanner-native 640x480 8-bit grayscale BMP。
- `DEBUG.TXT`: reset reason と Analyzer breadcrumb。
- `LOG/`: 履歴。可視履歴数 500 件。

### Analyzer JSON / MSC capacity

- `ANALYZER_JSON_MAX` は 32768 bytes。
- `QRINFO.TXT` の FAT cluster chain も同じ 32768 bytes を収容できるよう割り当てる。
- JSON生成結果が上限を超えた場合は途中で切断したJSONを公開せず、`JSON_CAPACITY_EXCEEDED` の有効な小さいJSONを公開する。
- payload HEX や metadata の増加で report size が将来拡大する場合は、この上限を schema と合わせて再評価する。

### 将来

- `QRINFO.TXT` -> **`INFO.TXT`** に改名する。
- `LATEST.TXT` / raw binary / metadata の分離方法は multi-symbology の要件を踏まえて再設計する。
- ファイル schema は backward compatibility と Windows での扱いやすさを含めて決定する。

## Build warning / toolchain compatibility

ESP32 toolchain で vendored ZXing `Utf.cpp` に次の warning が出ることを確認しました。

```text
warning: comparison is always true due to limited range of data type [-Wtype-limits]
```

これは 16-bit `wchar_t` toolchain でも 32-bit `wchar_t` 向け比較をコンパイラが診断するためです。本枝では `WCHAR_MAX` による preprocessor 分岐で 16-bit / 32-bit `wchar_t` のコード自体を分離しています。host GCC で `-Wtype-limits` を有効にして `Utf.cpp` warning 0 を確認しています。UTF の挙動は変更しません。

## Crash diagnostics

Analyzer の段階情報は NVS / RTC breadcrumb として残し、次回起動時に `DEBUG.TXT` として公開します。USB MSC と同じ USB 経路を serial monitor として使用することは前提にしません。

主な確認項目:

- `reset_reason_name`
- `stage_name`
- `free_8bit`
- `largest_8bit`

## Third-party software / ZXing-C++ attribution

Analyzer の image decoder には **ZXing-C++** の一部を使用しています。ZXing-C++ は Apache License 2.0 で提供されています。

- Upstream project: `zxing-cpp/zxing-cpp`
- Upstream source used for this work: supplied master snapshot, project version 3.1.1
- License: Apache License, Version 2.0
- License text: `components/zxing_qr_packed/LICENSE`
- Vendored source: `components/zxing_qr_packed/zxing/core/src/`

上流ソースの copyright / SPDX 表示は保持します。QRTransfer で改変したファイルには変更通知を残します。現行変更は packed 1bpp read-only input view、packed input 用 row/cursor fallback、Analyzer telemetry、および ESP32 16-bit `wchar_t` toolchain warning 回避です。

ZXing の detector / candidate selection / perspective sampling / version/mask解析 / Reed-Solomon / payload decode の判断アルゴリズム自体は改変しない方針です。

共有された上流ソースに独立した `NOTICE` ファイルは無かったため、Apache-2.0 section 4(d) に基づいて複製すべき upstream NOTICE はありません。ライセンス全文、既存 copyright / SPDX、変更通知を保持します。

## 今後の優先順位

1. **Normal:** QRCode2 対応 symbology 全体を scanner result として安全に保存する。
2. scanner Code ID の正式 mapping を実装し、UNKNOWN を減らす。
3. multi-barcode Format 3 packet の保存仕様を決める。
4. **Analyzer:** quirc を削除し ZXing-only architecture に整理する。
5. `QRINFO.TXT` を `INFO.TXT` へ改名し、multi-symbology metadata schema を設計する。
6. Data Matrix -> PDF417 -> 主要 1D の順で ZXing reader を追加評価する。
7. 各 reader で Compact Hybrid / packed 1bpp の精度、code size、heap、stack、速度を測る。
8. scanner と ZXing の共通対応形式で raw payload / metadata を比較する corpus を蓄積する。

## ビルド

プロジェクトルートで:

```sh
make build
```

source variant:

```text
SOURCE_VARIANT: qrtransfer_v2_4_6_zxing_fix_exp31
```
