# QRTransfer firmware 2.4.6

AtomS3 Lite + QRCode2 を USB MSC デバイスとして使用し、読み取った QR コードを Windows などからファイルとして取得するファームウェアです。

## 設計方針

- **Normal モードを製品基準とする。** Analyzer の追加機能で通常スキャン、履歴、USB 更新の安定性を悪化させない。
- QR 本文の一次情報は **QRCode2 自身の decode 結果**とする。Scanner decode が成功した本文は Analyzer 側が失敗しても失わない。
- 履歴は commit-last で更新し、不完全な結果を最新データとして公開しない。
- QRCode2 の通常 baud は Normal / Analyzer とも **115200** を維持する。
- Analyzer は速度より診断忠実度を優先する。ただし大きな VGA 画像を heap に保持することは避ける。
- **QR 検出・姿勢推定・perspective 補正・ECC・Reed-Solomon・payload decode は既存の quirc に任せる。** Finder pattern や QR 幾何処理を独自実装して最適化しない。
- 独自に工夫する範囲は、Flash 保存、ストリーム縮小、二値化、1bpp/RLE などのデータ表現・メモリ節約までとする。

## モード

### Normal

QRCode2 の decode 結果を保存する通常運用モードです。画像再解析は行いません。

### Analyzer

QRCode2 が読んだ同じ QR について Protocol Format 3 metadata と scanner-native 640x480 GRAY8 image を取得し、quirc でも独立に再解析します。

モードは NVS に保存され、通常の再起動や電源再投入では維持されます。

- 起動時 3 秒以上 10 秒未満の長押し: 履歴・診断ファイルをクリアし、Analyzer なら Normal へ戻る。
- 起動時 10 秒長押し: 履歴を消さず Normal / Analyzer を切り替える。

Analyzer 実行中は緑と紫を交互に表示し、処理が継続していることを示します。

## USB MSC の主なファイル

- `LATEST.TXT`: 最新 QR 本文。
- `QRINFO.TXT`: Analyzer metadata JSON。
- `LATEST.BMP`: Analyzer が取得・commit した scanner-native 640x480 8-bit grayscale BMP。無圧縮で、画素値は scanner RAW と同一。
- `DEBUG.TXT`: reset reason と前回 Analyzer breadcrumb。panic / WDT などの診断用。
- `LOG/`: QR 履歴。可視履歴数は 500 件を維持する。

## Analyzer 画像処理

現在の Analyzer は次の順序で動作します。

1. QRCode2 の Protocol Format 3 情報と scanner decode payload を取得する。
2. scanner-native **640x480 GRAY8 / 307200 bytes** を UART 115200 で 1 回取得し、行単位で専用 Flash 領域へ commit する。
3. 診断用として Flash RAW を 2-pass 走査し、Otsu threshold と packed 1bpp を生成する。1bpp は 640x480 で **38400 bytes**。QR 判定には使用しない。
4. UART RX ring を解放してから、Flash RAW から **320x240 GRAY8** を生成して stock quirc へ渡す。
5. 320x240 で decode できなければ、Flash RAW から **480x360 GRAY8** を生成して stock quirc へ渡す。
6. 480x360 で QR geometry は検出できたが decode できない場合のみ、quirc が返した native 座標 corners から QR 周辺 crop を求め、scanner から native-resolution crop を再取得して stock quirc で retry する。
7. quirc payload と scanner payload を byte 単位で比較する。

この resolution ladder により、以前の 600x480 = 288000-byte contiguous quirc image は使用しません。

### RAM の考え方

- Scanner RAW 307200 bytes は Flash に置き、VGA 全体を heap に保持しない。
- 320x240 quirc image: 76800 bytes。
- 480x360 quirc image: 172800 bytes。
- packed 1bpp diagnostic: 38400 bytes。Flash 上に生成する。
- Normal モードでは Analyzer 用画像 buffer を確保しない。

### 1bpp / RLE の位置づけ

1bpp 化はデータ量を 307200 → 38400 bytes に減らせるため、診断保存・PC 比較・将来の decoder 評価には有用です。ただし現行の QR detection/decode を自前 1bpp engine に置き換える目的では使用しません。

RLE も保存・転送量削減の実験対象にはできますが、QR decoder のランダムアクセスを RLE 前提に改造することは避けます。

## Analyzer JSON で見る項目

主に以下を確認します。

- `scanner_metadata.payload_bytes`
- `qr_metadata.status`
- `qr_metadata.analysis_width` / `analysis_height`
- `qr_metadata.detected_symbols`
- `qr_metadata.version` / `ecc` / `mask`
- `qr_metadata.decoded_payload_bytes`
- `qr_metadata.payload_match_scanner`
- `qr_metadata.binary_probe`
- `qr_metadata.transfer_ms` / `second_transfer_ms`

成功時は `status = QUIRC_OK` かつ `payload_match_scanner = true` が基準です。

## Crash diagnostics

Analyzer の段階情報は NVS に breadcrumb として保存し、次回起動時に `DEBUG.TXT` として公開します。USB MSC と同じ USB 経路を monitor 用 serial console として使用することは前提にしません。

`DEBUG.TXT` では特に次を確認します。

- `reset_reason_name`
- `stage_name`
- `free_8bit`
- `largest_8bit`

## ビルド

プロジェクトルートで既存 Makefile を使用します。

```sh
make build
```

ビルド開始時に source variant が表示されます。

```text
SOURCE_VARIANT: qrtransfer_v2_4_6_stable_analyzer
```

## 今後の改良軸

優先順位は次の通りです。

1. Normal モードの安定性と既存仕様を守る。
2. Analyzer では scanner-native RAW を必ず基準データとして残す。
3. メモリ削減は Flash streaming、縮小、1bpp、必要なら RLE で行う。
4. QR detection/decode のアルゴリズム自体は quirc / ZXing / ZBar 等の成熟した既存実装を比較して採用し、自前パラメータ調整へ寄らない。
5. 別 decoder を試す場合は Analyzer に限定し、scanner decode と同一画像で比較する。
