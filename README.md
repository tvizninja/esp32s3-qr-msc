# QR Transfer v2.4.6

M5Stack AtomS3 Lite + Atomic QRCode2 Base を、読み取り専用 USB Mass Storage として動作させる QR 転送ファームウェアです。

QR コードの本文を `LATEST.TXT` と `LOG/` へ保存する **Normal モード**と、QRCode2 が読んだ同じ QR を画像から独立に再解析する **Analyzer モード**を備えます。

正式な主対象ホスト OS は Windows です。ファームウェアは ESP-IDF 5.5 系、ESP32-S3 native USB MSC を使用します。

---

## 1. 設計方針

今後の改良では、次の方針を優先します。

### 1.1 Normal モードを製品基準とする

- Normal モードは日常利用の標準動作とする。
- Analyzer の機能追加によって Normal のスキャン速度、安定性、RAM 使用、保存仕様を悪化させない。
- Normal ではカメラ画像取得や quirc による再解析を行わない。

### 1.2 QRCode2 の decode 結果を正とする

- QRCode2 自身が正常 decode した本文を製品データとして保存する。
- Analyzer の画像転送、quirc detect/decode、メタデータ生成に失敗しても、正常に取得済みの QR 本文を失敗扱いにしない。
- Analyzer は検証・診断用の独立した観測経路とする。

### 1.3 Analyzer は速度より解析忠実度を優先する

- Analyzer は処理時間短縮のために解析精度を落とさない。
- scanner native の 640x480 GRAY8 を基準とする。
- JPEG 等の非可逆圧縮を解析経路へ入れない。
- 1st pass は native pixel pitch を維持し、左右 20 px ずつを除いた 600x480 を quirc に入力する。
- 1st pass で検出できても decode できない場合は、検出した QR 周辺を native resolution で再取得して 2nd pass decode を行う。
- 2 回目の画像転送により時間が増えても、Analyzer の目的上は許容する。

### 1.4 保存は commit-last を守る

電源断や途中失敗で不完全データを有効扱いしないため、永続保存は「本文を書いてから最後に有効ヘッダを commit」する方針を維持します。

これは QR 履歴と Analyzer RAW 画像の双方に適用します。

### 1.5 履歴 500 件を製品仕様として維持する

- ユーザーに見せる `LOG/` は最新 500 件。
- Analyzer 用 RAW 領域を確保しても、この可視履歴数は減らさない。
- FAT/Flash 配置を変更する場合は、履歴 500 件と既存データ保護を優先する。

### 1.6 UART は 115200 bps を基準とする

- Normal / Analyzer とも QRCode2 の通常運用 baud は 115200。
- Analyzer の画像転送も 115200 のまま行う。
- 数秒の短縮のために scanner 側の永続 baud 状態を複雑化しない。

### 1.7 Windows の MSC キャッシュ挙動を前提にする

USB MSC は標準仕様を使いますが、ファイル更新通知は Windows の実機挙動を基準にしています。

- USB serial は固定。
- FAT volume serial は固定。
- 更新時に `bcdDevice` を 2 値で切り替える。
- `tud_disconnect()` → detach interval → FAT metadata rebuild → `tud_connect()` を行う。

単純な RAM/FAT 内容変更だけに戻さないことを原則とします。

### 1.8 ビルド再現性を守る

- ESP-IDF / target / flash layout / TinyUSB MSC の必須設定を固定する。
- merged binary は ESP-IDF 自身に生成させ、bootloader 等の offset を Makefile へ二重定義しない。
- `dependencies.lock` は依存解決の再現性のため version control 対象とする。

---

## 2. ハードウェア

- M5Stack AtomS3 Lite
- ESP32-S3
- SPI Flash: 8 MB
- Atomic QRCode2 Base

QRCode2 UART:

- UART1
- 115200 bps
- 8N1
- RX: GPIO5
- TX: GPIO6
- UART RX buffer: 8192 bytes

AtomS3 Lite:

- Button: GPIO41, active low, internal pull-up
- RGB LED: WS2812C-2020, GPIO35

---

## 3. 動作モード

### Normal

通常運用モードです。

QRCode2 が decode した QR 本文を Flash へ保存し、USB MSC 上の `LATEST.TXT` / `LOG/` として公開します。

画像取得や quirc 再解析は行いません。

### Analyzer

診断モードです。

QRCode2 自身の decode が成功した後、Protocol Format 3 の情報と 640x480 RAW image を取得し、AtomS3 Lite 上の quirc でも同じ QR を解析します。

結果は `QRINFO.TXT`、取得画像は `LATEST.BMP` として公開します。

Analyzer は 640x480 RAW を UART 115200 bps で取得するため、Normal より大幅に遅くなります。native crop retry が必要な場合は RAW 転送を 2 回行います。

### モードの永続化

選択モードは NVS に保存され、通常の再起動・電源 OFF/ON では維持されます。

NVS:

- namespace: `qrtransfer`
- key: `an_mode`
- `0`: Normal
- `1`: Analyzer

---

## 4. 起動時ボタン操作

USB 接続時に AtomS3 Lite のボタンを押している時間で保守操作を選択します。

### ボタンを押さずに起動

通常起動します。現在選択されている Normal / Analyzer モードを維持します。

### 3 秒以上、10 秒未満で離す

- QR 履歴を消去する。
- Analyzer モードだった場合は Normal モードへ戻す。
- Normal モードだった場合は Normal のまま。
- 完了時は緑 2 回点滅。

Analyzer の診断終了後は、この操作を標準の「クリーンアップして Normal へ戻る」手順とします。

### 10 秒まで保持する

- 履歴を消去せず Normal / Analyzer を切り替える。
- 選択結果を NVS に保存する。
- Analyzer へ切替: 紫 3 回点滅。
- Normal へ切替: 緑 3 回点滅。

### 長押し中の表示

- 3 秒未満: 赤点滅
- 3 秒以上 10 秒未満: 赤点灯
- 10 秒到達: 紫

Analyzer モードで通常起動した場合は、起動時に紫 2 回点滅して診断モードであることを示します。

---

## 5. 通常操作

### シングルタップ

250 ms のダブルタップ判定後、QR スキャンを開始します。

### 250 ms 以内のダブルタップ

QRCode2 の白色補光を ON/OFF します。

- ON: 水色を短く表示
- OFF: 白を短く表示

### スキャン中

- Atom RGB: 青
- QRCode2 positioning light: 点滅
- 白色補光: 有効時のみ

### 読取成功

- QRCode2 が短い beep を 1 回
- Atom RGB: 緑
- QR 本文を Flash へ commit
- `LATEST.TXT` / `LOG/` を更新
- Analyzer の場合は続けて画像解析を行う
- 最後に MSC を再接続して Windows 側へ更新を通知

### スキャンタイムアウト

- 10 秒
- オレンジ表示後に idle へ戻る

---

## 6. QR 本文仕様

製品として保証する 1 QR あたりの payload は最大 **1500 bytes** です。

内部実装上の最大受信 buffer は 4096 bytes とし、余裕を持たせています。1500 bytes を超える QR が decode できても製品保証外です。

日本語中心の場合、1500 bytes は UTF-8 で概ね 500 文字程度が目安です。

---

## 7. USB MSC 上のファイル

USB drive は読み取り専用です。

### `LATEST.TXT`

現在の電源セッションで最後に正常取得した QR 本文です。

- UTF-8 BOM 付き
- BOM 以降は QR payload byte をそのまま保存
- CRLF 変換なし
- LF は LF のまま

起動時は BOM + ASCII space 1 文字に戻ります。前回までの記録は `LOG/` に残ります。

### `LOG/`

Flash に保存された QR 履歴です。

- 表示上限: 最新 500 件
- filename: `0001.TXT` ～ `9999.TXT`
- 9999 の次は 0000、その次は 0001

### `QRINFO.TXT`

Analyzer で解析結果が生成された場合に表示する JSON ファイルです。

主な内容:

- firmware version / mode
- scanner identity
- Protocol Format 3 request / write reply / readback
- Format 3 framing / CRC 情報
- scanner payload byte 数
- Code ID / symbology
- image width / height / type / byte 数
- 1st / 2nd image transfer time
- quirc detected symbol 数
- QR Version
- ECC level
- Mask pattern
- data type
- ECI
- quirc decoded payload byte 数
- scanner payload との byte 完全一致結果
- QR corner 座標
- crop 情報
- heap / largest contiguous block 診断値
- status / detail

### `LATEST.BMP`

Analyzer で取得・commit 済みの scanner native RAW image を Windows で直接確認できるよう公開するファイルです。

- 640x480
- 8-bit grayscale
- 無圧縮 BMP
- file size: 308278 bytes
- scanner の 307200 byte GRAY8 pixel data を無変換で使用
- 256-entry grayscale palette
- top-down BMP

BMP 化は MSC 上の表現だけです。Analyzer の解析用 pixel data を加工・圧縮しません。

---

## 8. Analyzer 処理

現在の Analyzer は次の順序で処理します。

1. QRCode2 自身の decode を取得する。
2. Protocol Format 3 を使用し、Code ID / framing / CRC を検証する。
3. QR 本文を Flash に commit する。ここまでの scanner decode を製品上の正とする。
4. Analyzer RAW 保存領域を **Image Read command 送信前**に erase する。
5. QRCode2 へ 640x480 RAW image を要求する。
6. image header が 640x480 / RAW GRAY8 / 307200 bytes であることを確認する。
7. 640-byte row を受信しながら native 640x480 RAW を Flash へ保存する。
8. 同時に左右 20 px ずつを除いた中央 600x480 を quirc へ入力する。縮小・補間は行わない。
9. 全 307200 bytes 受信後、RAW header を最後に commit する。
10. quirc で detect / decode する。
11. 1st pass で detect したが decode できなかった場合、corner 周辺に余白を付けた native crop を計算する。
12. crop が安全な連続 RAM サイズ内なら、640x480 RAW を再取得し、必要 crop 部分だけを native resolution で quirc へ渡す。
13. scanner payload と quirc payload を byte 単位で比較する。
14. `QRINFO.TXT` を生成し、MSC を再構築・再接続する。

### RAW erase のタイミング

QRCode2 は image header の直後から 307200 byte の body を連続送信します。

そのため Flash erase は image header 受信後ではなく、**Image Read request の前**に完了させます。image stream 開始後に大きな erase を行うと UART RX ring overflow の原因になります。

### 2nd pass native crop

1st pass は 600x480 の native pixel pitch を使います。

QR を detect できても RAM 制約等で decode できない場合は、保存した corner geometry を使って QR 周辺だけを再取得します。crop buffer は安全余裕のため 240 KiB 以下を上限とします。

Analyzer の目的は診断精度なので、2 回目の転送による待ち時間は許容します。

---

## 9. Protocol Format 3

Analyzer では QRCode2 の Protocol Format 3 を使用します。

- Configuration Write: PID/FID `51/43`, parameter `03`
- Normal では Protocol Format 0 を使用
- Analyzer は Configuration Write Reply と Configuration Read Reply を記録する
- 実際の scan frame について CRC、payload length、Code ID 等を検証する

Protocol envelope は QR 本文として保存しません。`LATEST.TXT` / `LOG/` に保存するのは payload 本体だけです。

Code ID の symbology 対応は、実機で確認した mapping を優先し、他製品の表を無条件に流用しません。

---

## 10. Flash 保存

Partition table:

| Partition | Offset | Size |
|---|---:|---:|
| nvs | 0x9000 | 0x6000 |
| phy_init | 0xF000 | 0x1000 |
| factory | 0x10000 | 0x200000 |
| qrstore | 0x210000 | 0x5F0000 |

`qrstore` record slot:

- 8192 bytes / slot
- header sector: 4096 bytes
- payload sector: 4096 bytes

Analyzer RAW 用として `qrstore` の末尾 40 slot、計 320 KiB を予約しています。

そのため履歴 ring の physical slot は 720 ですが、ユーザーに見せる `LOG/` 上限 500 件は維持します。

### QR record commit

1. slot erase
2. payload write
3. header write

### RAW image commit

1. RAW reserve erase
2. 307200-byte pixel data write
3. RAW header write

header を最後に書くことで、途中電源断した未完成データを valid と判定しないようにします。

---

## 11. Virtual FAT12 / USB

- sector: 512 bytes
- cluster: 1024 bytes
- FAT sectors: 9
- root directory sectors: 2
- root entries: 32
- `LOG/`: cluster 2..17
- `LATEST.TXT`: 5 clusters
- history: 500 logical slots × 5 clusters
- `QRINFO.TXT`: Analyzer metadata 用 4 clusters
- `LATEST.BMP`: 308278-byte BMP に必要な cluster 数を確保

USB identity:

- Manufacturer: `QRTransfer`
- Product: `QR Transfer MSC`
- Serial: `QRTFIXED`
- prototype VID/PID: `0x303A / 0x4002`
- MSC inquiry vendor: `QRDEV`
- MSC inquiry product: `QR TRANSFER`

Windows の filesystem cache refresh のため、正常更新ごとに `bcdDevice` を `0x0101` / `0x0102` で交互に切り替えます。

---

## 12. LED 状態

| 表示 | 意味 |
|---|---|
| 消灯 | Idle |
| 青 | Scanning |
| 緑 | QR 成功 / filesystem 更新 / reconnect guard |
| 紫 | Analyzer mode / Analyzer 処理 / mode 切替 |
| オレンジ | Scan timeout |
| 赤 1 回点滅を反復 | QRCode2 初期化失敗 |
| 赤 2 回点滅を反復 | Flash/history または USB MSC 起動失敗 |
| 赤 3 回点滅 1 set | recoverable scan/save failure |

Analyzer の長い RAW 転送中は、進捗表示を追加 task で持たず、受信 loop から progress hook を呼び出して表示します。Analyzer のためだけに不要な FreeRTOS task / stack を増やさない方針です。

---

## 13. 対応 OS

### Windows

正式対応・主検証対象です。

MSC reconnect/cache refresh の設計は Windows 実機挙動を基準にしています。

### Linux

正式サポート外です。標準 USB MSC/FAT のため動作する可能性はありますが、kernel / distribution / desktop / automount の組み合わせを保証しません。

### macOS

正式サポート外・未検証です。

---

## 14. Build 環境

推奨 Linux host:

- GNU Make
- rootless Docker
- sudo

Host へ ESP-IDF / Python venv / Rust / Cargo / esptool を入れることを前提にしません。

Firmware build:

```bash
make doctor
make image
make build
make config-check
```

ESP-IDF container:

- `espressif/idf:v5.5.5`
- target: `esp32s3`

`make build` 後、ESP-IDF の `idf.py merge-bin -f raw` により次を生成します。

```text
build/qrtransfer-merged.bin
```

bootloader / partition table / application の offset は ESP-IDF に管理させ、Makefile に重複記載しません。

### Flash tool

`espflash v4.5.0` の公式 prebuilt binary を使用します。

```bash
make flash-tool
make flash PORT=/dev/ttyACM0
```

内部では host 上で概ね次を実行します。

```bash
sudo .tools/bin/espflash --skip-update-check \
    write-bin \
    --chip esp32s3 \
    --port /dev/ttyACM0 \
    --baud 460800 \
    0x0 build/qrtransfer-merged.bin
```

Flash 時に Docker から `/dev/ttyACM*` へアクセスさせないことで、rootless Docker の serial device permission 問題を避けます。

Baud override:

```bash
make flash PORT=/dev/ttyACM0 FLASH_BAUD=115200
```

Whole-chip erase は必要な場合だけ実行します。

```bash
make erase-flash PORT=/dev/ttyACM0
```

### Stale sdkconfig

製品必須設定は `sdkconfig.defaults` と `partitions.csv` を基準にします。

古い `sdkconfig` が残っている場合は、誤った 2 MB flash / default partition 構成を使用しないよう build 側で検出します。

```bash
make reset-config
make build
```

### TinyUSB MSC 必須設定

```text
CONFIG_TINYUSB_MSC_ENABLED=y
CONFIG_TINYUSB_MSC_BUFSIZE=512
```

`make config-check` で ESP32-S3、8 MB flash、custom partition、TinyUSB MSC 等の製品必須設定を確認します。

---

## 15. Repository 管理

`.gitignore` では `build/`, `sdkconfig`, `managed_components/`, `.tools/` などの生成物を除外します。

`dependencies.lock` は Component Manager の解決結果を固定するため、生成後は version control に含めることを推奨します。

ドキュメントはこの `README.md` を唯一の現行仕様書とします。

過去版ごとの追記、fix 検証メモ、診断手順の履歴は配布物へ残しません。必要な設計判断は「設計方針」と各現行仕様節へ統合します。

---

## 16. 変更時の確認項目

機能変更後は最低限、次を確認します。

### Normal

1. 通常起動で Normal が維持される。
2. QR を連続して読み、`LATEST.TXT` が常に最新になる。
3. `LOG/` の過去データが保持される。
4. Analyzer 用変更によって通常スキャン時間や USB 更新が退行していない。

### Analyzer

1. 10 秒長押しで履歴を消さず Analyzer へ切り替わる。
2. 再起動しても Analyzer が維持される。
3. Protocol Format 3 が write/readback とも確認できる。
4. 640x480 RAW body 307200 bytes を最後まで受信できる。
5. `LATEST.BMP` が 640x480 8-bit grayscale BMP として Windows で開ける。
6. `QRINFO.TXT` が生成される。
7. quirc 成功時は `status = QUIRC_OK` となる。
8. `payload_match_scanner = true` を確認する。
9. 高密度 QR 等で必要なら native crop retry が動作する。
10. 3 秒以上 10 秒未満の長押しで履歴が消え、Normal へ戻る。

### 障害時

Analyzer が失敗しても、scanner が正常 decode 済みの QR 本文が `LATEST.TXT` / `LOG/` に残ることを最優先で確認します。

---

## 17. 現時点での後続候補

次の項目は、既存の設計原則を崩さない範囲で検討します。

- exact QR segment sequence の解析
- Reed-Solomon corrected error count / block diagnostics
- 画像品質 metric / grading
- Windows の他 PC / hub / adapter での互換性検証
- Analyzer 診断情報の追加

Analyzer の高速化は、**解析精度・native pixel fidelity・Normal の安定性を犠牲にしない方法に限る**ものとします。
