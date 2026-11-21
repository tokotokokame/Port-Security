# DATA_CHANGELOG — データ変更履歴

データ（`data/`）の追加・変更・削除をレコード単位で記録する。
Phase 0 基準（`docs/baseline/DATA_INVENTORY.json`）にある ID を削除・改名する場合は、**その ID と理由をここに書かないと CI が失敗する**（Q-COUNT）。

## v1.1（2026-11-22）

### Phase 0
- 基準スナップショットを作成（`main` @ `652af77`、825 レコード）。データの変更なし。
- `data/raw/mitre/attack_catalog.json` を追加（ATT&CK v20.1 公式 STIX から ID・名称・廃止状態を抽出）。
