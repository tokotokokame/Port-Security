# RELEASE_CHECKLIST — リリース手順

機械で判定できる項目は CI が止めます。人が確認するのは「CI では分からないこと」だけです。

## 1. 自動（CI が失敗したらマージ・リリースしない）

| 項目 | 実行場所 | 合格条件 |
|---|---|---|
| 参照整合性 | validate.yml / android.yml: `tools/validate.py` | errors=0 |
| 品質基準 Q-JSON〜Q-COUNT | 同: `tools/quality.py` | errors=0（info は Phase 4 対象の記録） |
| 不正データ注入テスト | validate.yml: `unittest discover -s tools` | 全件成功 |
| 生成物の一致 | validate.yml: `git diff --exit-code` | スキーマ・仕様・各レポート・アプリ用データがコミット済み |
| 静的解析・アプリテスト | android.yml: `flutter analyze` / `flutter test` | 指摘 0・全件成功 |
| APK 点検 | android.yml: `tools/check_manifest.py` | 権限・exported・バックアップ・デバッグ・平文通信 PASS |

## 2. 人が確認する

- [ ] `docs/DATA_CHANGELOG.md` に今回の変更（追加・修正・削除した ID と理由）がある
- [ ] 確認済みに上げたレコードは、出典の本文を自分で確認した（`verified_via` に確認した原文）
- [ ] 新しい出典の `access_date` が確認した日になっている
- [ ] `docs/VALIDATION_REPORT.md` の件数が想定どおり（意図しない減少がない）
- [ ] `docs/MITRE_VALIDATION_REPORT.md` の「存在しない / 廃止 / 名称不一致」が 0 件
- [ ] `docs/CVE_VALIDATION_REPORT.md` の各 CVE に該当条件がある
- [ ] 直近の data-freshness が成功している（失敗していれば一次データを更新してから）
- [ ] 実機で起動し、検索・ポート詳細（概要 / att&ck / src）・CVE 画面を開ける

## 3. 公開

1. PR を main にマージする
2. android.yml が `v1.0.<run>` として Releases に APK と SHA256SUMS を公開する
3. Releases のノートに `DATA_CHANGELOG.md` の該当節へのリンクを追記する
