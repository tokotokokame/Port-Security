# TEST_REPORT — v1.1 試験結果

- 対象ブランチ: `feature/v1.1-quality`（PR #5）
- 実施日: 2026-11-22
- 判定: **合格**（未実施の項目は「未実施」と明記）

## 1. データ検証（ローカル実行の出力）

| コマンド | 結果 |
|---|---|
| `python3 tools/validate.py data` | `841 records / errors=0 warnings=0 -> PASS` |
| `python3 tools/quality.py` | `quality: errors=0 info=2 -> PASS`（info は Phase 4 対象の FortiGate / NEC IX） |
| `python3 -m unittest discover -s tools` | `Ran 42 tests … OK`（test_validate 17 件 + test_quality 25 件） |
| `python3 tools/make_schemas.py && python3 tools/build_index.py` | 生成物の差分なし |

### 品質基準ごとの結果（Phase 0 基準 → v1.1）

| コード | Phase 0 | v1.1 | 主な対応 |
|---|---|---|---|
| Q-JSON | 0 | 0 | — |
| Q-SCHEMA | 1（未整備） | 0 | 12 スキーマを整備、全レコード適合 |
| Q-DUP | 0 | 0 | — |
| Q-ATTACK | 0 | 0 | 公式 STIX v20.1 と照合（本文中の ID を含む） |
| Q-TRANSPORT | 30 | 0 | DET 監視ポートを (番号, 通信方式) に、サービスのポートを通信方式付きに |
| Q-IPPROTO | 7 | 0 | IP プロトコル番号・階層を分離し、IANA Protocol Numbers と照合 |
| Q-IANA | （v1.1 で追加） | 0 | service_name を IANA 登録名に（10 件修正） |
| Q-VERIFIED | 20 | 0 | 確認済みポート 20 件に根拠を付与 |
| Q-SRC | 13 | 0 | 出典 18 件を再確認（引用の付け替え・削除 3 件、URL 修正 1 件） |
| Q-HIDDEN | 5 | 0 | アプリ用データ・画面に確度・確認日・未確認事項 |
| Q-ASSOC | 10 | 0 | 全 271 件に関連区分と経路 |
| Q-CVE | 6 | 0 | 7 件を公式 CVE レコード・KEV から構造化 |
| Q-COUNT | （v1.1 で追加） | 0 | Phase 0 の ID はすべて維持（削除なし） |

## 2. CI（GitHub Actions）

| ジョブ | 内容 | 結果 |
|---|---|---|
| validate（PR） | validate / quality / 注入テスト / 生成物の一致 | 成功 [job](https://github.com/tokotokokame/Port-Security/actions/runs/44955697637/job/137003158624) |
| build（push / PR） | 品質ゲート → flutter analyze → flutter test（33 件）→ APK ビルド → APK 点検 | 成功 [push](https://github.com/tokotokokame/Port-Security/actions/runs/44955692830/job/137003219847) / [PR](https://github.com/tokotokokame/Port-Security/actions/runs/44955697647/job/137003241495) |
| refresh-iana | IANA Protocol Numbers 台帳の取得（commit 7a2d204） | 成功 |

flutter test の件数（33 件）はテストコード上の件数。CI のジョブは 1 件でも失敗すると失敗になるため、成功は全件合格を意味する。

## 3. 不正データを混入させた CI 試験（Phase 6 の完了条件）

一時ブランチ `feature/ci-negative-check` に 2 種類の不正を入れて push した（マージしない）。

- DET0118/AN0329 の監視ポートに通信方式なしの `443`
- SRC-NMAP の確認状態を未定義値 `未再検証` に

| 回 | 結果 | 内容 |
|---|---|---|
| 1 回目 | 失敗（[job](https://github.com/tokotokokame/Port-Security/actions/runs/44955569674/job/137002767187)） | ゲートは止まったが、`validate.py` が TypeError で異常終了し原因が読めなかった → 修正（不正な形を違反として報告、両検査を必ず実行、GitHub 注釈を出力） |
| 2 回目 | 失敗（[job](https://github.com/tokotokokame/Port-Security/actions/runs/44955695512/job/137003151391)） | 注釈に 6 件の違反を表示: Q-SRC ×2、Q-TRANSPORT、Q-SCHEMA ×2、validate（(番号, 通信方式) の形でない） |

## 4. 鮮度チェック

| 対象 | 結果 |
|---|---|
| ATT&CK | 最新版 v20.1 = 収録版（attack-stix-data の index.json） |
| CISA KEV | catalog 2026.11.20。対象 7 件の掲載状況に変化なし |
| CVE レコード | 7 件とも dateUpdated に変化なし |
| IANA | 作業環境からは iana.org に接続できないため **未実施**（週次の freshness.yml で実施） |
| 出典 URL の到達確認 | **未実施**（freshness.yml の `--links` で週次に参考表示） |

## 5. 試験中に見つかった不具合

| 不具合 | 発見方法 | 対応 |
|---|---|---|
| `quality.check_cve` の変数名衝突（本文のみの CVE があると例外終了） | test_quality の注入テスト | 変数名を変更 |
| `validate.py` が不正な形の監視ポートで例外終了 | CI の注入試験 1 回目 | 違反として報告するよう修正、テスト追加 |

## 6. 実機確認

**未実施**。マージ後の Releases の APK で、検索・ポート詳細（概要の cve / att&ck の関連区分 / src の review）・CVE 画面を確認する（`RELEASE_CHECKLIST.md`）。
