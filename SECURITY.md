# SECURITY

## 設計方針

- データはアプリに同梱し、**通信は行いません**。リリース APK に `INTERNET` 権限はありません。
- 外部リンクは `https` のみを許可し、外部ブラウザで開きます。それ以外のスキームは開きません。開けない場合は URL をコピーします。
- 利用者データを保存・送信しません。バックアップは無効です（`allowBackup="false"`）。
- 攻撃コードや攻撃手順は含みません。教育・防御目的の参照データです。

## リリース前の自動点検（`.github/workflows/android.yml`）

| 点検 | 内容 |
|---|---|
| `flutter analyze` | 静的解析で指摘が0件であること |
| `flutter test` | 検索・データ読込・異常データ耐性・画面遷移・下部インセット |
| データ同期 | アプリ同梱データが `dist/` と一致すること |
| `tools/check_manifest.py` | 権限、exported コンポーネント、allowBackup、debuggable、平文通信 |

外部公開（exported）が許されるのは、起動用の `MainActivity` と、権限で保護されたコンポーネントだけです。

## 署名

- リリース鍵は管理者が作成し、GitHub Secrets（`ANDROID_KEYSTORE_BASE64` / `ANDROID_KEYSTORE_PASSWORD` / `ANDROID_KEY_ALIAS` / `ANDROID_KEY_PASSWORD`）にだけ置きます。リポジトリにはコミットしません（`.gitignore` で `*.jks` / `*.keystore` を除外）。手順は [docs/RELEASE_SIGNING.md](docs/RELEASE_SIGNING.md)。
- **main（正式リリース）では Secrets が 1 つでも欠けているとビルドが失敗し、リリースしません。** Gradle も `REQUIRE_RELEASE_SIGNING=1` のときは鍵がなければ失敗します。デバッグ鍵での署名は PR・feature ブランチの検証用だけで、その APK は公開しません。
- ビルド後に `tools/check_signing.py` が `apksigner` の結果を検査します（デバッグ証明書の拒否、APK 間の証明書の一致、`docs/signing/release-cert.sha256` に固定した証明書との一致）。
- v1.0.31 以前はデバッグ鍵で署名されていました（ビルドごとに異なる鍵）。正式署名の最初のリリースへ更新するときは一度アンインストールが必要です。

## 脆弱性の報告

GitHub の Issues ではなく、リポジトリ所有者へ直接ご連絡ください。
