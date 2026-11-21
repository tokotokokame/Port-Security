# Port Security（Android アプリ）

`assets/data/` の `ports.json` / `kb.json` / `iana.json`（リポジトリ直下の `tools/build_index.py` が生成）を同梱した、オフラインのポート検索アプリです。

## 開発

```bash
flutter pub get
flutter analyze
flutter test
flutter build apk --release
```

データを更新するときは、リポジトリ直下で `python3 tools/build_index.py` を実行してください。アプリ同梱データも同時に再生成されます。

## 署名

リリース用の署名鍵は GitHub Secrets から読み込みます（`ANDROID_KEYSTORE_BASE64` / `ANDROID_KEYSTORE_PASSWORD` / `ANDROID_KEY_ALIAS` / `ANDROID_KEY_PASSWORD`）。Secrets が未設定の場合はデバッグ鍵で署名されるため、更新時には一度アンインストールが必要です。
