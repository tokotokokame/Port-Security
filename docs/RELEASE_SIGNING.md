# RELEASE_SIGNING（正式署名の設定手順・管理者向け）

v1.2 から、正式リリース（main への push）は**リリース用の署名鍵が必須**です。
Secrets が登録されるまで、main のビルドは失敗し、リリースは公開されません。

> 秘密鍵とパスワードはリポジトリに登録しないでください。この手順で作るファイル（`*.jks`）は `.gitignore` で除外しています。

## 暫定措置（Secrets 登録まで）

`.github/workflows/android.yml` の `ALLOW_DEBUG_RELEASE: "true"` により、Secrets 未登録の間は main でも
**デバッグ署名のまま公開**します（リリース名に「デバッグ署名・暫定」と付きます。更新時はアンインストールが必要）。
Secrets を登録すると自動で正式署名に切り替わります。登録後は値を `"false"` に戻し、
Secrets が消えた場合に main のビルドが失敗する状態へ戻してください。

## 1. 鍵の作成（管理者の PC で 1 回だけ）

```bash
keytool -genkeypair -v -keystore port-security-release.jks -storetype PKCS12 \
  -alias port-security -keyalg RSA -keysize 4096 -validity 10000 \
  -dname "CN=Port Security, O=tokotokokame"
```

- パスワードはパスワードマネージャーなどに保管してください。**鍵を失うと、同じアプリとして更新できなくなります。**
- `.jks` はリポジトリの外（バックアップ先を含む安全な場所）に保管します。

## 2. GitHub Secrets への登録

リポジトリの Settings → Secrets and variables → Actions に 4 つ登録します（`gh` を使う場合）。

```bash
base64 -w0 port-security-release.jks | gh secret set ANDROID_KEYSTORE_BASE64
gh secret set ANDROID_KEYSTORE_PASSWORD   # 鍵ストアのパスワード
gh secret set ANDROID_KEY_ALIAS --body port-security
gh secret set ANDROID_KEY_PASSWORD        # 鍵のパスワード（PKCS12 では鍵ストアと同じ）
```

## 3. 証明書の指紋の固定

```bash
keytool -list -v -keystore port-security-release.jks -alias port-security | grep 'SHA256:'
```

表示された値をコロンなしの小文字 64 桁にして `docs/signing/release-cert.sha256` の 1 行目に書き、コミットします（公開してよい情報です）。

```bash
keytool -list -v -keystore port-security-release.jks -alias port-security \
  | sed -n 's/.*SHA256: //p' | tr -d ':' | tr 'A-F' 'a-f' > docs/signing/release-cert.sha256
```

以降の CI は、APK の証明書がこの値と一致しなければ失敗します（`tools/check_signing.py`）。

## 4. 確認

- main のビルドの `Signing certificate check` で `signing=release pinned=yes` と表示されること
- リリースの説明に載る「署名証明書 SHA-256」が `docs/signing/release-cert.sha256` と同じであること
- 手元で確認する場合: `apksigner verify --print-certs port-security-*.apk`（`CN=Android Debug` でないこと）

## 5. 利用者への案内

v1.0.31 以前の APK はデバッグ鍵（ビルドごとに異なる鍵）で署名されています。
正式署名の最初のリリースへ更新するときは、**一度アンインストールしてから**インストールしてください（README の「アップデート」に記載）。
