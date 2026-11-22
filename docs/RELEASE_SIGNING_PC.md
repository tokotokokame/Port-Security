# 正式署名の設定手順（Parrot OS / PC 版）

`docs/RELEASE_SIGNING.md` の PC 向け実行手順です。main のビルドが
「正式署名の Secrets が未登録」で失敗しているときに実施します。

> 鍵（`*.jks`）とパスワードは Git に入れないでください。`.jks` は `.gitignore` で除外済みです。

## 0. 準備（初回のみ）

```bash
sudo apt update
sudo apt install -y default-jre-headless gh git
keytool -help | head -3     # 表示されれば OK
gh auth login               # GitHub.com → HTTPS → ブラウザで認証
```

## 1. 鍵を作る（1 回だけ）

鍵はリポジトリの外に置きます。

```bash
mkdir -p ~/secure && chmod 700 ~/secure && cd ~/secure
keytool -genkeypair -v -keystore port-security-release.jks -storetype PKCS12 \
  -alias port-security -keyalg RSA -keysize 4096 -validity 10000 \
  -dname "CN=Port Security, O=tokotokokame"
chmod 600 port-security-release.jks
```

- パスワードを 2 回聞かれます（入力は表示されません）。**必ずパスワードマネージャー等に保管してください。**
- PKCS12 では、鍵のパスワードは鍵ストアのパスワードと同じです。

## 2. GitHub Secrets に 4 つ登録する

```bash
cd ~/secure
R=tokotokokame/Port-Security
base64 -w0 port-security-release.jks | gh secret set ANDROID_KEYSTORE_BASE64 -R $R
gh secret set ANDROID_KEYSTORE_PASSWORD -R $R          # 1 で決めたパスワードを入力
gh secret set ANDROID_KEY_ALIAS -R $R --body port-security
gh secret set ANDROID_KEY_PASSWORD -R $R               # 同じパスワードを入力
gh secret list -R $R                                   # 4 つ並べば OK
```

`gh` を使わない場合は、ブラウザで
`https://github.com/tokotokokame/Port-Security/settings/secrets/actions` を開き、
同じ名前で 4 つ登録します（`base64 -w0 port-security-release.jks` の出力が `ANDROID_KEYSTORE_BASE64` の値です）。

## 3. ビルドをやり直す

```bash
gh run list -R $R --branch main --limit 3
gh run rerun <失敗した run の ID> -R $R
gh run watch <run の ID> -R $R
```

## 4. 確認

ビルドの「Signing certificate check」に `signing=release` と表示されること。

## 4b. 暫定措置を解除する

`.github/workflows/android.yml` の `ALLOW_DEBUG_RELEASE: "true"` を `"false"` に変えてコミットします
（5 のコミットと一緒で構いません）。

## 5. 証明書の指紋を固定する（任意・推奨）

```bash
cd <Port-Security の作業ディレクトリ>
git pull origin main
mkdir -p docs/signing
keytool -list -v -keystore ~/secure/port-security-release.jks -alias port-security \
  | sed -n 's/.*SHA256: //p' | tr -d ':' | tr 'A-F' 'a-f' > docs/signing/release-cert.sha256
cat docs/signing/release-cert.sha256     # 64 桁の 16 進数が 1 行
git add docs/signing/release-cert.sha256
git commit -m "Add release certificate pin"
git push origin main
```

以降の CI は、APK の証明書がこの値と一致しなければ失敗します。
5 を行わなくても、1〜4 だけで正式署名のリリースは公開されます（`pinned=no` と表示されます）。

## 6. バックアップ

- `~/secure/port-security-release.jks` とパスワードを、別の安全な場所にもコピーしてください。
- **鍵を失うと、同じアプリとして更新できなくなります。**

## 7. 初回の更新時

v1.0.31 以前の APK はデバッグ鍵で署名されています。正式署名の最初のリリースへ更新するときは、一度アンインストールしてからインストールしてください。
