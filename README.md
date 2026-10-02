# 名刺帳（Render版）

名刺をカメラで撮影して登録し、会社名・部署・肩書・氏名・電話番号・メールアドレスなどを自動で読み取って保管するWebアプリです。

- サーバー: Node.js（Express）
- データ保存: Render PostgreSQL（名刺の写真もDBに保存）
- 読み取り: Claude API（画像からの文字読み取り）
- ログイン: Basic認証（ID・パスワード）

## Render へのデプロイ

1. このフォルダを GitHub のリポジトリにプッシュします。
2. Render のダッシュボードで **New → Blueprint** を選び、そのリポジトリを指定します。`render.yaml` が読み込まれ、Webサービス「meishi」とデータベース「meishi-db」が作成されます。
3. 途中で次の環境変数の入力を求められます。

   | 変数 | 内容 |
   |---|---|
   | `ANTHROPIC_API_KEY` | Claude API のキー（https://console.anthropic.com で発行） |
   | `APP_USER` | ログインID（自由に決める） |
   | `APP_PASSWORD` | ログインパスワード（長めのものを推奨） |

4. デプロイが終わると `https://meishi-xxxx.onrender.com` のようなURLが発行されます。スマホのブラウザで開き、ホーム画面に追加しておくと便利です。

`ANTHROPIC_MODEL` には読み取りに使うモデル名が入っています。変更したい場合はRenderの環境変数で書き換えてください。

## 無料プランでの注意

- 無料のWebサービスはしばらくアクセスがないと停止し、次に開いたとき起動に数十秒かかります。
- 無料のPostgreSQLには利用期限があります。継続して使う場合は有料プランに切り替えてください（最新の条件はRenderの料金ページで確認してください）。
- 読み取り1回ごとにClaude APIの利用料がかかります。

## ローカルで動かす

```bash
npm install
DATABASE_URL=postgres://user:pass@localhost:5432/meishi \
ANTHROPIC_API_KEY=sk-ant-... \
npm start
```

`http://localhost:3000` を開きます。`APP_USER` と `APP_PASSWORD` を設定しない場合はログインなしで動きます（ローカル専用にしてください）。外部のDB接続URLでSSLが必要な場合は `PGSSL=true` を付けます。

## API

| メソッド | パス | 内容 |
|---|---|---|
| GET | `/api/cards` | 名刺一覧（写真なし） |
| GET | `/api/cards/:id/image` | 名刺の写真 |
| POST | `/api/cards` | 新規登録（multipart: `image` と `data`＝JSON文字列） |
| PUT | `/api/cards/:id` | 内容の更新（JSON） |
| DELETE | `/api/cards/:id` | 削除 |
| POST | `/api/ocr` | 写真から項目を読み取る（multipart: `image`） |
