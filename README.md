# WebShark

🦈 Linuxゲートウェイ上でネットワークパケットをリアルタイムで可視化するWebベースのネットワーク分析ツールです。

## 特徴

- 🚀 **シンプルな構成**: Rustで書かれた単一バイナリ
- 📊 **リアルタイム可視化**: WebSocketを使った動的更新
- 🔍 **tshark統合**: Wiresharkのtsharkコマンドを使用
- 🎨 **美しいUI**: モダンなWebインターフェース
- 📈 **統計情報**: プロトコル別、送信元/宛先別の統計

## 必要な依存関係

### システム要件
- Linux OS (Ubuntu, CentOS, Debian等)
- Rust 1.70+
- Wireshark (tsharkコマンド)

### インストール

1. **Wiresharkのインストール**:
   ```bash
   # Ubuntu/Debian
   sudo apt update
   sudo apt install wireshark-common
   
   # CentOS/RHEL
   sudo yum install wireshark-cli
   
   # または
   sudo dnf install wireshark-cli
   ```

2. **権限設定** (重要):
   ```bash
   # wiresharkグループに追加
   sudo usermod -a -G wireshark $USER
   
   # または、sudoなしでtsharkを実行できるように設定
   sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tshark
   ```

3. **Rustのインストール** (必要に応じて):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source ~/.cargo/env
   ```

## ビルドと実行

1. **プロジェクトのビルド**:
   ```bash
   cargo build --release
   ```

2. **実行**:
   ```bash
   # 管理者権限で実行 (ネットワークインターフェースアクセスのため)
   sudo ./target/release/webshark
   ```

3. **ブラウザでアクセス**:
   ```
   http://localhost:3000
   ```

## 使用方法

1. ブラウザで `http://localhost:3000` にアクセス
2. 「開始」ボタンをクリックしてパケットキャプチャを開始
3. リアルタイムでパケット情報が表示される
4. 統計情報も自動的に更新される

## 設定オプション

### インターフェース指定
デフォルトでは全インターフェース(`any`)を監視しますが、特定のインターフェースを指定したい場合は、
`src/main.rs`の129行目を変更してください：

```rust
.args(&[
    "-i", "eth0",  // 特定のインターフェース
    // ...
])
```

### ポート変更
デフォルトポート3000を変更したい場合は、97行目を変更してください：

```rust
let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
```

## トラブルシューティング

### 1. tsharkが見つからない
```bash
which tshark
```
で確認し、パスが通っていることを確認してください。

### 2. 権限エラー
```bash
sudo ./target/release/packet-visualizer
```
で実行するか、上記の権限設定を行ってください。

### 3. ネットワークインターフェースが見つからない
```bash
ip link show
```
で利用可能なインターフェースを確認してください。

### 4. WebSocket接続エラー
ファイアウォールで3000ポートが開いていることを確認してください：
```bash
sudo ufw allow 3000
```

## 開発

### ログ出力
```bash
RUST_LOG=debug cargo run
```

### ホットリロード
```bash
cargo watch -x run
```

## セキュリティ注意事項

- このツールは管理者権限で実行する必要があります
- 本番環境では適切なアクセス制限を設定してください
- ネットワークトラフィックを監視するため、プライバシーに配慮してください

## ライセンス

MIT License

## 貢献

バグ報告や機能要望は、GitHubのIssueまでお願いします。