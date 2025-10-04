# Protocol パッケージ - Hulegu 通信プロトコル
## 概要
protocol パッケージは、Hulegu が WebSocket 接続を介して WireGuard パケットを中継するために使用するバイナリ通信プロトコルを実装しています。メッセージのエンコード/デコード、セッション管理、パケット転送機能を提供します。

## メッセージ構造
すべてのプロトコルメッセージは以下の基本構造に従います：
```
+-----------------+------------------+------------------+
| メッセージタイプ   | ペイロード長       | ペイロード        |
| １バイト          | ２バイト          | 可変長            |
+-----------------+------------------+------------------+
```

## メッセージタイプ
プロトコルでは以下のメッセージタイプを定義しています：
```markdown
// コントロールメッセージ
TypeHandshake    = 0x01  // 初期ハンドシェイク
TypeHandshakeAck = 0x02  // ハンドシェイク確認応答
TypePing         = 0x03  // キープアライブpingリクエスト
TypePong         = 0x04  // ping応答
TypeDisconnect   = 0x05  // 正常切断通知

// データメッセージ
TypePacket       = 0x10  // WireGuardパケット
TypePacketAck    = 0x11  // パケット確認応答（オプション）

// エラーメッセージ
TypeError        = 0xF0  // エラー通知
```

## 使用方法
メッセージのエンコード
```go
// ハンドシェイクメッセージを作成
handshake := &HandshakeData{
    PublicKey: publicKey,
    Version:   ProtocolVersion,
    Timestamp: GetCurrentTimestamp(),
}

// ハンドシェイクデータをエンコード
handshakePayload, err := EncodeHandshake(handshake)
if err != nil {
    return err
}

// メッセージを作成してエンコード
msg := &Message{
    Type:    TypeHandshake,
    Payload: handshakePayload,
}

msgBytes, err := EncodeMessage(msg)
if err != nil {
    return err
}

// WebSocketで送信
conn.WriteMessage(websocket.BinaryMessage, msgBytes)
```
メッセージのデコード
```go
// WebSocketメッセージを受信
_, data, err := conn.ReadMessage()
if err != nil {
    return err
}

// メッセージをデコード
msg, err := DecodeMessage(data)
if err != nil {
    return err
}

// メッセージタイプに基づいて処理
switch msg.Type {
case TypeHandshake:
    handshake, err := DecodeHandshake(msg.Payload)
    if err != nil {
        return err
    }
    // ハンドシェイクを処理...

case TypePacket:
    packet, err := DecodePacket(msg.Payload)
    if err != nil {
        return err
    }
    // パケットを処理...
}
```
## 定数
| 名前 | 型 | 値 | 説明 |
|------|------|-------|-------------|
| ProtocolVersion | uint16 | 1 | 現在のプロトコルバージョン |
| MaxMessageSize | int | 65535 | メッセージの最大サイズ（バイト） |
| MaxPayloadSize | int | 65532 | ペイロードの最大サイズ（バイト） |
| HandshakeTimeout | time.Duration | 10秒 | ハンドシェイクのタイムアウト時間 |
| MaxTimestampDrift | time.Duration | 30秒 | タイムスタンプの最大許容ずれ |
| DefaultSessionExpiry | time.Duration | 24時間 | デフォルトのセッション有効期限 |

## データ型
### Message
タイプとペイロードを含む基本メッセージ構造。

### HandshakeData
- クライアント認証情報を含みます：
- 公開鍵（WireGuard公開鍵）
- プロトコルバージョン
- リプレイ攻撃防止のためのタイムスタンプ

### PacketData
WireGuardパケット情報を含みます：

- 宛先ピアの公開鍵
- パケット識別子
- 生のWireGuardパケットデータ
- その他の型
- HandshakeAckData
- PingData
- PongData
- ErrorData

### エラー処理
プロトコルには特定のエラーコードによるエラー報告機能が含まれています：
- 認証失敗
- 無効なメッセージ形式
- セッション期限切れ
- レート制限
- ピアが見つからない
- バージョンの非互換性

### セキュリティ考慮事項
- すべてのメッセージは安全なWebSocket接続（wss://）で送信されるべき
- タイムスタンプ検証によりリプレイ攻撃を防止
- クライアント識別はWireGuardの公開鍵を使用するが、接続自体のセキュリティはWSS（WebSocket Secure）に依存
- WireGuardパケットはエンドツーエンドで暗号化されたまま

### プロトコルフロー
- セッション確立 - 認証を含むハンドシェイク交換
```
クライアント                                 サーバー
    |                                          |
    |---- TypeHandshake (公開鍵, バージョン) ---->|
    |                                          | (検証/セッション・公開鍵登録)
    |<--- TypeHandshakeAck (セッションID) -------|
    |                                          |
```
- パケット転送 - WireGuardパケットの送受信
```
クライアント                                 サーバー
    |                                          |
    |---- TypePacket (宛先キー, パケット) ------> |
    |                                          | (宛先に転送)
    |<--- TypePacket (送信元キー, パケット) ------|
    |                                          |
```
- キープアライブ - 接続を維持するための定期的なping/pong交換
```
クライアント                                 サーバー
    |                                          |
    |---- TypePing (タイムスタンプ) ------------>|
    |                                          |
    |<--- TypePong (エコーデータ) ---------------|
    |                                          |
```
- セッション終了 - クリーンな切断
```
クライアント                                 サーバー
    |                                          |
    |--- TypeDisconnect ---------------------->|
    |                                          | (セッション終了)
    |<-- TypeDisconnect -----------------------|
    |                                          |
```
