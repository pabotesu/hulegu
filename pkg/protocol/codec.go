package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// EncodeMessage はメッセージをバイト列にエンコードします
func EncodeMessage(msg *Message) ([]byte, error) {
	// メッセージヘッダーサイズ: タイプ(1) + ペイロード長(2)
	const headerSize = 3

	// バッファの作成
	buffer := new(bytes.Buffer)

	// タイプの書き込み
	err := buffer.WriteByte(byte(msg.Type))
	if err != nil {
		return nil, fmt.Errorf("failed to write message type: %w", err)
	}

	// ペイロード長の書き込み
	payloadLen := uint16(len(msg.Payload))
	err = binary.Write(buffer, binary.BigEndian, payloadLen)
	if err != nil {
		return nil, fmt.Errorf("failed to write payload length: %w", err)
	}

	// ペイロードの書き込み
	if len(msg.Payload) > 0 {
		_, err = buffer.Write(msg.Payload)
		if err != nil {
			return nil, fmt.Errorf("failed to write payload: %w", err)
		}
	}

	return buffer.Bytes(), nil
}

// DecodeMessage はバイト列からメッセージを復元します
func DecodeMessage(data []byte) (*Message, error) {
	// 最低限必要なサイズ検証
	if len(data) < 3 {
		return nil, fmt.Errorf("message too short: %d bytes", len(data))
	}

	// メッセージタイプの取得
	msgType := MessageType(data[0])

	// ペイロード長の取得
	payloadLen := binary.BigEndian.Uint16(data[1:3])

	// ペイロード長の検証
	if len(data) < int(3+payloadLen) {
		return nil, fmt.Errorf("incomplete message: expected %d bytes, got %d", 3+payloadLen, len(data))
	}

	// ペイロードの取り出し
	var payload []byte
	if payloadLen > 0 {
		payload = make([]byte, payloadLen)
		copy(payload, data[3:3+payloadLen])
	}

	return &Message{
		Type:    msgType,
		Payload: payload,
	}, nil
}

// EncodeHandshake はハンドシェイクデータをエンコードします
func EncodeHandshake(data *HandshakeData) ([]byte, error) {
	buffer := new(bytes.Buffer)

	// 公開鍵の書き込み
	_, err := buffer.Write(data.PublicKey[:])
	if err != nil {
		return nil, err
	}

	// バージョンの書き込み
	err = binary.Write(buffer, binary.BigEndian, data.Version)
	if err != nil {
		return nil, err
	}

	// タイムスタンプの書き込み
	err = binary.Write(buffer, binary.BigEndian, data.Timestamp)
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

// DecodeHandshake はハンドシェイクデータをデコードします
func DecodeHandshake(payload []byte) (*HandshakeData, error) {
	if len(payload) < 32+2+8 {
		return nil, fmt.Errorf("invalid handshake payload size: %d", len(payload))
	}

	reader := bytes.NewReader(payload)

	// 公開鍵の読み取り
	var pubKey wgtypes.Key
	copy(pubKey[:], payload[:32])
	reader.Seek(32, 0)

	// バージョンの読み取り
	var version uint16
	err := binary.Read(reader, binary.BigEndian, &version)
	if err != nil {
		return nil, err
	}

	// タイムスタンプの読み取り
	var timestamp int64
	err = binary.Read(reader, binary.BigEndian, &timestamp)
	if err != nil {
		return nil, err
	}

	return &HandshakeData{
		PublicKey: pubKey,
		Version:   version,
		Timestamp: timestamp,
	}, nil
}

// EncodeHandshakeAck はハンドシェイク応答データをエンコードします
func EncodeHandshakeAck(data *HandshakeAckData) ([]byte, error) {
	buffer := new(bytes.Buffer)

	// セッションIDの長さを書き込み
	sessionIDLen := uint8(len(data.SessionID))
	err := buffer.WriteByte(sessionIDLen)
	if err != nil {
		return nil, err
	}

	// セッションIDを書き込み
	_, err = buffer.WriteString(data.SessionID)
	if err != nil {
		return nil, err
	}

	// サーバー時間を書き込み
	err = binary.Write(buffer, binary.BigEndian, data.ServerTime)
	if err != nil {
		return nil, err
	}

	// 有効期限を書き込み
	err = binary.Write(buffer, binary.BigEndian, data.Expiry)
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

// DecodeHandshakeAck はハンドシェイク応答データをデコードします
func DecodeHandshakeAck(payload []byte) (*HandshakeAckData, error) {
	if len(payload) < 1 { // 最低限セッションID長が必要
		return nil, fmt.Errorf("invalid handshake ack payload size: %d", len(payload))
	}

	// セッションIDの長さを読み取り
	sessionIDLen := int(payload[0])

	// ペイロード長の検証
	if len(payload) < 1+sessionIDLen+8+8 { // 長さ(1) + セッションID(可変) + サーバー時間(8) + 有効期限(8)
		return nil, fmt.Errorf("invalid handshake ack payload size: %d, expected at least %d", len(payload), 1+sessionIDLen+16)
	}

	// セッションIDを読み取り
	sessionID := string(payload[1 : 1+sessionIDLen])

	// サーバー時間と有効期限を読み取り
	reader := bytes.NewReader(payload[1+sessionIDLen:])

	var serverTime, expiry int64
	err := binary.Read(reader, binary.BigEndian, &serverTime)
	if err != nil {
		return nil, err
	}

	err = binary.Read(reader, binary.BigEndian, &expiry)
	if err != nil {
		return nil, err
	}

	return &HandshakeAckData{
		SessionID:  sessionID,
		ServerTime: serverTime,
		Expiry:     expiry,
	}, nil
}

// EncodePing はPingデータをエンコードします
func EncodePing(data *PingData) ([]byte, error) {
	buffer := new(bytes.Buffer)

	// タイムスタンプの書き込み
	err := binary.Write(buffer, binary.BigEndian, data.Timestamp)
	if err != nil {
		return nil, err
	}

	// シーケンス番号の書き込み
	err = binary.Write(buffer, binary.BigEndian, data.Sequence)
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

// DecodePing はPingデータをデコードします
func DecodePing(payload []byte) (*PingData, error) {
	if len(payload) < 8+4 { // タイムスタンプ(8) + シーケンス(4)
		return nil, fmt.Errorf("invalid ping payload size: %d", len(payload))
	}

	reader := bytes.NewReader(payload)

	var timestamp int64
	var sequence uint32

	err := binary.Read(reader, binary.BigEndian, &timestamp)
	if err != nil {
		return nil, err
	}

	err = binary.Read(reader, binary.BigEndian, &sequence)
	if err != nil {
		return nil, err
	}

	return &PingData{
		Timestamp: timestamp,
		Sequence:  sequence,
	}, nil
}

// EncodePong はPongデータをエンコードします
func EncodePong(data *PongData) ([]byte, error) {
	buffer := new(bytes.Buffer)

	// エコータイムスタンプの書き込み
	err := binary.Write(buffer, binary.BigEndian, data.EchoTimestamp)
	if err != nil {
		return nil, err
	}

	// サーバー時間の書き込み
	err = binary.Write(buffer, binary.BigEndian, data.ServerTime)
	if err != nil {
		return nil, err
	}

	// シーケンス番号の書き込み
	err = binary.Write(buffer, binary.BigEndian, data.Sequence)
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

// DecodePong はPongデータをデコードします
func DecodePong(payload []byte) (*PongData, error) {
	if len(payload) < 8+8+4 { // エコータイムスタンプ(8) + サーバー時間(8) + シーケンス(4)
		return nil, fmt.Errorf("invalid pong payload size: %d", len(payload))
	}

	reader := bytes.NewReader(payload)

	var echoTimestamp, serverTime int64
	var sequence uint32

	err := binary.Read(reader, binary.BigEndian, &echoTimestamp)
	if err != nil {
		return nil, err
	}

	err = binary.Read(reader, binary.BigEndian, &serverTime)
	if err != nil {
		return nil, err
	}

	err = binary.Read(reader, binary.BigEndian, &sequence)
	if err != nil {
		return nil, err
	}

	return &PongData{
		EchoTimestamp: echoTimestamp,
		ServerTime:    serverTime,
		Sequence:      sequence,
	}, nil
}

// EncodePacket はWireGuardパケットデータをエンコードします
func EncodePacket(data *PacketData) ([]byte, error) {
	buffer := new(bytes.Buffer)

	// 宛先キーの書き込み
	_, err := buffer.Write(data.TargetKey[:])
	if err != nil {
		return nil, err
	}

	// 送信元キーの書き込み（新規追加）
	_, err = buffer.Write(data.SourceKey[:])
	if err != nil {
		return nil, err
	}

	// パケットIDの書き込み
	err = binary.Write(buffer, binary.BigEndian, data.PacketID)
	if err != nil {
		return nil, err
	}

	// パケットデータ長の書き込み
	packetLen := uint16(len(data.PacketData))
	err = binary.Write(buffer, binary.BigEndian, packetLen)
	if err != nil {
		return nil, err
	}

	// パケットデータの書き込み
	_, err = buffer.Write(data.PacketData)
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

// DecodePacket はWireGuardパケットデータをデコードします
func DecodePacket(payload []byte) (*PacketData, error) {
	if len(payload) < 32+32+4+2 { // 宛先キー(32) + 送信元キー(32) + ID(4) + データ長(2)
		return nil, fmt.Errorf("invalid packet payload size: %d", len(payload))
	}

	reader := bytes.NewReader(payload)

	// 宛先キーの読み取り
	var targetKey wgtypes.Key
	copy(targetKey[:], payload[:32])

	// 送信元キーの読み取り（新規追加）
	var sourceKey wgtypes.Key
	copy(sourceKey[:], payload[32:64])

	reader.Seek(64, 0) // 両方のキーをスキップ

	// パケットIDの読み取り
	var packetID uint32
	err := binary.Read(reader, binary.BigEndian, &packetID)
	if err != nil {
		return nil, err
	}

	// パケットデータ長の読み取り
	var packetLen uint16
	err = binary.Read(reader, binary.BigEndian, &packetLen)
	if err != nil {
		return nil, err
	}

	// パケットデータの読み取り
	offset := 32 + 32 + 4 + 2 // 宛先キー + 送信元キー + ID + データ長
	if len(payload) < offset+int(packetLen) {
		return nil, fmt.Errorf("packet data truncated")
	}

	packetData := make([]byte, packetLen)
	copy(packetData, payload[offset:offset+int(packetLen)])

	return &PacketData{
		TargetKey:  targetKey,
		SourceKey:  sourceKey, // 新規追加
		PacketID:   packetID,
		PacketData: packetData,
	}, nil
}

// EncodeError はエラーデータをエンコードします
func EncodeError(data *ErrorData) ([]byte, error) {
	buffer := new(bytes.Buffer)

	// エラーコードの書き込み
	err := binary.Write(buffer, binary.BigEndian, data.Code)
	if err != nil {
		return nil, err
	}

	// メッセージ長の書き込み
	msgLen := uint8(len(data.Message))
	err = buffer.WriteByte(msgLen)
	if err != nil {
		return nil, err
	}

	// メッセージの書き込み（あれば）
	if msgLen > 0 {
		_, err = buffer.WriteString(data.Message)
		if err != nil {
			return nil, err
		}
	}

	return buffer.Bytes(), nil
}

// DecodeError はエラーデータをデコードします
func DecodeError(payload []byte) (*ErrorData, error) {
	if len(payload) < 2+1 { // コード(2) + メッセージ長(1)
		return nil, fmt.Errorf("invalid error payload size: %d", len(payload))
	}

	reader := bytes.NewReader(payload)

	// エラーコードの読み取り
	var code uint16
	err := binary.Read(reader, binary.BigEndian, &code)
	if err != nil {
		return nil, err
	}

	// メッセージ長の読み取り
	msgLenByte, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	msgLen := int(msgLenByte)

	// ペイロード長の検証
	if len(payload) < 2+1+msgLen {
		return nil, fmt.Errorf("invalid error message length")
	}

	// メッセージの読み取り
	message := ""
	if msgLen > 0 {
		msgBytes := make([]byte, msgLen)
		_, err = reader.Read(msgBytes)
		if err != nil {
			return nil, err
		}
		message = string(msgBytes)
	}

	return &ErrorData{
		Code:    code,
		Message: message,
	}, nil
}
