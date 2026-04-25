# Error Types

## Top-level errors (src/errors/)
- `AuthRejection` — authentication rejection (→ Reject message)
- `ChannelRepoError` — channel repository errors
- `HandleIncomingConnectionError` — connection handling errors (wraps IO, proto read/write, proxy protocol)
- `MessageHandlerError` — message handler errors (wraps proto, auth, permissions, etc.)
- `MessageTypeNotForIncoming` — wrong message direction
- `UnknownMessageType` — unrecognized message type
- `MessageLengthExceeded` — message too large
- `ReadProtoMessageError` — protobuf read errors
- `WriteProtoMessageError` — protobuf write errors
- `FromProtoToMessageError` — conversion errors
- `ProxyProtocolHeaderTooLargeError` — PROXY protocol header overflow

## Message protocol errors (src/messages/errors/)
- `MessageProtocolError` — umbrella enum
- `PingProtocolError` — ping-specific protocol errors
- `UserStateProtocolError` — user state protocol errors

## Crypt errors (src/client/crypt/errors.rs)
- `CryptError` — voice crypto errors (wraps aws-lc-rs errors)

## Proxy protocol errors (src/proxy_protocol.rs)
- `GetProxyProtocolRealIpError` — PROXY protocol parsing errors
