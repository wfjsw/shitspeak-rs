# Client Disconnect

`Client::disconnect` in `src/client/client.rs` is an async method returning `Result<(), WriteProtoMessageError>`. It gracefully shuts down local clients by locking the TLS write half (`connection_tx`) and awaiting `AsyncWriteExt::shutdown()`, which sends the TLS close notification before closing the write side. Remote clients have no local connection halves, so `disconnect` returns `Ok(())` for them.
