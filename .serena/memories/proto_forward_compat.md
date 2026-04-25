# Protobuf Forward Compatibility

- The Mumble protocol values and existing message fields will not change.
- Newer clients may send unrecognized fields or enum variants that the server doesn't know about.
- The server MUST ignore unknown fields/variants and produce a warning log.
- This applies to all protobuf messages and enums.
- When converting proto enums to native enums (e.g., `DenyType`, `RejectType`), unknown values should map to a reasonable default (e.g., `DenyType::Text` or `RejectType::None`) with a `tracing::warn!`.
- The `From`/`TryFrom` impls in `src/messages/encoder/` should handle unknown enum variants gracefully.
- prost already ignores unknown fields by default, so no action needed for message fields.
