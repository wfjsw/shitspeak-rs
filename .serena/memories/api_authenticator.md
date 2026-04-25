# API / Authenticator Trait

## Authenticator Trait (src/api/authenticator.rs)
- `Authenticator` trait — async trait for pluggable authentication
- `AuthenticationRejection` enum — reasons for auth failure
- `AuthenticateResult` struct — successful auth result
- `AuthenticateAuxiliaryData` — additional data from auth
- `RegisteredUser` struct — registered user info

## Planned Extensions (from guidelines.md)
- `get_user_texture(user_id) -> Option<Bytes>` (default: None)
- `get_user_comment(user_id) -> Option<String>` (default: None)
- `set_user_texture(user_id, Bytes) -> Result<(), ()>` (default: Err)
- `set_user_comment(user_id, String) -> Result<(), ()>` (default: Err)
- All have default no-op implementations

## NoopAuthenticator (src/main.rs)
- Simple no-op implementation for testing/development
- Implements `Authenticator` trait
