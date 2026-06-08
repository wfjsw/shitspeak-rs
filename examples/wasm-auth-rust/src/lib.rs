use std::alloc::{alloc as raw_alloc, dealloc as raw_dealloc, Layout};
use std::collections::HashMap;
use std::ptr;
use std::slice;

use serde::{Deserialize, Serialize};

#[link(wasm_import_module = "shitspeak")]
extern "C" {
    #[link_name = "fetch"]
    fn host_fetch(
        request_ptr: i32,
        request_len: i32,
        response_ptr: i32,
        response_capacity: i32,
    ) -> i32;
    #[link_name = "log"]
    fn host_log(level: i32, ptr: i32, len: i32);
}

#[no_mangle]
pub extern "C" fn alloc(len: i32) -> i32 {
    let Some(layout) = layout_for(len) else {
        return 0;
    };
    unsafe { raw_alloc(layout) as i32 }
}

#[no_mangle]
pub extern "C" fn dealloc(ptr: i32, len: i32) {
    if ptr == 0 {
        return;
    }
    let Some(layout) = layout_for(len) else {
        return;
    };
    unsafe { raw_dealloc(ptr as u32 as usize as *mut u8, layout) }
}

#[no_mangle]
pub extern "C" fn authenticate(ptr: i32, len: i32) -> u64 {
    let request = match read_json::<AuthenticateRequest>(ptr, len) {
        Ok(request) => request,
        Err(error) => {
            log(2, &format!("invalid auth request: {error}"));
            return write_json(&AuthenticateResponse::reject("retry_later"));
        }
    };

    if request.username == "admin" {
        return if request.password.as_deref() == Some("secret") {
            write_json(&AuthenticateResponse::accept(
                Some(1),
                "Admin",
                vec!["admin".to_owned()],
            ))
        } else {
            write_json(&AuthenticateResponse::reject("wrong_password"))
        };
    }

    if request.username == "guest" {
        return write_json(&AuthenticateResponse::accept(None, "guest", Vec::new()));
    }

    if let Some(remote_username) = request.username.strip_prefix("fetch:") {
        return write_json(&authenticate_with_fetch(
            remote_username,
            request.password.as_deref(),
        ));
    }

    write_json(&AuthenticateResponse::reject("no_such_user"))
}

#[no_mangle]
pub extern "C" fn language(ptr: i32, len: i32) -> u64 {
    let language = read_json::<LanguageRequest>(ptr, len)
        .ok()
        .and_then(|request| request.username)
        .filter(|username| username.ends_with(".es"))
        .map(|_| "es")
        .unwrap_or("en");
    write_json(&LanguageResponse { language })
}

fn authenticate_with_fetch(username: &str, password: Option<&str>) -> AuthenticateResponse {
    let request_body = serde_json::json!({
        "username": username,
        "password": password,
    });
    let mut headers = HashMap::new();
    headers.insert("content-type".to_owned(), "application/json".to_owned());

    let fetch_request = FetchRequest {
        url: "https://auth.example.test/mumble/check".to_owned(),
        method: "POST".to_owned(),
        headers,
        body: Some(request_body.to_string()),
        timeout_ms: 5_000,
    };

    let response = match fetch_json(fetch_request) {
        Ok(response) => response,
        Err(error) => {
            log(2, &format!("fetch auth failed: {error}"));
            return AuthenticateResponse::reject("retry_later");
        }
    };

    if !response.ok || response.status != 200 {
        return AuthenticateResponse::reject("retry_later");
    }

    let Some(body) = response.body else {
        return AuthenticateResponse::reject("retry_later");
    };
    serde_json::from_str::<AuthenticateResponse>(&body)
        .unwrap_or_else(|_| AuthenticateResponse::reject("retry_later"))
}

fn fetch_json(request: FetchRequest) -> Result<FetchResponse, String> {
    let request_json = serde_json::to_vec(&request).map_err(|error| error.to_string())?;
    let mut response = vec![0u8; 64 * 1024];
    let mut written = unsafe {
        host_fetch(
            request_json.as_ptr() as i32,
            request_json.len() as i32,
            response.as_mut_ptr() as i32,
            response.len() as i32,
        )
    };

    if written < 0 {
        let required = written
            .checked_neg()
            .ok_or_else(|| "host fetch returned invalid required length".to_owned())?;
        response.resize(required as usize, 0);
        written = unsafe {
            host_fetch(
                request_json.as_ptr() as i32,
                request_json.len() as i32,
                response.as_mut_ptr() as i32,
                response.len() as i32,
            )
        };
    }

    if written < 0 {
        return Err("host fetch response exceeded retry buffer".to_owned());
    }
    response.truncate(written as usize);
    serde_json::from_slice(&response).map_err(|error| error.to_string())
}

fn read_json<T>(ptr: i32, len: i32) -> Result<T, String>
where
    T: for<'de> Deserialize<'de>,
{
    if ptr < 0 || len < 0 {
        return Err("negative pointer or length".to_owned());
    }
    let bytes = unsafe { slice::from_raw_parts(ptr as u32 as usize as *const u8, len as usize) };
    serde_json::from_slice(bytes).map_err(|error| error.to_string())
}

fn write_json<T>(value: &T) -> u64
where
    T: Serialize,
{
    let bytes = serde_json::to_vec(value)
        .unwrap_or_else(|_| br#"{"accepted":false,"rejection":"retry_later"}"#.to_vec());
    let ptr = alloc(bytes.len() as i32);
    if ptr == 0 {
        return 0;
    }
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), ptr as u32 as usize as *mut u8, bytes.len());
    }
    ((ptr as u32 as u64) << 32) | bytes.len() as u64
}

fn log(level: i32, message: &str) {
    unsafe { host_log(level, message.as_ptr() as i32, message.len() as i32) }
}

fn layout_for(len: i32) -> Option<Layout> {
    if len < 0 {
        return None;
    }
    Layout::from_size_align((len as usize).max(1), 1).ok()
}

#[derive(Deserialize)]
struct AuthenticateRequest {
    username: String,
    password: Option<String>,
}

#[derive(Deserialize)]
struct LanguageRequest {
    username: Option<String>,
}

#[derive(Serialize)]
struct LanguageResponse<'a> {
    language: &'a str,
}

#[derive(Deserialize, Serialize)]
struct AuthenticateResponse {
    accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    rejection: Option<String>,
    user_id: Option<u32>,
    display_name: Option<String>,
    groups: Vec<String>,
    virtual_server_id: Option<String>,
    language: String,
    max_bandwidth: Option<u32>,
    texture_url: Option<String>,
    comment_url: Option<String>,
}

impl AuthenticateResponse {
    fn accept(user_id: Option<u32>, display_name: &str, groups: Vec<String>) -> Self {
        Self {
            accepted: true,
            rejection: None,
            user_id,
            display_name: Some(display_name.to_owned()),
            groups,
            virtual_server_id: None,
            language: "en".to_owned(),
            max_bandwidth: None,
            texture_url: None,
            comment_url: None,
        }
    }

    fn reject(rejection: &str) -> Self {
        Self {
            accepted: false,
            rejection: Some(rejection.to_owned()),
            user_id: None,
            display_name: None,
            groups: Vec::new(),
            virtual_server_id: None,
            language: "en".to_owned(),
            max_bandwidth: None,
            texture_url: None,
            comment_url: None,
        }
    }
}

#[derive(Serialize)]
struct FetchRequest {
    url: String,
    method: String,
    headers: HashMap<String, String>,
    body: Option<String>,
    timeout_ms: u64,
}

#[derive(Deserialize)]
struct FetchResponse {
    ok: bool,
    /// HTTP status code; 0 when no HTTP response was received (network error).
    status: u16,
    #[serde(default)]
    status_text: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    body: Option<String>,
}
