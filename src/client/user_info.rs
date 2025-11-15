pub struct UserInfo {
    groups: Vec<String>,
    tokens: Vec<String>,
}

pub struct UserInfoExtended {
    username: String,
    password: Option<String>,
}
