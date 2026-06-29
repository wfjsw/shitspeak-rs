#[derive(Debug, Clone)]
pub struct Credential {
    pub username: String,
    pub password: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UserInfoExtended {
    credential: Option<Credential>,
}

impl UserInfoExtended {
    pub fn set_credential(&mut self, credential: Credential) {
        self.credential = Some(credential);
    }

    pub fn get_credential(&self) -> &Option<Credential> {
        &self.credential
    }

    pub fn clear_credential(&mut self) {
        self.credential = None;
    }
}

impl Default for UserInfoExtended {
    fn default() -> Self {
        UserInfoExtended { credential: None }
    }
}

impl Credential {
    pub fn new(username: String, password: Option<String>) -> Self {
        Credential { username, password }
    }
}
