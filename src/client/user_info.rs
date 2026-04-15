use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct UserInfo {
    user_id: Option<u32>,
    
    groups: HashSet<String>,
    tokens: HashSet<String>,
    display_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Credential {
    username: String,
    password: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UserInfoExtended {
    credential: Option<Credential>,
}

impl UserInfo {
    pub fn new(
        groups: HashSet<String>,
        tokens: HashSet<String>,
        display_name: Option<String>,
    ) -> Self {
        UserInfo {
            user_id: None,

            groups,
            tokens,
            display_name,
        }
    }

    pub fn get_user_id(&self) -> Option<u32> {
        self.user_id
    }

    pub fn set_user_id(&mut self, user_id: Option<u32>) {
        self.user_id = user_id;
    }

    pub fn is_registered(&self) -> bool {
        self.user_id.is_some()
    }

    pub fn get_groups(&self) -> &HashSet<String> {
        &self.groups
    }

    pub fn get_groups_mut(&mut self) -> &mut HashSet<String> {
        &mut self.groups
    }

    pub fn has_group(&self, group: &str) -> bool {
        self.groups.contains(&group.to_string())
    }

    pub fn add_group(&mut self, group: String) {
        self.groups.insert(group);
    }

    pub fn del_group(&mut self, group: &str) {
        self.groups.remove(&group.to_string());
    }

    pub fn set_groups(&mut self, groups: HashSet<String>) {
        self.groups = groups;
    }

    pub fn get_tokens(&self) -> &HashSet<String> {
        &self.tokens
    }

    pub fn add_token(&mut self, token: String) {
        self.tokens.insert(token);
    }

    pub fn del_token(&mut self, token: &str) {
        self.tokens.remove(token);
    }

    pub fn set_tokens(&mut self, tokens: HashSet<String>) {
        self.tokens = tokens;
    }

    // TODO: case insensitive
    pub fn has_token(&self, token: &str) -> bool {
        self.tokens.contains(&token.to_string())
    }

    pub fn get_display_name(&self) -> &str {
        self.display_name.as_deref().expect("Unexpected empty username; Accessing before initialization?")
    }

    pub fn get_display_name_opt(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    pub fn set_display_name(&mut self, display_name: Option<String>) {
        self.display_name = display_name;
    }
}

impl Default for UserInfo {
    fn default() -> Self {
        UserInfo {
            user_id: None,

            groups: HashSet::new(),
            tokens: HashSet::new(),
            display_name: None,
        }
    }
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
