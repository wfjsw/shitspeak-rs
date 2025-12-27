use std::collections::HashSet;

pub struct UserInfo {
    groups: HashSet<String>,
    tokens: HashSet<String>,
    display_name: Option<String>,
}

pub struct UserInfoExtended {
    username: String,
    password: Option<String>,
}

impl UserInfo {
    pub fn new(
        groups: HashSet<String>,
        tokens: HashSet<String>,
        display_name: Option<String>,
    ) -> Self {
        UserInfo {
            groups,
            tokens,
            display_name,
        }
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

    pub fn get_display_name(&self) -> &Option<String> {
        &self.display_name
    }
}

impl Default for UserInfo {
    fn default() -> Self {
        UserInfo {
            groups: HashSet::new(),
            tokens: HashSet::new(),
            display_name: None,
        }
    }
}
