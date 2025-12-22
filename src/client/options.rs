pub struct ClientOptions {
    block_group_shouts: bool,
    promiscuous_mode: bool,
}

impl Default for ClientOptions {
    fn default() -> Self {
        ClientOptions {
            block_group_shouts: false,
            promiscuous_mode: false,
        }
    }
}

impl ClientOptions {
    pub fn new() -> Self {
        ClientOptions::default()
    }

    pub fn block_group_shouts(&self) -> bool {
        self.block_group_shouts
    }

    pub fn set_block_group_shouts(&mut self, value: bool) {
        self.block_group_shouts = value;
    }

    pub fn promiscuous_mode(&self) -> bool {
        self.promiscuous_mode
    }

    pub fn set_promiscuous_mode(&mut self, value: bool) {
        self.promiscuous_mode = value;
    }
}
