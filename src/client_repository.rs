use std::collections::{HashMap, HashSet};

use crate::client::client::Client;

pub struct ClientRepository {
    clients: HashMap<u32, Client>,

    allocation_pointer: u32,
    free_ids: HashSet<u32>,
}
