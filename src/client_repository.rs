use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use parking_lot::Mutex;
use tokio::net::TcpStream;
use tokio_rustls::TlsStream;

use crate::{
    client::{
        client::Client, client_session_identifier::ClientSessionIdentifier,
        user_version::UserVersion,
    },
    constants::MAX_LOCAL_SESSION_ID,
};

pub struct ClientRepository {
    node_id: u16,
    clients: Mutex<HashMap<ClientSessionIdentifier, Arc<Client>>>,

    // The pointer only store local_session_id part
    allocation_pointer: Mutex<u32>,
    free_ids: Mutex<HashSet<u32>>,
}

impl ClientRepository {
    pub fn new(node_id: u16) -> Self {
        ClientRepository {
            node_id,
            clients: Mutex::new(HashMap::new()),
            allocation_pointer: Mutex::new(0),
            free_ids: Mutex::new(HashSet::new()),
        }
    }

    pub fn allocate_client(
        &mut self,
        real_ip_address: IpAddr,
        tcp_address: SocketAddr,
        udp_address: Option<SocketAddr>,
        local_address: SocketAddr,
        connection: TlsStream<TcpStream>,
        user_version: UserVersion,
    ) -> Arc<Client> {
        let id = {
            let mut free_ids = self.free_ids.lock();
            if let Some(free_id) = free_ids.iter().next().copied() {
                free_ids.remove(&free_id);
                free_id
            } else {
                let mut allocation_pointer = self.allocation_pointer.lock();
                let id = *allocation_pointer;

                if id > MAX_LOCAL_SESSION_ID {
                    panic!("Exceeded maximum number of local session IDs. Consider rearranging the allocation strategy");
                }

                *allocation_pointer += 1;
                id
            }
        };
        let client_identifier = ClientSessionIdentifier::new(self.node_id, id).unwrap();
        let client = Client::new(
            client_identifier,
            real_ip_address,
            tcp_address,
            udp_address,
            local_address,
            connection,
            user_version,
            None,
        );
        let client = Arc::new(client);
        self.clients
            .lock()
            .insert(client_identifier, Arc::clone(&client));
        client
    }

    pub fn add_remote_client(&mut self, id: ClientSessionIdentifier, client: Arc<Client>) {
        let client = Arc::clone(&client);
        self.clients.lock().insert(id, client);
    }

    pub fn remove_client(&mut self, id: ClientSessionIdentifier) -> Option<Arc<Client>> {
        if let Some(client) = self.clients.lock().remove(&id) {
            self.free_ids.lock().insert(id.local_session_id);
            Some(client)
        } else {
            None
        }
    }

    pub fn clear_clients_from_node(&mut self, node_id: u16) {
        let mut clients = self.clients.lock();
        let mut free_ids = self.free_ids.lock();

        let ids_to_remove: Vec<ClientSessionIdentifier> = clients
            .keys()
            .filter(|id| id.node_id == node_id)
            .copied()
            .collect();

        for id in ids_to_remove {
            clients.remove(&id);
            free_ids.insert(id.local_session_id);
        }
    }

    pub fn get_client(&self, id: ClientSessionIdentifier) -> Option<Arc<Client>> {
        self.clients.lock().get(&id).cloned()
    }
}
