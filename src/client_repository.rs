use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use parking_lot::{Mutex, RwLock};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;

use crate::{
    client::{
        client::Client, client_session_identifier::ClientSessionIdentifier,
    },
    constants::MAX_LOCAL_SESSION_ID,
};

pub struct ClientRepository {
    local_node_id: u16,
    clients: RwLock<HashMap<ClientSessionIdentifier, Arc<Box<Client>>>>,

    clients_by_host: RwLock<HashMap<IpAddr, HashSet<ClientSessionIdentifier>>>,
    clients_by_udp_address: RwLock<HashMap<SocketAddr, ClientSessionIdentifier>>,

    // The pointer only store local_session_id part
    allocation_pointer: Mutex<u32>,
    free_ids: Mutex<HashSet<u32>>,
}

impl ClientRepository {
    pub fn new(local_node_id: u16) -> Self {
        ClientRepository {
            local_node_id,
            clients: RwLock::new(HashMap::new()),
            clients_by_host: RwLock::new(HashMap::new()),
            clients_by_udp_address: RwLock::new(HashMap::new()),
            allocation_pointer: Mutex::new(0),
            free_ids: Mutex::new(HashSet::new()),
        }
    }

    pub fn allocate_client(
        &self,
        real_ip_address: IpAddr,
        tcp_address: SocketAddr,
        udp_address: Option<SocketAddr>,
        local_address: SocketAddr,
        connection: TlsStream<TcpStream>,
    ) -> Arc<Box<Client>> {
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
        let client_identifier = ClientSessionIdentifier::new(self.local_node_id, id).unwrap();
        let client = Client::new(
            client_identifier,
            real_ip_address,
            tcp_address,
            udp_address,
            local_address,
            connection,
        );
        let client = Arc::new(client);

        self.clients
            .write()
            .insert(client_identifier, Arc::clone(&client));

        if let Some(udp_address) = udp_address {
            self.clients_by_udp_address
                .write()
                .insert(udp_address, client_identifier);
        }

        self.clients_by_host
            .write()
            .entry(tcp_address.ip())
            .or_insert_with(HashSet::new)
            .insert(client_identifier);

        client
    }

    pub fn add_remote_client(&self, id: ClientSessionIdentifier, client: Arc<Box<Client>>) {
        if client.get_node_id() == self.local_node_id {
            panic!("Not supposed to add a remote client with the local node ID");
        }

        let client = Arc::clone(&client);
        self.clients.write().insert(id, client);
    }

    pub fn remove_client(&self, id: ClientSessionIdentifier) -> Option<Arc<Box<Client>>> {
        if let Some(client) = self.clients.write().remove(&id) {

            if client.get_node_id() == self.local_node_id {
                if let Some(udp_address) = client.get_udp_address() {
                    self.clients_by_udp_address.write().remove(&udp_address);
                }

                let tcp_address = client.get_tcp_address();

                self.clients_by_host
                    .write()
                    .entry(tcp_address.ip())
                    .and_modify(|set| {
                        set.remove(&id);
                        if set.is_empty() {
                            self.clients_by_host.write().remove(&tcp_address.ip());
                        }
                    });

                self.free_ids.lock().insert(id.local_session_id);
            }

            Some(client)
        } else {
            None
        }
    }

    pub fn clear_clients_from_node(&self, node_id: u16) {
        if node_id == self.local_node_id {
            panic!("Not supposed to clear clients from the local node");
        }

        let mut clients = self.clients.write();
        let mut free_ids = self.free_ids.lock();

        let ids_to_remove: Vec<ClientSessionIdentifier> = clients
            .keys()
            .filter(|id| id.node_id == node_id)
            .copied()
            .collect();

        for id in ids_to_remove {
            clients.remove(&id);
            free_ids.insert(id.get_local_session_id());
        }
    }

    pub fn get_client(&self, id: ClientSessionIdentifier) -> Option<Arc<Box<Client>>> {
        self.clients.read().get(&id).cloned()
    }
}
