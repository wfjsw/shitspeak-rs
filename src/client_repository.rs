use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use tokio::sync::{Mutex, RwLock};
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

    pub async fn allocate_local_client(
        &self,
        real_ip_address: IpAddr,
        tcp_address: SocketAddr,
        udp_address: Option<SocketAddr>,
        local_address: SocketAddr,
        connection: TlsStream<TcpStream>,
    ) -> Arc<Box<Client>> {
        let mut clients_guard = self.clients.write().await;
        let mut client_by_udp_address_guard = self.clients_by_udp_address.write().await;
        let mut client_by_host_guard = self.clients_by_host.write().await;
        let mut free_ids_guard = self.free_ids.lock().await;

        let id = {
            if let Some(free_id) = free_ids_guard.iter().next().copied() {
                free_ids_guard.remove(&free_id);
                free_id
            } else {
                let mut allocation_pointer = self.allocation_pointer.lock().await;
                let id = *allocation_pointer;

                if id > MAX_LOCAL_SESSION_ID {
                    panic!("Exceeded maximum number of local session IDs. Consider rearranging the allocation strategy");
                }

                *allocation_pointer += 1;
                id
            }
        };
        let client_identifier = ClientSessionIdentifier::new(self.local_node_id, id).unwrap();
        let client = Client::new_local(
            client_identifier,
            real_ip_address,
            tcp_address,
            udp_address,
            local_address,
            connection,
        );
        
        let client = Arc::new(client);

        clients_guard.insert(client_identifier, Arc::clone(&client));

        if let Some(udp_address) = udp_address {
            client_by_udp_address_guard
                .insert(udp_address, client_identifier);
        }

        if let Some(set) = client_by_host_guard.get_mut(&tcp_address.ip()) {
            set.insert(client_identifier);
        } else {
            let mut set = HashSet::new();
            set.insert(client_identifier);
            client_by_host_guard.insert(tcp_address.ip(), set);
        }

        client
    }

    pub async fn add_remote_client(&self, id: ClientSessionIdentifier, client: Arc<Box<Client>>) {
        if client.get_node_id() == self.local_node_id {
            panic!("Not supposed to add a remote client with the local node ID");
        }

        let client = Arc::clone(&client);
        self.clients.write().await.insert(id, client);
    }

    pub async fn remove_client(&self, id: ClientSessionIdentifier) -> Option<Arc<Box<Client>>> {
        let mut clients_guard = self.clients.write().await;
        let mut client_by_udp_address_guard = self.clients_by_udp_address.write().await;
        let mut client_by_host_guard = self.clients_by_host.write().await;
        let mut free_ids_guard = self.free_ids.lock().await;

        if let Some(client) = clients_guard.remove(&id) {
            if client.get_node_id() == self.local_node_id {
                if let Some(udp_address) = client.get_udp_address() {
                    client_by_udp_address_guard.remove(&udp_address);
                }

                let tcp_address = client.get_tcp_address();

                if let Some(set) = client_by_host_guard.get_mut(&tcp_address.ip()) {
                    set.remove(&id);
                    if set.is_empty() {
                        client_by_host_guard.remove(&tcp_address.ip());
                    }
                }

                free_ids_guard.insert(id.local_session_id);
            }

            Some(client)
        } else {
            None
        }
    }

    pub async fn clear_clients_from_node(&self, node_id: u16) {
        if node_id == self.local_node_id {
            panic!("Not supposed to clear clients from the local node");
        }

        let mut clients = self.clients.write().await;
        let mut free_ids = self.free_ids.lock().await;

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

    pub async fn get_client(&self, id: ClientSessionIdentifier) -> Option<Arc<Box<Client>>> {
        self.clients.read().await.get(&id).cloned()
    }

}
