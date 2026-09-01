use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use async_trait::async_trait;
use shitspeak_auth::{
    AuthenticateAuxiliaryData, AuthenticateResult, AuthenticationExpiryAction,
    AuthenticationRejection, Authenticator, Language, ReloadableAuthenticator,
};
use tokio::sync::Barrier;

struct LabelAuthenticator {
    label: &'static str,
}

#[async_trait]
impl Authenticator for LabelAuthenticator {
    async fn authenticate(
        &self,
        _username: &str,
        _password: Option<&str>,
        _auxiliary_data: &AuthenticateAuxiliaryData,
    ) -> Result<AuthenticateResult, AuthenticationRejection> {
        Ok(result(self.label))
    }
}

struct BlockingAuthenticator {
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
}

#[async_trait]
impl Authenticator for BlockingAuthenticator {
    async fn authenticate(
        &self,
        _username: &str,
        _password: Option<&str>,
        _auxiliary_data: &AuthenticateAuxiliaryData,
    ) -> Result<AuthenticateResult, AuthenticationRejection> {
        self.entered.wait().await;
        self.release.wait().await;
        Ok(result("old"))
    }
}

#[tokio::test]
async fn in_flight_authentication_keeps_backend_alive_across_reload() {
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let authenticator = Arc::new(ReloadableAuthenticator::fixed(BlockingAuthenticator {
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
    }));

    let in_flight = {
        let authenticator = Arc::clone(&authenticator);
        tokio::spawn(async move {
            authenticator
                .authenticate("user", None, &auxiliary_data())
                .await
                .expect("old backend should authenticate")
        })
    };

    entered.wait().await;
    authenticator.apply_prepared_reload(Some(Arc::new(LabelAuthenticator { label: "new" })));
    release.wait().await;

    assert_eq!(
        in_flight
            .await
            .expect("authentication task panicked")
            .display_name,
        Some("old".to_owned())
    );
    assert_eq!(
        authenticator
            .authenticate("user", None, &auxiliary_data())
            .await
            .expect("new backend should authenticate")
            .display_name,
        Some("new".to_owned())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_authentication_observes_complete_backend_generations() {
    let authenticator = Arc::new(ReloadableAuthenticator::fixed(LabelAuthenticator {
        label: "a",
    }));
    let mut tasks = Vec::new();

    for _ in 0..8 {
        let authenticator = Arc::clone(&authenticator);
        tasks.push(tokio::spawn(async move {
            for _ in 0..200 {
                let display_name = authenticator
                    .authenticate("user", None, &auxiliary_data())
                    .await
                    .expect("backend should authenticate")
                    .display_name
                    .expect("backend should return a display name");
                assert!(display_name == "a" || display_name == "b");
                tokio::task::yield_now().await;
            }
        }));
    }

    for generation in 0..200 {
        let label = if generation % 2 == 0 { "b" } else { "a" };
        authenticator.apply_prepared_reload(Some(Arc::new(LabelAuthenticator { label })));
        tokio::task::yield_now().await;
    }

    for task in tasks {
        task.await.expect("authentication task panicked");
    }
}

fn auxiliary_data() -> AuthenticateAuxiliaryData {
    AuthenticateAuxiliaryData {
        certificate_hash: None,
        session_id: 1,
        ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        tls_ja3: None,
        tls_ja4: None,
        tls_ja4t: None,
        tls_ja4x: None,
        tls_ja4l: None,
        tls_sni: None,
        proxy_server_address: None,
        packet_capture_backends: Vec::new(),
        packet_capture_backend: None,
        uses_proxy_protocol: false,
        version: None,
        client_name: None,
        os_name: None,
        os_version: None,
        auth_session_id: None,
    }
}

fn result(label: &str) -> AuthenticateResult {
    AuthenticateResult {
        user_id: None,
        fqdn: None,
        display_name: Some(label.to_owned()),
        groups: Vec::new(),
        is_superuser: false,
        invisible: false,
        virtual_server_id: None,
        language: Language::default(),
        max_bandwidth: None,
        texture_url: None,
        comment_url: None,
        auth_session_id: None,
        authenticated_until: None,
        authentication_expiry_action: AuthenticationExpiryAction::default(),
    }
}
