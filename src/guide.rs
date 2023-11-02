use crate::bootstrap::Config;
use crate::crypto::hmac::Hmac;
use crate::crypto::{Address, GtpCrypto, GtpGuideTcpRequest, SecretsStorage};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::de::DeserializeOwned;
use tiny_http::{Response, Server};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use std::sync::Arc;

pub struct Guide {
    secrets: Arc<SecretsStorage>,
    address: Address,
    server_address: Address,
}

impl Guide {
    pub fn from_config(config: &Config, address: Address) -> Self {
        Self {
            secrets: Arc::new(
                config
                    .secrets
                    .get(&address)
                    .expect("Guide address should present in config")
                    .to_owned(),
            ),
            server_address: config.server_address.clone(),
            address,
        }
    }

    pub async fn serve<H: Hmac + DeserializeOwned>(
        self,
        bind_address: Address,
    ) -> (JoinHandle<()>, oneshot::Sender<()>) {
        let server = Server::http(bind_address).unwrap();

        let (tx, mut rx) = oneshot::channel();
        let handle = tokio::task::spawn_blocking(move || loop {
            println!("server started accepting connections");
            if let Ok(Some(mut request)) = server.recv_timeout(Duration::from_millis(100)) {
                let secrets = self.secrets.clone();
                let address_this = self.address.clone();
                let server_address = self.server_address.clone();
                tokio::spawn(async move {
                    let user_address = request.remote_addr().unwrap().clone().ip();
                    println!("received request from {}", user_address);

                    let mut buf = Vec::new();
                    request.as_reader().read_to_end(&mut buf).unwrap();
                    let ts = {
                        let start = SystemTime::now();
                        start
                            .duration_since(UNIX_EPOCH)
                            .expect("unreachable")
                            .as_millis()
                    };

                    if let Ok(body) = serde_json::from_slice::<GtpGuideTcpRequest<H>>(&buf) {
                        match body {
                            GtpGuideTcpRequest::Tour(tour) => {
                                let tour_res = GtpCrypto::process_tour(
                                    &user_address.to_string(),
                                    &secrets,
                                    address_this,
                                    server_address,
                                    tour,
                                    ts,
                                );
                                let response = Response::from_string(
                                    serde_json::to_string(&tour_res).unwrap(),
                                );
                                let _ = request.respond(response);
                            }
                            GtpGuideTcpRequest::Aggregation(agg) => {
                                let agg_res = GtpCrypto::aggregate(
                                    &user_address.to_string(),
                                    &secrets,
                                    address_this,
                                    server_address,
                                    agg,
                                    ts,
                                );
                                let response =
                                    Response::from_string(serde_json::to_string(&agg_res).unwrap());
                                let _ = request.respond(response);
                            }
                        }
                    }
                });
            }
            if rx.try_recv().is_ok() {
                break;
            }
        });
        (handle, tx)
    }
}
