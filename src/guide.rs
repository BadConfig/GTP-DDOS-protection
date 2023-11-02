use crate::bootstrap::Config;
use crate::crypto::hmac::Hmac;
use crate::crypto::{Address, GtpCrypto, GtpGuideTcpRequest, SecretsStorage};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::de::DeserializeOwned;
use tiny_http::{Response, Server};

use std::error::Error;
use std::sync::Arc;

pub struct Guide {
    secrets: Arc<SecretsStorage>,
    address: Address,
    server_address: Address,
}

impl Guide {
    fn from_config(config: Config, address: Address) -> Self {
        Self {
            secrets: Arc::new(
                config
                    .secrets
                    .get(&address)
                    .expect("Guide address should present in config")
                    .to_owned(),
            ),
            server_address: config.server_address,
            address,
        }
    }

    async fn serve<H: Hmac + DeserializeOwned>(self) -> Result<(), Box<dyn Error>> {
        let server = Server::http(self.address.clone()).unwrap();

        tokio::task::spawn_blocking(move || {
            for mut request in server.incoming_requests() {
                let secrets = self.secrets.clone();
                let address_this = self.address.clone();
                let server_address = self.server_address.clone();
                tokio::spawn(async move {
                    println!(
                        "received request! method: {:?}, url: {:?}, headers: {:?}",
                        request.method(),
                        request.url(),
                        request.headers()
                    );
                    let user_address = request.remote_addr().unwrap().clone();

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
                                GtpCrypto::process_tour(
                                    &user_address.to_string(),
                                    &secrets,
                                    address_this,
                                    server_address,
                                    tour,
                                    ts,
                                );
                                let response = Response::from_string("hello world");
                                request.respond(response);
                            }
                            GtpGuideTcpRequest::Aggregation(agg) => {
                                GtpCrypto::aggregate(
                                    &user_address.to_string(),
                                    &secrets,
                                    address_this,
                                    server_address,
                                    agg,
                                    ts,
                                );
                                let response = Response::from_string("hello world");
                                request.respond(response);
                            }
                        }
                    }
                });
            }
        })
        .await?;
        Ok(())
    }
}
