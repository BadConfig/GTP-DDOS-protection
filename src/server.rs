use crate::bootstrap::Config;
use crate::crypto::hmac::Hmac;
use crate::crypto::{
    Address, GtpCrypto, GtpSetupResponse, GtpVerificationRequest, Secret, SecretsStorage,
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

//use dashmap::DashMap;
use rand::seq::SliceRandom;
use serde::de::DeserializeOwned;
use tiny_http::{Response, Server};

use std::sync::Arc;

pub struct QuoteServer {
    secrets: Arc<SecretsStorage>,
    address: Address,
    //TODO: this might be useful to prevent taking multiple chalenges at once and to create
    //priority queue
    //clients: DashMap<Address, u128>,
    gtp_expiration: u128,
    secret: Secret,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRequest<H: Hmac> {
    pub gtp_solution: Option<GtpVerificationRequest<H>>,
}

static QUOTES: &[&str] = &[
    "Lorem ipsum dolor sit amet",
    "consectetur adipiscing elit",
    "sed do eiusmod tempor incididunt",
    "ut labore et dolore magna aliquaLorem",
    "ipsum dolor sit amet",
    "consectetur adipiscing elit",
    "sed do eiusmod tempor incididunt",
    "ut labore et dolore magna aliqua",
];

impl QuoteServer {
    pub fn from_config(config: &Config, address: Address, gtp_expiration: u128) -> Self {
        Self {
            secrets: Arc::new(
                config
                    .secrets
                    .get(&address)
                    .expect("Guide address should present in config")
                    .to_owned(),
            ),
            address,
            gtp_expiration,
            secret: GtpCrypto::gen_secret(),
        }
    }

    pub async fn serve<H: Hmac + DeserializeOwned>(
        self,
        bind_address: Address,
    ) -> (JoinHandle<()>, oneshot::Sender<()>) {
        let server = Server::http(bind_address).unwrap();

        let (tx, mut rx) = oneshot::channel();

        println!("server started accepting connections");
        let handle = tokio::task::spawn_blocking(move || loop {
            if let Ok(Some(mut request)) = server.recv_timeout(Duration::from_millis(100)) {
                let secrets = self.secrets.clone();
                let address = self.address.clone();
                let server_secret = self.secret;

                tokio::spawn(async move {
                    let user_address = request.remote_addr().unwrap().clone().ip().to_string();
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

                    if let Ok(body) = serde_json::from_slice::<UserRequest<H>>(&buf) {
                        if let Some(gtp_solution) = body.gtp_solution {
                            if GtpCrypto::verify(
                                &user_address,
                                &secrets,
                                server_secret,
                                gtp_solution,
                                self.gtp_expiration,
                                ts,
                            ) {
                                let response = serde_json::to_string(&serde_json::json!({
                                "text": QUOTES.choose(&mut rand::thread_rng()).unwrap().to_string(),
                            }))
                            .unwrap();
                                let response = Response::from_string(response);
                                request.respond(response).unwrap();
                            }
                        }
                    } else {
                        let challenge: GtpSetupResponse<H> = GtpCrypto::setup(
                            &user_address,
                            10,
                            &secrets,
                            server_secret,
                            address,
                            ts,
                        );
                        let response =
                            Response::from_string(serde_json::to_string(&challenge).unwrap());
                        let _ = request.respond(response);
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
