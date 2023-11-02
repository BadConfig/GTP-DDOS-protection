use crate::bootstrap::Config;
use crate::crypto::hmac::Hmac;
use crate::crypto::{
    Address, GtpCrypto, GtpSetupResponse, GtpVerificationRequest, Secret, SecretsStorage,
};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use rand::seq::SliceRandom;
use serde::de::DeserializeOwned;
use tiny_http::{Response, Server};

use std::error::Error;
use std::sync::Arc;

pub struct QuoteServer {
    secrets: Arc<SecretsStorage>,
    address: Address,
    clients: DashMap<Address, u128>,
    rps_to_ddos: u128,
    gtp_expiration: u128,
    secret: Secret,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRequest<H: Hmac> {
    gtp_solution: Option<GtpVerificationRequest<H>>,
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
    fn from_config(
        config: Config,
        address: Address,
        rps_to_ddos: u128,
        gtp_expiration: u128,
    ) -> Self {
        Self {
            secrets: Arc::new(
                config
                    .secrets
                    .get(&address)
                    .expect("Guide address should present in config")
                    .to_owned(),
            ),
            address,
            clients: Default::default(),
            rps_to_ddos,
            gtp_expiration,
            secret: GtpCrypto::gen_secret(),
        }
    }

    async fn serve<H: Hmac + DeserializeOwned>(self) -> Result<(), Box<dyn Error>> {
        let server = Server::http(self.address.clone()).unwrap();

        tokio::task::spawn_blocking(move || {
            //let start_ts = {
            //    let start = SystemTime::now();
            //    start.duration_since(UNIX_EPOCH).expect("unreachable")
            //};
            for mut request in server.incoming_requests() {
                //let elapsed_ts = {
                //    let start = SystemTime::now();
                //    start.duration_since(UNIX_EPOCH).expect("unreachable")
                //};

                //if start_ts - elapsed_ts {}

                let secrets = self.secrets.clone();
                let clients = self.clients.clone();
                let address = self.address.clone();
                let server_secret = self.secret.clone();

                tokio::spawn(async move {
                    let user_address = request.remote_addr().unwrap().clone().to_string();

                    let mut buf = Vec::new();
                    request.as_reader().read_to_end(&mut buf).unwrap();

                    //clients.insert(user_address, ts);
                    {
                        let user = clients.get_mut(&user_address);
                        if user.is_none() {
                            let response = Response::from_string(
                                QUOTES.choose(&mut rand::thread_rng()).unwrap().to_string(),
                            );
                            request.respond(response);
                            return;
                        }
                    }

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
                                let user = clients.remove(&user_address);
                                let response = Response::from_string(
                                    QUOTES.choose(&mut rand::thread_rng()).unwrap().to_string(),
                                );
                                request.respond(response);
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
                            clients.insert(user_address, ts);
                            let response =
                                Response::from_string(serde_json::to_string(&challenge).unwrap());
                            request.respond(response);
                        }
                    }
                });
            }
        })
        .await?;
        Ok(())
    }
}
