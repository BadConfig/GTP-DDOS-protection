pub mod hmac;
#[cfg(test)]
pub mod tests;
use hmac::Hmac;
use rand::Rng;
use serde::{Deserialize, Serialize};

pub type Secret = [u8; 32];
pub type Address = String;

pub type SecretsStorage = Vec<(Address, Secret)>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GtpSetupResponse<H: Hmac> {
    pub h0: H::Sign,
    pub length: u8,
    pub ts: u128,
    pub msg: H::Sign,
    pub address_1: Address,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GtpVerificationRequest<H: Hmac> {
    pub h0: H::Sign,
    pub h_sol: H::Sign,
    pub length: u8,
    pub first_ts: u128,
    pub last_ts: u128,
    pub address_1: Address,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GtpAggregationRequest<H: Hmac> {
    pub h0: H::Sign,
    pub hl: H::Sign,
    pub length: u8,
    pub step: u8,
    pub pervious_ts: u128,
    pub previous_msg: H::Sign,
    pub previous_msg_2: H::Sign,
    pub address_1: Address,
    pub address_this: Address,
    pub path: Vec<Address>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GtpAggregationResponse<H: Hmac> {
    pub h_sol: H::Sign,
    pub ts: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GtpTourResponse<H: Hmac> {
    pub h: H::Sign,
    pub msg: H::Sign,
    pub ts: u128,
    pub next_guide: Address,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GtpTourRequest<H: Hmac> {
    pub h0: H::Sign,
    pub length: u8,
    pub step: u8,
    pub previous_ts: u128,
    pub previous_msg: H::Sign,
    pub previous_msg_2: H::Sign,
    pub address_1: Address,
    pub previous_address: Address,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GtpGuideTcpRequest<H: Hmac> {
    Tour(GtpTourRequest<H>),
    Aggregation(GtpAggregationRequest<H>),
}

impl<H: Hmac> GtpTourRequest<H> {
    fn verify(&self, secret: Secret, user_address: &Address, address: &Address) -> bool {
        if self.step > 1 {
            let mut value = Vec::new();
            value.extend(self.previous_msg_2.as_ref());
            value.extend(user_address.as_bytes().iter().cloned());
            value.extend([self.length]);
            value.extend([self.step - 1]);
            value.extend(self.previous_address.as_bytes().iter().cloned());
            value.extend(address.as_bytes().iter().cloned());
            value.extend(self.previous_ts.to_le_bytes());
            H::verify(&value, &self.previous_msg, &secret)
        } else {
            let mut value = Vec::new();
            value.extend(user_address.as_bytes().iter().cloned());
            value.extend([self.length]);
            value.extend(self.address_1.as_bytes().iter().cloned());
            value.extend(self.previous_ts.to_le_bytes());
            value.extend(self.h0.as_ref());
            H::verify(&value, &self.previous_msg, &secret)
        }
    }
}

pub struct GtpCrypto;

impl GtpCrypto {
    pub fn gen_secret() -> Secret {
        rand::thread_rng().gen::<[u8; 32]>()
    }

    pub fn setup<H: Hmac>(
        user_address: &Address,
        length: u8,
        storage: &SecretsStorage,
        server_secret: Secret,
        server_address: String,
        ts: u128,
    ) -> GtpSetupResponse<H> {
        let next_guide: usize = rand::thread_rng().gen_range(0..storage.len() - 1);
        let (guide_address, guide_secret) = storage
            .iter()
            .filter(|v| *v.0 != server_address)
            .skip(next_guide)
            .next()
            .expect("unreachable");

        let mut value = Vec::new();
        value.extend(user_address.as_bytes().iter().cloned());
        value.extend([length]);
        value.extend(guide_address.as_bytes().iter().cloned());
        value.extend(ts.to_le_bytes());

        let h0 = H::sign(&value, &server_secret);
        value.extend(h0.as_ref());
        let msg = H::sign(&value, guide_secret);

        GtpSetupResponse {
            h0,
            length,
            ts,
            msg,
            address_1: guide_address.to_owned(),
        }
    }

    pub fn process_tour<H: Hmac>(
        user_address: &Address,
        storage: &SecretsStorage,
        address_this: String,
        server_address: String,
        request: GtpTourRequest<H>,
        ts: u128,
    ) -> Option<GtpTourResponse<H>> {
        let (_, prev_guide_secret) = storage
            .iter()
            .find(|v| v.0 == request.previous_address)
            .expect("unreachable");

        if !request.verify(*prev_guide_secret, user_address, &address_this) {
            return None;
        }
        let next_guide: usize = rand::thread_rng().gen_range(0..storage.len() - 1);
        let (first_guide_address, first_guide_secret) = storage
            .iter()
            .find(|v| v.0 == request.address_1)
            .expect("unreachable");
        let (next_guide_address, next_guide_secret) = if request.step != request.length - 1 {
            storage
                .iter()
                .filter(|v| *v.0 != server_address)
                .skip(next_guide)
                .next()
                .expect("unreachable")
                .to_owned()
        } else {
            (
                first_guide_address.to_owned(),
                first_guide_secret.to_owned(),
            )
        };

        let mut h_value = Vec::new();
        h_value.extend(request.h0.as_ref());
        h_value.extend(user_address.as_bytes());
        h_value.extend([request.length]);
        h_value.extend([request.step]);
        h_value.extend(address_this.as_bytes());
        h_value.extend(next_guide_address.as_bytes().iter().cloned());
        let h = H::sign(&h_value, &first_guide_secret);

        let mut msg_value = Vec::new();
        msg_value.extend(request.previous_msg.as_ref());
        msg_value.extend(user_address.as_bytes().iter().cloned());
        msg_value.extend([request.length]);
        msg_value.extend([request.step]);
        msg_value.extend(address_this.as_bytes().iter().cloned());
        msg_value.extend(next_guide_address.as_bytes().iter().cloned());
        msg_value.extend(ts.to_le_bytes());
        let msg = H::sign(&msg_value, &next_guide_secret);

        Some(GtpTourResponse {
            h,
            msg,
            next_guide: next_guide_address.to_owned(),
            ts,
        })
    }

    pub fn aggregate<H: Hmac>(
        user_address: &Address,
        storage: &SecretsStorage,
        address_this: String,
        server_address: Address,
        request: GtpAggregationRequest<H>,
        ts: u128,
    ) -> Option<GtpAggregationResponse<H>> {
        let mut h = request.h0.clone();
        for (i, address) in request.path.clone().into_iter().enumerate() {
            let (_, guide_secret) = storage
                .iter()
                .find(|v| v.0 == address)
                .expect("unreachable");

            let mut b = Vec::new();
            b.extend(request.h0.as_ref());
            b.extend(user_address.as_bytes().iter().cloned());
            b.extend([request.length]);
            b.extend([i as u8 + 1]);
            b.extend(address.as_bytes().iter().cloned());
            b.extend(
                request
                    .path
                    .get(i + 1)
                    .unwrap_or(&request.address_1)
                    .as_bytes()
                    .iter()
                    .cloned(),
            );
            let b = H::sign(&b, &guide_secret);

            h = H::xor(h, b);
        }

        if request.hl.as_ref() != h.as_ref() {
            return None;
        }

        let (_, server_secret) = storage
            .iter()
            .find(|v| v.0 == server_address)
            .expect("unreachable");

        let mut sol_val = Vec::new();
        sol_val.extend(request.h0.as_ref());
        sol_val.extend(user_address.as_bytes().iter().cloned());
        sol_val.extend([request.length]);
        sol_val.extend(ts.to_le_bytes());
        let sol_h = H::sign(&sol_val, &server_secret);

        Some(GtpAggregationResponse { h_sol: sol_h, ts })
    }

    pub fn verify<H: Hmac>(
        user_address: &Address,
        storage: &SecretsStorage,
        server_secret: Secret,
        request: GtpVerificationRequest<H>,
        time_delta: u128,
        ts: u128,
    ) -> bool {
        let (_, guide_1_secret) = storage
            .iter()
            .find(|v| v.0 == request.address_1)
            .expect("unreachable");

        let mut h0_val = Vec::new();
        h0_val.extend(user_address.as_bytes().iter().cloned());
        h0_val.extend([request.length]);
        h0_val.extend(request.address_1.as_bytes().iter().cloned());
        h0_val.extend(&request.first_ts.to_le_bytes());

        let mut h_sol_val = Vec::new();
        h_sol_val.extend(request.h0.as_ref());
        h_sol_val.extend(user_address.as_bytes().iter().cloned());
        h_sol_val.extend([request.length]);
        h_sol_val.extend(&request.last_ts.to_le_bytes());
        H::verify(&h_sol_val, &request.h_sol, &guide_1_secret)
            && H::verify(&h0_val, &request.h0, &server_secret)
            && ts - request.last_ts < time_delta
    }
}
