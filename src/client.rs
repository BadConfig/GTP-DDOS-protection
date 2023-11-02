use serde::Serialize;
use serde_json::Value;

use crate::{
    crypto::{
        hmac::Hmac, Address, GtpAggregationRequest, GtpAggregationResponse, GtpGuideTcpRequest,
        GtpSetupResponse, GtpTourRequest, GtpTourResponse, GtpVerificationRequest,
    },
    server::UserRequest,
};

pub async fn make_request<H: Hmac + Serialize>(address: Address) -> Option<String> {
    let client = reqwest::Client::new();
    let res = {
        let snd = reqwest::get(format!("http://{}", address.to_owned())).await;
        if snd.is_err() {
            println!("{:?}", snd);
        }
        let resp = snd.unwrap().json::<Value>().await;
        if resp.is_err() {
            println!("{:?}", resp);
        }
        resp.unwrap()
    };
    if let Some(text) = res.get("text") {
        return Some(text.as_str()?.to_string());
    }

    let setup_data = serde_json::from_value::<GtpSetupResponse<H>>(res).ok()?;

    let mut path = vec![setup_data.address_1.clone()];

    let mut previous_msg = setup_data.msg.clone();
    let mut previous_msg_2 = setup_data.msg.clone();
    let mut previous_ts = setup_data.ts;
    let mut previous_address = address.clone();
    let mut new_address = setup_data.address_1.clone();

    let mut h_agg = setup_data.h0.clone();

    for i in 1..setup_data.length {
        let req: GtpTourRequest<H> = GtpTourRequest {
            h0: setup_data.h0.clone(),
            length: setup_data.length,
            step: i,
            previous_ts,
            address_1: setup_data.address_1.clone(),
            previous_address: previous_address.clone(),
            previous_msg: previous_msg.clone(),
            previous_msg_2: previous_msg_2.clone(),
        };
        let req = serde_json::to_string(&GtpGuideTcpRequest::Tour(req)).unwrap();
        let res = {
            let snd = client
                .post(format!("http://{}", new_address.clone()))
                .body(req)
                .send()
                .await;
            if snd.is_err() {
                println!("{:?}", snd);
            }
            let resp = snd.unwrap().json::<Value>().await;
            if resp.is_err() {
                println!("{:?}", resp);
            }
            resp.unwrap()
        };

        let res = serde_json::from_value::<GtpTourResponse<H>>(res).ok()?;

        previous_msg_2 = previous_msg;
        previous_msg = res.msg;
        previous_ts = res.ts;
        previous_address = new_address;
        new_address = res.next_guide;
        path.push(new_address.clone());

        h_agg = H::xor(h_agg, res.h);
    }

    path.pop();
    let agg_req: GtpAggregationRequest<H> = GtpAggregationRequest {
        h0: setup_data.h0.clone(),
        hl: h_agg,
        address_1: setup_data.address_1.clone(),
        address_this: previous_address,
        length: setup_data.length,
        pervious_ts: previous_ts,
        previous_msg,
        previous_msg_2,
        step: setup_data.length,
        path,
    };

    let req = serde_json::to_string(&GtpGuideTcpRequest::Aggregation(agg_req)).unwrap();
    let res = {
        let snd = client
            .post(format!("http://{}", setup_data.address_1.clone()))
            .body(req)
            .send()
            .await;
        if snd.is_err() {
            println!("{:?}", snd);
        }
        let resp = snd.unwrap().json::<Value>().await;
        if resp.is_err() {
            println!("{:?}", resp);
        }
        resp.unwrap()
    };

    let res = serde_json::from_value::<GtpAggregationResponse<H>>(res).ok()?;

    let verification_req: GtpVerificationRequest<H> = GtpVerificationRequest {
        h0: setup_data.h0,
        h_sol: res.h_sol,
        last_ts: res.ts,
        first_ts: setup_data.ts,
        length: setup_data.length,
        address_1: setup_data.address_1,
    };

    let verif_req = UserRequest {
        gtp_solution: Some(verification_req),
    };

    let req = serde_json::to_string(&verif_req).unwrap();
    let res = {
        let snd = client
            .post(format!("http://{}", address.clone()))
            .body(req)
            .send()
            .await;
        if snd.is_err() {
            println!("{:?}", snd);
        }
        let resp = snd.unwrap().json::<Value>().await;
        if resp.is_err() {
            println!("{:?}", resp);
        }
        resp.unwrap()
    };

    res.get("text")
        .and_then(|t| t.as_str().map(|t| t.to_string()))
}
