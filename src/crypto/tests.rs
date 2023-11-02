use super::hmac::Blake3Hasher;
use super::*;

#[test]
fn happy_path() {
    let s1 = GtpCrypto::gen_secret();
    let s2 = GtpCrypto::gen_secret();
    let s3 = GtpCrypto::gen_secret();

    let s4 = GtpCrypto::gen_secret();
    let s5 = GtpCrypto::gen_secret();
    let s6 = GtpCrypto::gen_secret();

    let server_keys = vec![
        ("localhost:4001".to_string(), s1),
        ("localhost:4002".to_string(), s2),
        ("localhost:8000".to_string(), s4),
    ];
    let guide1_keys = vec![
        ("localhost:8000".to_string(), s1),
        ("localhost:4001".to_string(), s5),
        ("localhost:4002".to_string(), s3),
    ];
    let guide2_keys = vec![
        ("localhost:8000".to_string(), s2),
        ("localhost:4001".to_string(), s3),
        ("localhost:4002".to_string(), s6),
    ];

    let server_secret = GtpCrypto::gen_secret();

    let client_addr = "localhost:5432";

    let length = 4;

    let setup_response: GtpSetupResponse<Blake3Hasher> = GtpCrypto::setup(
        &client_addr.to_string(),
        length,
        &server_keys,
        server_secret,
        "localhost:8000".to_string(),
        10,
    );

    let mut path = Vec::new();

    let mut hxor = setup_response.h0.clone();

    let mut request: GtpTourRequest<Blake3Hasher> = GtpTourRequest {
        h0: setup_response.h0,
        length: setup_response.length,
        step: 1,
        previous_ts: setup_response.ts,
        previous_msg: setup_response.msg,
        previous_msg_2: setup_response.msg,
        address_1: setup_response.address_1.clone(),
        previous_address: "localhost:8000".to_string(),
    };

    path.push(setup_response.address_1.clone());

    let tour_result = if setup_response.address_1 == "localhost:4001".to_string() {
        GtpCrypto::process_tour(
            &client_addr.to_string(),
            &guide1_keys,
            "localhost:4001".to_string(),
            "localhost:8000".to_string(),
            request.clone(),
            11,
        )
    } else {
        GtpCrypto::process_tour(
            &client_addr.to_string(),
            &guide2_keys,
            "localhost:4002".to_string(),
            "localhost:8000".to_string(),
            request.clone(),
            11,
        )
    };
    let tour_result = tour_result.unwrap();

    hxor = Blake3Hasher::xor(hxor, tour_result.h);

    request.previous_msg_2 = request.previous_msg;
    request.previous_msg = tour_result.msg;
    request.previous_address = setup_response.address_1.clone();
    request.step += 1;
    request.previous_ts = tour_result.ts;

    let last_guide = tour_result.next_guide.clone();
    path.push(last_guide.clone());

    let tour_result = if tour_result.next_guide == "localhost:4001".to_string() {
        GtpCrypto::process_tour(
            &client_addr.to_string(),
            &guide1_keys,
            "localhost:4001".to_string(),
            "localhost:8000".to_string(),
            request.clone(),
            12,
        )
    } else {
        GtpCrypto::process_tour(
            &client_addr.to_string(),
            &guide2_keys,
            "localhost:4002".to_string(),
            "localhost:8000".to_string(),
            request.clone(),
            12,
        )
    };
    let tour_result = tour_result.unwrap();

    hxor = Blake3Hasher::xor(hxor, tour_result.h);

    request.previous_msg_2 = request.previous_msg;
    request.previous_msg = tour_result.msg;
    request.previous_address = last_guide;
    request.step += 1;
    request.previous_ts = tour_result.ts;

    let last_guide = tour_result.next_guide.clone();
    path.push(last_guide.clone());

    let tour_result = if tour_result.next_guide == "localhost:4001".to_string() {
        GtpCrypto::process_tour(
            &client_addr.to_string(),
            &guide1_keys,
            "localhost:4001".to_string(),
            "localhost:8000".to_string(),
            request.clone(),
            13,
        )
    } else {
        GtpCrypto::process_tour(
            &client_addr.to_string(),
            &guide2_keys,
            "localhost:4002".to_string(),
            "localhost:8000".to_string(),
            request.clone(),
            13,
        )
    };
    let tour_result = tour_result.unwrap();

    hxor = Blake3Hasher::xor(hxor, tour_result.h);

    let aggregation_request: GtpAggregationRequest<Blake3Hasher> = GtpAggregationRequest {
        h0: setup_response.h0,
        hl: hxor,
        length: setup_response.length,
        step: setup_response.length,
        pervious_ts: tour_result.ts,
        previous_msg: tour_result.msg,
        previous_msg_2: request.previous_msg,
        address_1: setup_response.address_1.clone(),
        address_this: last_guide,
        path: path.clone(),
    };

    let aggregation_result = if setup_response.address_1 == "localhost:4001".to_string() {
        GtpCrypto::aggregate(
            &client_addr.to_string(),
            &guide1_keys,
            "localhost:4001".to_string(),
            "localhost:8000".to_string(),
            aggregation_request.clone(),
            14,
        )
    } else {
        GtpCrypto::aggregate(
            &client_addr.to_string(),
            &guide2_keys,
            "localhost:4002".to_string(),
            "localhost:8000".to_string(),
            aggregation_request.clone(),
            14,
        )
    };
    let aggregation_result = aggregation_result.unwrap();

    assert!(GtpCrypto::verify::<Blake3Hasher>(
        &client_addr.to_string(),
        &server_keys,
        server_secret,
        GtpVerificationRequest {
            h0: setup_response.h0,
            h_sol: aggregation_result.h_sol,
            length: setup_response.length,
            first_ts: setup_response.ts,
            last_ts: aggregation_result.ts,
            address_1: setup_response.address_1,
        },
        5,
        17,
    ));
}
