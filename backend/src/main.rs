mod state;
mod witness;

use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use sp1_sdk::{MockProver, ProverClient};
use tokio::sync::Mutex;
use tower_http::cors::{Any, CorsLayer};

use shared::{
    EthOrderWitness, EthSignedOrder, OrderWitness, ProgramInput, RegisterKeyRequest,
    RegisterKeyWitness, SessionKey, SignedOrder,
};
use state::AppState;
use witness::run_proof;

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

#[derive(Clone)]
struct ServerState {
    app: Arc<Mutex<AppState>>,
    prover: Arc<MockProver>,
}

#[tokio::main]
async fn main() {
    let prover = ProverClient::builder().mock().build().await;

    let state = ServerState {
        app: Arc::new(Mutex::new(AppState::new())),
        prover: Arc::new(prover),
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/register-key", post(register_key))
        .route("/place-order", post(place_order))
        .route("/place-order-eth", post(place_order_eth))
        .route("/state", get(get_state))
        .layer(cors)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3001").await.unwrap();
    println!("Backend listening on 0.0.0.0:3001");
    axum::serve(listener, app).await.unwrap();
}

async fn register_key(
    State(state): State<ServerState>,
    Json(req): Json<RegisterKeyRequest>,
) -> impl IntoResponse {
    let pubkey_bytes: [u8; 32] = match hex::decode(&req.pubkey_hex) {
        Ok(b) if b.len() == 32 => b.try_into().unwrap(),
        _ => return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid pubkey_hex"}))),
    };

    let key = SessionKey {
        pubkey: pubkey_bytes,
        key_index: req.key_index,
    };

    let (old_leaf_hash, old_root, new_root, siblings, leaf_index) = {
        let mut app = state.app.lock().await;
        app.register_key(req.account_address, key)
    };

    let witness = RegisterKeyWitness {
        request: req,
        old_leaf_hash,
        old_session_key_root: old_root,
        new_session_key_root: new_root,
        merkle_siblings: siblings,
        leaf_index,
    };

    let input = ProgramInput::RegisterKey(witness);

    match run_proof(input, ELF, &state.prover).await {
        Ok(result) => {
            let report = &result.report;
            let total_instructions = report.total_instruction_count();
            let total_syscalls = report.total_syscall_count();
            let sys_call_counts = report.syscall_counts.clone();
            println!(
                "REGISTER_KEY proof succeeded: account={} key_index={} new_root={} | instructions={} syscalls={} gas={:?} sys_call_counts={:?}",
                hex::encode(result.output.account_address),
                result.output.key_index,
                hex::encode(result.output.new_session_key_root),
                total_instructions,
                total_syscalls,
                report.gas(),
                sys_call_counts
            );
            (
                StatusCode::OK,
                Json(json!({
                    "success": true,
                    "new_root": hex::encode(result.output.new_session_key_root),
                    "proof_type": "REGISTER_KEY",
                    "execution_report": {
                        "total_instructions": total_instructions,
                        "total_syscalls": total_syscalls,
                        "gas": report.gas(),
                        "touched_memory_addresses": report.touched_memory_addresses,
                        "exit_code": report.exit_code,
                    }
                })),
            )
        }
        Err(e) => {
            eprintln!("REGISTER_KEY proof failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("proof failed: {e}")})),
            )
        }
    }
}

async fn place_order(
    State(state): State<ServerState>,
    Json(order): Json<SignedOrder>,
) -> impl IntoResponse {
    let (session_key, siblings, leaf_index, root) = {
        let app = state.app.lock().await;
        match app.get_key_proof(order.account_address, order.key_index) {
            Some((key, sibs, idx)) => (key, sibs, idx, app.current_root),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "Session key not registered"})),
                )
            }
        }
    };

    let witness = OrderWitness {
        order: order.clone(),
        session_key,
        session_key_root: root,
        merkle_siblings: siblings,
        leaf_index,
    };

    let input = ProgramInput::VerifyOrder(witness);

    match run_proof(input, ELF, &state.prover).await {
        Ok(result) => {
            let report = &result.report;
            let total_instructions = report.total_instruction_count();
            let total_syscalls = report.total_syscall_count();
            println!(
                "VERIFY_ORDER proof succeeded: account={} key_index={} | instructions={} syscalls={} gas={:?}",
                hex::encode(result.output.account_address),
                result.output.key_index,
                total_instructions,
                total_syscalls,
                report.gas(),
            );
            (
                StatusCode::OK,
                Json(json!({
                    "success": true,
                    "proof_type": "VERIFY_ORDER",
                    "order": order,
                    "execution_report": {
                        "total_instructions": total_instructions,
                        "total_syscalls": total_syscalls,
                        "gas": report.gas(),
                        "touched_memory_addresses": report.touched_memory_addresses,
                        "exit_code": report.exit_code,
                    }
                })),
            )
        }
        Err(e) => {
            eprintln!("VERIFY_ORDER proof failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("proof failed: {e}")})),
            )
        }
    }
}

async fn place_order_eth(
    State(state): State<ServerState>,
    Json(order): Json<EthSignedOrder>,
) -> impl IntoResponse {
    let witness = EthOrderWitness {
        order: order.clone(),
    };

    let input = ProgramInput::VerifyOrderEth(witness);

    match run_proof(input, ELF, &state.prover).await {
        Ok(result) => {
            let report = &result.report;
            let total_instructions = report.total_instruction_count();
            let total_syscalls = report.total_syscall_count();
            println!(
                "VERIFY_ORDER_ETH proof succeeded: account={} key_index={} | instructions={} syscalls={} gas={:?}",
                hex::encode(result.output.account_address),
                result.output.key_index,
                total_instructions,
                total_syscalls,
                report.gas(),
            );
            (
                StatusCode::OK,
                Json(json!({
                    "success": true,
                    "proof_type": "VERIFY_ORDER_ETH",
                    "order": order,
                    "execution_report": {
                        "total_instructions": total_instructions,
                        "total_syscalls": total_syscalls,
                        "gas": report.gas(),
                        "touched_memory_addresses": report.touched_memory_addresses,
                        "exit_code": report.exit_code,
                    }
                })),
            )
        }
        Err(e) => {
            eprintln!("VERIFY_ORDER_ETH proof failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("proof failed: {e}")})),
            )
        }
    }
}

async fn get_state(State(state): State<ServerState>) -> impl IntoResponse {
    let app = state.app.lock().await;
    Json(json!({
        "session_key_root": hex::encode(app.current_root),
        "registered_keys": app.session_keys.len()
    }))
}
