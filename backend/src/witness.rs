use anyhow::{anyhow, Result};
use sp1_sdk::{Elf, ExecutionReport, MockProver, Prover, SP1Stdin};

use shared::{ProgramInput, ProofOutput};

pub struct ProofResult {
    pub output: ProofOutput,
    pub report: ExecutionReport,
}

pub async fn run_proof(
    input: ProgramInput,
    elf: &[u8],
    client: &MockProver,
) -> Result<ProofResult> {
    // borsh-encoded ProgramInput, written as a single stdin chunk that the
    // guest reads via `sp1_zkvm::io::read_vec()`.
    let input_bytes = borsh::to_vec(&input).map_err(|e| anyhow!("borsh serialize input: {e}"))?;
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(input_bytes);

    let (public_values, report) = client
        .execute(Elf::from(elf), stdin)
        .await
        .map_err(|e| anyhow!("SP1 execution error: {e}"))?;

    let pv_bytes = public_values.as_slice();
    if pv_bytes.is_empty() {
        return Err(anyhow!(
            "SP1 program produced no public output (guest likely panicked)"
        ));
    }

    let output: ProofOutput = borsh::from_slice(pv_bytes)
        .map_err(|e| anyhow!("borsh deserialize public output: {e}"))?;
    Ok(ProofResult { output, report })
}
