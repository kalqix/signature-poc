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
    let mut stdin = SP1Stdin::new();
    stdin.write(&input);

    // Execute the SP1 program. If the guest panics, the mock executor
    // may return Ok with empty public values, or propagate an error.
    let (mut public_values, report) = client
        .execute(Elf::from(elf), stdin)
        .await
        .map_err(|e| anyhow!("SP1 execution error: {e}"))?;

    // Guard against reading from empty/corrupt public values
    if public_values.as_slice().is_empty() {
        return Err(anyhow!(
            "SP1 program produced no public output (guest likely panicked)"
        ));
    }

    let output: ProofOutput = public_values.read();
    Ok(ProofResult { output, report })
}
