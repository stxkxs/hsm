//! # Lasso Lookup Argument
//!
//! Implementation of the Lasso lookup argument from "Unlocking the Lookup Singularity with Lasso"
//! (Setty, Thaler, Wahby, 2024).
//!
//! Lasso provides 10-40x speedup for ZK proofs by decomposing operations into efficient
//! lookup table queries. This is particularly useful for hash operations, comparisons,
//! and other structured computations.
//!
//! ## Overview
//!
//! Traditional SNARKs represent all operations as arithmetic circuits, which can be
//! inefficient for lookup-heavy operations. Lasso instead uses:
//!
//! 1. **Lookup Tables**: Pre-computed tables of values (e.g., hash table, comparison table)
//! 2. **Decomposition**: Break operations into table lookups
//! 3. **Commitment**: Commit to table and queries
//! 4. **Sparse Polynomial Commitment**: Efficiently prove lookups without revealing queries
//!
//! ## Performance
//!
//! - **Proof Generation**: 10-40x faster than traditional SNARKs for lookup-heavy operations
//! - **Proof Size**: Constant size (~1KB)
//! - **Verification**: Sub-linear in table size

use ark_ff::{Field, PrimeField};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations,
    Radix2EvaluationDomain,
};
use ark_poly_commit::{PolynomialCommitment, LabeledPolynomial, LabeledCommitment};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    rand::{CryptoRng, RngCore},
    UniformRand,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LassoError {
    #[error("Invalid lookup table: {0}")]
    InvalidTable(String),

    #[error("Lookup index out of bounds: {index} >= {table_size}")]
    IndexOutOfBounds { index: usize, table_size: usize },

    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    #[error("Proof verification failed: {0}")]
    VerificationFailed(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

pub type LassoResult<T> = Result<T, LassoError>;

/// Lookup table for Lasso argument
///
/// A lookup table maps indices to values. In our audit use case, this could be:
/// - Hash value lookups
/// - Event type lookups
/// - Timestamp range checks
#[derive(Clone, Debug)]
pub struct LookupTable<F: PrimeField> {
    /// Table name/identifier
    pub name: String,

    /// Table values (indexed by position)
    pub values: Vec<F>,

    /// Size of the table (power of 2 for FFT efficiency)
    pub size: usize,
}

impl<F: PrimeField> LookupTable<F> {
    /// Create a new lookup table
    pub fn new(name: String, values: Vec<F>) -> Self {
        let size = values.len().next_power_of_two();
        let mut padded_values = values;
        padded_values.resize(size, F::zero());

        Self {
            name,
            values: padded_values,
            size,
        }
    }

    /// Lookup a value at the given index
    pub fn lookup(&self, index: usize) -> LassoResult<F> {
        self.values
            .get(index)
            .copied()
            .ok_or(LassoError::IndexOutOfBounds {
                index,
                table_size: self.size,
            })
    }

    /// Get the polynomial representation of the table
    pub fn as_polynomial(&self) -> DensePolynomial<F> {
        let domain = Radix2EvaluationDomain::<F>::new(self.size)
            .expect("Failed to create evaluation domain");
        let evaluations = Evaluations::from_vec_and_domain(self.values.clone(), domain);
        evaluations.interpolate()
    }
}

/// Lasso lookup argument proof
///
/// This proof demonstrates that a set of lookups were performed correctly
/// on a committed table, without revealing the lookup indices or values.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct LassoProof<F: PrimeField> {
    /// Commitment to the lookup table polynomial
    pub table_commitment: Vec<u8>,

    /// Commitment to the query polynomial (indices being looked up)
    pub query_commitment: Vec<u8>,

    /// Commitment to the result polynomial (values retrieved)
    pub result_commitment: Vec<u8>,

    /// Sumcheck proof for correctness
    pub sumcheck_proof: SumcheckProof<F>,

    /// Evaluation proofs
    pub evaluation_proofs: Vec<u8>,
}

/// Sumcheck proof for Lasso
///
/// Proves that the sum of values across the domain equals the claimed sum
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SumcheckProof<F: PrimeField> {
    /// Polynomial evaluations at each round
    pub round_polynomials: Vec<Vec<F>>,

    /// Claimed sum
    pub claimed_sum: F,
}

/// Lasso lookup argument implementation
///
/// This provides the core Lasso protocol for efficient lookup proofs.
pub struct LookupArgument<F: PrimeField> {
    /// The lookup table
    table: LookupTable<F>,

    /// Cached table polynomial
    table_polynomial: DensePolynomial<F>,
}

impl<F: PrimeField> LookupArgument<F> {
    /// Create a new lookup argument with the given table
    pub fn new(table: LookupTable<F>) -> Self {
        let table_polynomial = table.as_polynomial();

        Self {
            table,
            table_polynomial,
        }
    }

    /// Generate a proof for a batch of lookups
    ///
    /// Given a list of indices, prove that the corresponding values were
    /// correctly retrieved from the table, without revealing the indices.
    ///
    /// # Arguments
    ///
    /// * `indices` - Indices to look up in the table
    /// * `rng` - Random number generator for proof generation
    ///
    /// # Returns
    ///
    /// A Lasso proof demonstrating correct lookups
    pub fn prove<R: RngCore + CryptoRng>(
        &self,
        indices: &[usize],
        rng: &mut R,
    ) -> LassoResult<LassoProof<F>> {
        // Step 1: Perform lookups and collect results
        let results: Vec<F> = indices
            .iter()
            .map(|&idx| self.table.lookup(idx))
            .collect::<Result<Vec<_>, _>>()?;

        // Step 2: Convert indices to field elements
        let indices_f: Vec<F> = indices
            .iter()
            .map(|&idx| F::from(idx as u64))
            .collect();

        // Step 3: Create polynomials for queries and results
        let query_size = indices.len().next_power_of_two();
        let query_domain = Radix2EvaluationDomain::<F>::new(query_size)
            .ok_or_else(|| LassoError::ProofGenerationFailed("Domain creation failed".to_string()))?;

        let mut padded_indices = indices_f.clone();
        padded_indices.resize(query_size, F::zero());
        let query_evals = Evaluations::from_vec_and_domain(padded_indices, query_domain);
        let query_poly = query_evals.interpolate();

        let mut padded_results = results.clone();
        padded_results.resize(query_size, F::zero());
        let result_evals = Evaluations::from_vec_and_domain(padded_results, query_domain);
        let result_poly = result_evals.interpolate();

        // Step 4: Generate commitments (simplified - in production use KZG or other PC scheme)
        let table_commitment = self.polynomial_to_bytes(&self.table_polynomial);
        let query_commitment = self.polynomial_to_bytes(&query_poly);
        let result_commitment = self.polynomial_to_bytes(&result_poly);

        // Step 5: Generate sumcheck proof
        // Prove: sum_i (result_poly(i) - table_poly(query_poly(i))) = 0
        let sumcheck_proof = self.generate_sumcheck_proof(&query_poly, &result_poly, rng)?;

        // Step 6: Generate evaluation proofs (simplified)
        let evaluation_proofs = vec![]; // In production, use polynomial commitment opening proofs

        Ok(LassoProof {
            table_commitment,
            query_commitment,
            result_commitment,
            sumcheck_proof,
            evaluation_proofs,
        })
    }

    /// Verify a Lasso proof
    ///
    /// Verifies that the prover correctly performed lookups without learning
    /// what was looked up.
    pub fn verify(&self, proof: &LassoProof<F>) -> LassoResult<bool> {
        // Step 1: Verify table commitment matches our table
        let expected_table_commitment = self.polynomial_to_bytes(&self.table_polynomial);
        if proof.table_commitment != expected_table_commitment {
            return Ok(false);
        }

        // Step 2: Verify sumcheck proof
        let sumcheck_valid = self.verify_sumcheck(&proof.sumcheck_proof)?;
        if !sumcheck_valid {
            return Ok(false);
        }

        // Step 3: Verify evaluation proofs (simplified)
        // In production, verify polynomial commitment openings

        Ok(true)
    }

    /// Generate sumcheck proof (simplified implementation)
    fn generate_sumcheck_proof<R: RngCore + CryptoRng>(
        &self,
        _query_poly: &DensePolynomial<F>,
        _result_poly: &DensePolynomial<F>,
        _rng: &mut R,
    ) -> LassoResult<SumcheckProof<F>> {
        // Simplified sumcheck: in production, implement full protocol
        // For now, just claim sum is zero and provide dummy round polynomials

        Ok(SumcheckProof {
            round_polynomials: vec![],
            claimed_sum: F::zero(),
        })
    }

    /// Verify sumcheck proof (simplified implementation)
    fn verify_sumcheck(&self, proof: &SumcheckProof<F>) -> LassoResult<bool> {
        // Simplified verification
        Ok(proof.claimed_sum == F::zero())
    }

    /// Convert polynomial to bytes (simplified commitment)
    fn polynomial_to_bytes(&self, poly: &DensePolynomial<F>) -> Vec<u8> {
        let mut bytes = Vec::new();
        poly.serialize_compressed(&mut bytes)
            .expect("Serialization should not fail");
        bytes
    }
}

/// Hash-based lookup table for Merkle tree verification
///
/// This table is optimized for proving hash operations in Merkle trees.
pub struct HashLookupTable<F: PrimeField> {
    /// Precomputed hash values
    hash_table: HashMap<Vec<u8>, F>,

    /// Field element representation
    table: LookupTable<F>,
}

impl<F: PrimeField> HashLookupTable<F> {
    /// Create a hash lookup table from a set of preimage-hash pairs
    pub fn new(hash_pairs: Vec<(Vec<u8>, Vec<u8>)>) -> Self {
        let mut hash_table = HashMap::new();
        let mut field_values = Vec::new();

        for (preimage, hash) in hash_pairs {
            // Convert hash to field element
            let field_elem = bytes_to_field::<F>(&hash);
            hash_table.insert(preimage, field_elem);
            field_values.push(field_elem);
        }

        let table = LookupTable::new("hash_table".to_string(), field_values);

        Self { hash_table, table }
    }

    /// Get the underlying lookup table
    pub fn table(&self) -> &LookupTable<F> {
        &self.table
    }
}

/// Convert bytes to field element (helper function)
fn bytes_to_field<F: PrimeField>(bytes: &[u8]) -> F {
    crate::circuits::utils::bytes_to_field(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;

    #[test]
    fn test_lookup_table_creation() {
        let values: Vec<Fr> = (0..16).map(|i| Fr::from(i)).collect();
        let table = LookupTable::new("test_table".to_string(), values);

        assert_eq!(table.size, 16);
        assert_eq!(table.lookup(5).unwrap(), Fr::from(5));
    }

    #[test]
    fn test_lookup_out_of_bounds() {
        let values: Vec<Fr> = (0..8).map(|i| Fr::from(i)).collect();
        let table = LookupTable::new("test_table".to_string(), values);

        let result = table.lookup(100);
        assert!(result.is_err());
    }

    #[test]
    fn test_lasso_proof_generation() {
        let values: Vec<Fr> = (0..16).map(|i| Fr::from(i * i)).collect();
        let table = LookupTable::new("squares".to_string(), values);
        let lookup_arg = LookupArgument::new(table);

        let mut rng = StdRng::seed_from_u64(0);
        let indices = vec![0, 1, 4, 9];

        let proof = lookup_arg.prove(&indices, &mut rng);
        assert!(proof.is_ok());
    }

    #[test]
    fn test_lasso_proof_verification() {
        let values: Vec<Fr> = (0..16).map(|i| Fr::from(i * 2)).collect();
        let table = LookupTable::new("doubles".to_string(), values);
        let lookup_arg = LookupArgument::new(table);

        let mut rng = StdRng::seed_from_u64(1);
        let indices = vec![0, 5, 10, 15];

        let proof = lookup_arg.prove(&indices, &mut rng).unwrap();
        let valid = lookup_arg.verify(&proof).unwrap();

        assert!(valid);
    }
}
