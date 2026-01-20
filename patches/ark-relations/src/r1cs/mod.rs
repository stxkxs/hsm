//! Core interface for working with Rank-1 Constraint Systems (R1CS).

use ark_std::vec::Vec;

/// A result type specialized to `SynthesisError`.
pub type Result<T> = core::result::Result<T, SynthesisError>;

#[macro_use]
mod impl_lc;
mod constraint_system;
mod error;

// trace module disabled - requires tracing-subscriber which has RUSTSEC-2025-0055
// Stub implementations provided below for API compatibility

/// Stub for ConstraintTrace when tracing-subscriber is not available.
/// This type exists for API compatibility but capture() always returns None.
#[derive(Clone, Debug)]
pub struct ConstraintTrace {
    _private: (),
}

impl ConstraintTrace {
    /// Capture is a no-op without tracing-subscriber
    pub fn capture() -> Option<Self> {
        None
    }

    /// Returns empty path without tracing-subscriber
    pub fn path(&self) -> Vec<TraceStep> {
        Vec::new()
    }
}

impl core::fmt::Display for ConstraintTrace {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "<tracing disabled>")
    }
}

/// Stub for TraceStep
#[derive(Debug, Clone, Copy)]
pub struct TraceStep {
    /// Name of the constraint generating span.
    pub name: &'static str,
    /// Name of the module containing the constraint generating span.
    pub module_path: &'static str,
    /// Name of the file containing the constraint generating span.
    pub file: &'static str,
    /// Line number of the constraint generating span.
    pub line: u32,
}

/// Stub for TracingMode
#[derive(PartialEq, Eq, Ord, PartialOrd, Hash, Debug)]
pub enum TracingMode {
    /// Filter for r1cs target only
    OnlyConstraints,
    /// Filter out r1cs target
    NoConstraints,
    /// No filtering
    All,
}

/// Stub for ConstraintLayer - does nothing without tracing-subscriber
pub struct ConstraintLayer<S> {
    /// Mode (unused in stub)
    pub mode: TracingMode,
    _marker: core::marker::PhantomData<S>,
}

impl<S> ConstraintLayer<S> {
    /// Create new stub layer
    pub fn new(mode: TracingMode) -> Self {
        Self { mode, _marker: core::marker::PhantomData }
    }
}

impl<S> Default for ConstraintLayer<S> {
    fn default() -> Self {
        Self::new(TracingMode::All)
    }
}

impl<S> core::fmt::Debug for ConstraintLayer<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConstraintLayer")
            .field("mode", &self.mode)
            .field("note", &"tracing disabled - stub implementation")
            .finish()
    }
}

pub use tracing::info_span;

pub use ark_ff::{Field, ToConstraintField};
pub use constraint_system::{
    ConstraintMatrices, ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, Namespace,
    OptimizationGoal, SynthesisMode,
};
pub use error::SynthesisError;

use core::cmp::Ordering;

/// A sparse representation of constraint matrices.
pub type Matrix<F> = Vec<Vec<(F, usize)>>;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
/// An opaque counter for symbolic linear combinations.
pub struct LcIndex(usize);

/// Represents the different kinds of variables present in a constraint system.
#[derive(Copy, Clone, PartialEq, Debug, Eq)]
pub enum Variable {
    /// Represents the "zero" constant.
    Zero,
    /// Represents of the "one" constant.
    One,
    /// Represents a public instance variable.
    Instance(usize),
    /// Represents a private witness variable.
    Witness(usize),
    /// Represents of a linear combination.
    SymbolicLc(LcIndex),
}

/// A linear combination of variables according to associated coefficients.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LinearCombination<F: Field>(pub Vec<(F, Variable)>);

/// Generate a `Namespace` with name `name` from `ConstraintSystem` `cs`.
/// `name` must be a `&'static str`.
#[macro_export]
macro_rules! ns {
    ($cs:expr, $name:expr) => {{
        let span = $crate::r1cs::info_span!(target: "r1cs", $name);
        let id = span.id();
        let _enter_guard = span.enter();
        core::mem::forget(_enter_guard);
        core::mem::forget(span);
        $crate::r1cs::Namespace::new($cs.clone(), id)
    }};
}

impl Variable {
    /// Is `self` the zero variable?
    #[inline]
    pub fn is_zero(&self) -> bool {
        matches!(self, Variable::Zero)
    }

    /// Is `self` the one variable?
    #[inline]
    pub fn is_one(&self) -> bool {
        matches!(self, Variable::One)
    }

    /// Is `self` an instance variable?
    #[inline]
    pub fn is_instance(&self) -> bool {
        matches!(self, Variable::Instance(_))
    }

    /// Is `self` a witness variable?
    #[inline]
    pub fn is_witness(&self) -> bool {
        matches!(self, Variable::Witness(_))
    }

    /// Is `self` a linear combination?
    #[inline]
    pub fn is_lc(&self) -> bool {
        matches!(self, Variable::SymbolicLc(_))
    }

    /// Get the `LcIndex` in `self` if `self.is_lc()`.
    #[inline]
    pub fn get_lc_index(&self) -> Option<LcIndex> {
        match self {
            Variable::SymbolicLc(index) => Some(*index),
            _ => None,
        }
    }

    /// Returns `Some(usize)` if `!self.is_lc()`, and `None` otherwise.
    #[inline]
    pub fn get_index_unchecked(&self, witness_offset: usize) -> Option<usize> {
        match self {
            // The one variable always has index 0
            Variable::One => Some(0),
            Variable::Instance(i) => Some(*i),
            Variable::Witness(i) => Some(witness_offset + *i),
            _ => None,
        }
    }
}

impl PartialOrd for Variable {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        use Variable::*;
        match (self, other) {
            (Zero, Zero) => Some(Ordering::Equal),
            (One, One) => Some(Ordering::Equal),
            (Zero, _) => Some(Ordering::Less),
            (One, _) => Some(Ordering::Less),
            (_, Zero) => Some(Ordering::Greater),
            (_, One) => Some(Ordering::Greater),

            (Instance(i), Instance(j)) | (Witness(i), Witness(j)) => i.partial_cmp(j),
            (Instance(_), Witness(_)) => Some(Ordering::Less),
            (Witness(_), Instance(_)) => Some(Ordering::Greater),

            (SymbolicLc(i), SymbolicLc(j)) => i.partial_cmp(j),
            (_, SymbolicLc(_)) => Some(Ordering::Less),
            (SymbolicLc(_), _) => Some(Ordering::Greater),
        }
    }
}

impl Ord for Variable {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap()
    }
}
