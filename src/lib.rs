pub use anyhow::Result;
pub use plonky2::iop::witness::PartialWitness;
pub use plonky2::iop::witness::WitnessWrite;
pub use plonky2::plonk::circuit_builder::CircuitBuilder;
pub use plonky2::field::types::Field;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::circuit_data::VerifierCircuitData;
use plonky2::plonk::circuit_data::VerifierCircuitTarget;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::proof::ProofWithPublicInputsTarget;

pub type C = plonky2::plonk::config::PoseidonGoldilocksConfig;
pub type F = <C as plonky2::plonk::config::GenericConfig<2>>::F;
pub type CircuitPIVK = Circuit<(ProofWithPublicInputsTarget<2>, VerifierCircuitTarget)>;

pub struct Circuit<T> {
    c: CircuitData<F, C, 2>,
    t: T,
}

impl<T> Circuit<T> {
    pub fn new<Func>(f: Func) -> Self
    where Func: FnOnce(&mut CircuitBuilder<F, 2>) -> T {
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_zk_config());
        let w = f(&mut builder);
        Self { c: builder.build::<C>(), t: w }
    }
    pub fn prove<Func>(&self, f: Func) -> Result<ProofWithPublicInputs<F, C, 2>>
    where Func: FnOnce(&mut PartialWitness<F>, &T) -> Result<()> {
        let mut pw = PartialWitness::<F>::new();
        f(&mut pw, &self.t)?;
        let pi = self.c.prove(pw);
        pi
    }
    pub fn vk(&self) -> VerifierCircuitData<F, C, 2> { self.c.verifier_data() }
}
pub struct Recurse<T> {
    ic: Circuit<T>,
    oc: CircuitPIVK,
}
impl<T> Recurse<T> {
    fn circuit<Func>(f: Func) -> impl FnOnce(&mut CircuitBuilder<F, 2>) -> (ProofWithPublicInputsTarget<2>, VerifierCircuitTarget)
    where Func: FnOnce(&mut CircuitBuilder<F, 2>) -> T {
        |builder| {
            let c = Circuit::new(f).c.common;
            let pi = builder.add_virtual_proof_with_pis(&c);
            let vk = builder.add_virtual_verifier_data(c.config.fri_config.cap_height);
            builder.verify_proof::<C>(&pi, &vk, &c);
            (pi, vk)
        }
    }
    pub fn new<Func>(f: Func) -> Self
    where Func: Fn(&mut CircuitBuilder<F, 2>) -> T {
        Self { ic: Circuit::new(&f), oc: Circuit::new(Self::circuit(&f)) }
    }
    pub fn prove<Func>(&self, f: Func) -> Result<ProofWithPublicInputs<F, C, 2>>
    where Func: FnOnce(&mut PartialWitness<F>, &T) -> Result<()> {
        self.oc.defprove(self.ic.prove(f)?, self.ic.vk())
    }
    pub fn vk(&self) -> VerifierCircuitData<F, C, 2> { self.oc.vk() }
}
pub trait PIVK {
    fn verifier<const N: usize>() -> Self;
    fn defprove(&self, pi: ProofWithPublicInputs<F, C, 2>, vk: VerifierCircuitData<F, C, 2>) -> Result<ProofWithPublicInputs<F, C, 2>>;
}
impl PIVK for CircuitPIVK {
    fn verifier<const N: usize>() -> Self { Self::new(Recurse::circuit(Recurse::circuit(|builder| builder.add_virtual_public_input_arr::<N>()))) }
    fn defprove(&self, pi: ProofWithPublicInputs<F, C, 2>, vk: VerifierCircuitData<F, C, 2>) -> Result<ProofWithPublicInputs<F, C, 2>> {
        self.prove(|w, t| {
            w.set_proof_with_pis_target(&t.0, &pi)?;
            w.set_verifier_data_target(&t.1, &vk.verifier_only)
        })
    }
}
