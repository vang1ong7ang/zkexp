use anyhow::Ok;
use plonky2::field::types::Sample;
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::hash::merkle_tree::MerkleTree;
use std::time::Instant;
use zkexp::*;
type H = <C as plonky2::plonk::config::GenericConfig<2>>::InnerHasher;

fn main() -> Result<()> {
    for logn in 1..25 {
        eprintln!("EXP - {logn}: ...");
        let leaves = (0..1 << logn).map(|_| F::rand_vec(1)).collect();
        let tree = MerkleTree::<F, H>::new(leaves, 0);
        eprintln!("array size = {}", tree.leaves.len());
        let index = tree.leaves.len() / 2 - 1;
        let data = tree.get(index)[0];
        let path = tree.prove(index);
        let rec = Recurse::new(|builder| {
            let root = builder.add_virtual_hash_public_input();
            let index = builder.add_virtual_public_input();
            let data = builder.add_virtual_public_input();
            let path = MerkleProofTarget { siblings: builder.add_virtual_hashes(logn) };
            let sels = builder.split_le(index, logn);
            builder.verify_merkle_proof::<H>(vec![data], &sels, root, &path);
            (root, index, data, path)
        });
        let now = Instant::now();
        let pi = rec.prove(|w, t| {
            for i in 0..path.siblings.len() {
                w.set_hash_target(t.3.siblings[i], path.siblings[i])?;
            }
            w.set_target(t.1, F::from_canonical_usize(index))?;
            w.set_target(t.2, data)?;
            w.set_hash_target(t.0, tree.cap.0[0])
        })?;
        eprintln!("C1C2 proving time = {}", now.elapsed().as_millis());
        let now = Instant::now();
        rec.vk().verify(pi.clone())?;
        eprintln!("C1C2 verifying time = {}", now.elapsed().as_millis());
        let pivk = CircuitPIVK::verifier::<2>();
        let now = Instant::now();
        let pi = pivk.defprove(pi, rec.vk())?;
        eprintln!("C3 proving time = {}", now.elapsed().as_millis());
        let now = Instant::now();
        pivk.vk().verify(pi)?;
        eprintln!("C3 verifying time = {}", now.elapsed().as_millis());
    }
    Ok(())
}
