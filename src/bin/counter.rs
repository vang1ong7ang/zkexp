use zkexp::*;

fn main() -> Result<()> {
    let rec = Recurse::new(|builder| {
        let (x, y) = (builder.add_virtual_target(), builder.add_virtual_target());
        builder.register_public_inputs(&[x, y]);
        let z = builder.sub(x, y);
        builder.assert_one(z);
        [x, y]
    });
    let pi = rec.prove(|w, t| w.set_target_arr(t, &[F::ONE, F::ZERO]))?;
    rec.vk().verify(pi.clone())?;
    let pivk = CircuitPIVK::verifier::<2>();
    let pi = pivk.defprove(pi, rec.vk())?;
    pivk.vk().verify(pi)
}
