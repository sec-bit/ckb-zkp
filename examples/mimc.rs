use rand::prelude::*;
use zkp::{prove, prove_to_bytes, verify, verify_from_bytes, Curve, Gadget, Scheme};

fn main() {
    let bytes = vec![1, 2, 3, 4, 5]; // this is your secret.
    let rng = thread_rng();

    // use Proof struct.
    use curve::bn_256::Bn_256;
    let proof =
        prove::<Bn_256, ThreadRng>(Gadget::MiMC, Scheme::Groth16, Curve::Bn_256, &bytes, rng)
            .unwrap();
    let is_ok = verify(&proof);
    assert!(is_ok);

    // use Bytes.
    let proof_bytes =
        prove_to_bytes(Gadget::MiMC, Scheme::Groth16, Curve::Bn_256, &bytes, rng).unwrap();
    let is_ok2 = verify_from_bytes(&proof_bytes);
    assert!(is_ok2);

    println!("all is ok");
}
