use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::KemCore;
use rand::rngs::OsRng;

#[test]
fn test_ml_kem() {
    let (dk, ek) = ml_kem::MlKem768::generate(&mut OsRng);
    let (ct, ss1) = ek.encapsulate(&mut OsRng).unwrap();
    let ss2 = dk.decapsulate(&ct).unwrap();
    assert_eq!(ss1, ss2);
}
