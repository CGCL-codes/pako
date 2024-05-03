use std::collections::BTreeMap;

use super::*;
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use rand::rngs::StdRng;
use rand::SeedableRng as _;

impl Hash for &[u8] {
    fn digest(&self) -> Digest {
        Digest(Sha512::digest(self).as_slice()[..32].try_into().unwrap())
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.to_base64())
    }
}

pub fn keys() -> Vec<(PublicKey, SecretKey)> {
    let mut rng = StdRng::from_seed([0; 32]);
    (0..4).map(|_| generate_keypair(&mut rng)).collect()
}

#[test]
fn import_export_public_key() {
    let (public_key, _) = keys().pop().unwrap();
    let export = public_key.to_base64();
    let import = PublicKey::from_base64(&export);
    assert!(import.is_ok());
    assert_eq!(import.unwrap(), public_key);
}

#[test]
fn import_export_secret_key() {
    let (_, secret_key) = keys().pop().unwrap();
    let export = secret_key.to_base64();
    let import = SecretKey::from_base64(&export);
    assert!(import.is_ok());
    assert_eq!(import.unwrap(), secret_key);
}

#[test]
fn verify_valid_signature() {
    // Get a keypair.
    let (public_key, secret_key) = keys().pop().unwrap();

    // Make signature.
    let message: &[u8] = b"Hello, world!";
    let digest = message.digest();
    let signature = Signature::new(&digest, &secret_key);

    // Verify the signature.
    assert!(signature.verify(&digest, &public_key).is_ok());
}

#[test]
fn verify_invalid_signature() {
    // Get a keypair.
    let (public_key, secret_key) = keys().pop().unwrap();

    // Make signature.
    let message: &[u8] = b"Hello, world!";
    let digest = message.digest();
    let signature = Signature::new(&digest, &secret_key);

    // Verify the signature.
    let bad_message: &[u8] = b"Bad message!";
    let digest = bad_message.digest();
    assert!(signature.verify(&digest, &public_key).is_err());
}

#[test]
fn verify_valid_batch() {
    // Make signatures.
    let message: &[u8] = b"Hello, world!";
    let digest = message.digest();
    let mut keys = keys();
    let signatures: Vec<_> = (0..3)
        .map(|_| {
            let (public_key, secret_key) = keys.pop().unwrap();
            (public_key, Signature::new(&digest, &secret_key))
        })
        .collect();

    // Verify the batch.
    assert!(Signature::verify_batch(&digest, &signatures).is_ok());
}

#[test]
fn verify_invalid_batch() {
    // Make 2 valid signatures.
    let message: &[u8] = b"Hello, world!";
    let digest = message.digest();
    let mut keys = keys();
    let mut signatures: Vec<_> = (0..2)
        .map(|_| {
            let (public_key, secret_key) = keys.pop().unwrap();
            (public_key, Signature::new(&digest, &secret_key))
        })
        .collect();

    // Add an invalid signature.
    let (public_key, _) = keys.pop().unwrap();
    signatures.push((public_key, Signature::default()));

    // Verify the batch.
    assert!(Signature::verify_batch(&digest, &signatures).is_err());
}

#[tokio::test]
async fn signature_service() {
    // Get a keypair.
    let (public_key, secret_key) = keys().pop().unwrap();

    // Spawn the signature service.
    let sks = SecretKeyShare::default();
    let mut service = SignatureService::new(secret_key, sks);

    // Request signature from the service.
    let message: &[u8] = b"Hello, world!";
    let digest = message.digest();
    let signature = service.request_signature(digest.clone()).await;

    // Verify the signature we received.
    assert!(signature.verify(&digest, &public_key).is_ok());
}

#[tokio::test]
async fn signature_service_tss() {
    let mut rng = rand::thread_rng();
    let sk_set = SecretKeySet::random(1, &mut rng);
    let pk_set = sk_set.public_keys();
    let ss = SecretShare {
        id: 0,
        name: pk_set.public_key_share(0),
        secret: SerdeSecret(sk_set.secret_key_share(0)),
        pkset: pk_set.clone(),
    };

    let message: &[u8] = b"Hello, world!";
    let digest = message.digest();

    let (_, sk) = keys().pop().unwrap();
    let mut service = SignatureService::new(sk, ss.secret.into_inner());
    let sig_share_0 = service.request_tss_signature(digest.clone()).await.unwrap();

    let (_, sk1) = keys().pop().unwrap();
    let mut service1 = SignatureService::new(sk1, sk_set.secret_key_share(1));
    let sig_share_1 = service1
        .request_tss_signature(digest.clone())
        .await
        .unwrap();

    assert!(pk_set
        .public_key_share(0)
        .verify(&sig_share_0, digest.clone()));
    assert!(pk_set.public_key_share(1).verify(&sig_share_1, digest));
}

#[tokio::test]
async fn threshold_signature_test() {
    let sk_set = SecretKeySet::random(3, &mut rand::thread_rng());
    let sk_shares: Vec<_> = (0..6).map(|i| sk_set.secret_key_share(i)).collect();
    let pk_set = sk_set.public_keys();
    let msg = "Happy birthday! If this is signed, at least four people remembered!";

    // Create four signature shares for the message with format: (i, ith share).
    let sig_shares: BTreeMap<_, _> = (0..5).map(|i| (i, sk_shares[i].sign(msg))).collect();

    // Validate the signature shares.
    for (i, sig_share) in &sig_shares {
        assert!(pk_set.public_key_share(*i).verify(sig_share, msg));
    }

    // Combine them to produce the main signature.
    let sig = pk_set
        .combine_signatures(&sig_shares)
        .expect("not enough shares");

    // Validate the main signature. If the shares were valid, this can't fail.
    assert!(pk_set.public_key().verify(&sig, msg));
}
