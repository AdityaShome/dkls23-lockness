//! Signing helpers for the DKLs23 MVP.
//!
//! The threshold signing protocol is still pending the real MtA / OT path,
//! but the ECDSA math here is real and can be used to validate the current
//! presign output and future protocol wiring.

use core::fmt;

use generic_ec::{Curve, Point, Scalar};
use serde::{Deserialize, Serialize};

use crate::{presign::Presignature, Error, Result};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound = "")]
pub struct Signature<E: Curve> {
    pub r: Scalar<E>,
    pub s: Scalar<E>,
}

impl<E: Curve> Signature<E> {
    pub fn new(r: Scalar<E>, s: Scalar<E>) -> Self {
        Self { r, s }
    }
}

impl<E: Curve> fmt::Display for Signature<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature(r={:?}, s={:?})", self.r, self.s)
    }
}

fn message_scalar<E: Curve>(message_hash: &[u8; 32]) -> Scalar<E> {
    Scalar::<E>::from_be_bytes_mod_order(message_hash)
}

fn point_x_scalar<E: Curve>(point: &Point<E>) -> Result<Scalar<E>> {
    if point.is_zero() {
        return Err(Error::InvalidNoncePoint);
    }

    let encoded = point.to_bytes(false);
    let bytes = encoded.as_ref();
    let coordinate_len = (Point::<E>::serialized_len(false) - 1) / 2;
    if bytes.len() < 1 + coordinate_len {
        return Err(Error::InvalidNoncePoint);
    }

    Ok(Scalar::<E>::from_be_bytes_mod_order(&bytes[1..1 + coordinate_len]))
}

pub fn sign<E, S, N>(secret_key: S, nonce: N, message_hash: &[u8; 32]) -> Result<Signature<E>>
where
    E: Curve,
    S: AsRef<Scalar<E>>,
    N: AsRef<Scalar<E>>,
{
    let secret_key = secret_key.as_ref();
    let nonce = nonce.as_ref();

    if secret_key.is_zero() || nonce.is_zero() {
        return Err(Error::ZeroNonce);
    }

    let nonce_point = Point::<E>::generator() * nonce;
    if nonce_point.is_zero() {
        return Err(Error::ZeroNonce);
    }

    let r = point_x_scalar(&nonce_point)?;
    if r.is_zero() {
        return Err(Error::ZeroNonce);
    }

    let e = message_scalar::<E>(message_hash);
    let nonce_inv = nonce.invert().ok_or(Error::ZeroNonce)?;
    let s = nonce_inv * (e + (&r * secret_key));

    if s.is_zero() {
        return Err(Error::InvalidSignature);
    }

    Ok(Signature::new(r, s))
}

pub fn verify<E: Curve>(public_key: &Point<E>, message_hash: &[u8; 32], signature: &Signature<E>) -> Result<bool> {
    if signature.r.is_zero() || signature.s.is_zero() {
        return Ok(false);
    }

    let s_inv = signature.s.invert().ok_or(Error::InvalidSignature)?;
    let e = message_scalar::<E>(message_hash);
    let u1 = e * &s_inv;
    let u2 = &signature.r * &s_inv;

    let candidate = (&Point::<E>::generator() * &u1) + &(public_key * &u2);
    if candidate.is_zero() {
        return Ok(false);
    }

    let candidate_r = point_x_scalar(&candidate)?;
    Ok(candidate_r == signature.r)
}

pub fn sign_with_presignature<E, S>(
    secret_key: S,
    presignature: &Presignature<E>,
    message_hash: &[u8; 32],
) -> Result<Signature<E>>
where
    E: Curve,
    S: AsRef<Scalar<E>>,
{
    let expected_nonce_point = Point::<E>::generator() * &presignature.aggregate_nonce;
    if expected_nonce_point != presignature.nonce_point {
        return Err(Error::InvalidNoncePoint);
    }

    sign(secret_key, &presignature.aggregate_nonce, message_hash)
}
