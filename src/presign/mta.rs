use core::convert::Infallible;

use generic_ec::{Curve, Scalar};

pub trait MultiplicationToAddition<E: Curve> {
    type Error;

    fn multiply_to_additive_share(
        &mut self,
        lhs: Scalar<E>,
        rhs: Scalar<E>,
    ) -> Result<Scalar<E>, Self::Error>;
}

#[derive(Debug, Default)]
pub struct DirectMta;

impl<E: Curve> MultiplicationToAddition<E> for DirectMta {
    type Error = Infallible;

    fn multiply_to_additive_share(
        &mut self,
        lhs: Scalar<E>,
        rhs: Scalar<E>,
    ) -> Result<Scalar<E>, Self::Error> {
        Ok(lhs * rhs)
    }
}