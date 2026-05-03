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
pub struct MockMta;

impl<E: Curve> MultiplicationToAddition<E> for MockMta {
    type Error = Infallible;

    fn multiply_to_additive_share(
        &mut self,
        _lhs: Scalar<E>,
        _rhs: Scalar<E>,
    ) -> Result<Scalar<E>, Self::Error> {
        // Non-secure placeholder.
        // TODO(DKLs23): replace with OT / Vector-OLE based MtA.
        Ok(Scalar::<E>::zero())
    }
}