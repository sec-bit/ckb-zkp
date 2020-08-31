use math::fft::EvaluationDomain;
use math::PrimeField;

use crate::r1cs::{ConstraintSynthesizer, SynthesisError};

use crate::marlin::ahp::arithmetic::{compose_matrix_polynomials, Matrix, MatrixPolynomials};
use crate::marlin::ahp::constraint_systems::IndexerConstraintSystem;
use crate::marlin::ahp::{Error, AHP};
use crate::marlin::pc::LabeledPolynomial;

#[derive(Copy, Clone, Debug)]
pub struct IndexInfo {
    pub num_constraints: usize,
    pub num_variables: usize,
    pub num_non_zeros: usize,
}

impl math::ToBytes for IndexInfo {
    #[inline]
    fn write<W: math::io::Write>(&self, mut w: W) -> math::io::Result<()> {
        (self.num_variables as u64).write(&mut w)?;
        (self.num_constraints as u64).write(&mut w)?;
        (self.num_non_zeros as u64).write(&mut w)
    }
}

impl math::FromBytes for IndexInfo {
    #[inline]
    fn read<R: math::io::Read>(mut r: R) -> math::io::Result<Self> {
        let num_constraints = u64::read(&mut r)? as usize;
        let num_variables = u64::read(&mut r)? as usize;
        let num_non_zeros = u64::read(&mut r)? as usize;

        Ok(Self {
            num_constraints,
            num_variables,
            num_non_zeros,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Index<'a, F: PrimeField> {
    pub index_info: IndexInfo,

    pub a: Matrix<F>,
    pub b: Matrix<F>,
    pub c: Matrix<F>,

    pub a_star_polys: MatrixPolynomials<'a, F>,
    pub b_star_polys: MatrixPolynomials<'a, F>,
    pub c_star_polys: MatrixPolynomials<'a, F>,
}

impl<'a, F: PrimeField> math::ToBytes for Index<'a, F> {
    #[inline]
    fn write<W: math::io::Write>(&self, mut w: W) -> math::io::Result<()> {
        self.index_info.write(&mut w)?;
        self.a.write(&mut w)?;
        self.b.write(&mut w)?;
        self.c.write(&mut w)?;

        self.a_star_polys.write(&mut w)?;
        self.b_star_polys.write(&mut w)?;
        self.c_star_polys.write(&mut w)
    }
}

impl<'a, F: PrimeField> math::FromBytes for Index<'a, F> {
    #[inline]
    fn read<R: math::io::Read>(mut r: R) -> math::io::Result<Self> {
        let index_info = IndexInfo::read(&mut r)?;
        let a = Matrix::read(&mut r)?;
        let b = Matrix::read(&mut r)?;
        let c = Matrix::read(&mut r)?;

        let a_star_polys = MatrixPolynomials::read(&mut r)?;
        let b_star_polys = MatrixPolynomials::read(&mut r)?;
        let c_star_polys = MatrixPolynomials::read(&mut r)?;

        Ok(Self {
            index_info,
            a,
            b,
            c,
            a_star_polys,
            b_star_polys,
            c_star_polys,
        })
    }
}

impl<'a, F: PrimeField> Index<'a, F> {
    pub fn max_degree(&self) -> usize {
        AHP::<F>::max_degree(
            self.index_info.num_constraints,
            self.index_info.num_variables,
            self.index_info.num_non_zeros,
        )
        .unwrap()
    }

    pub fn iter(&self) -> impl Iterator<Item = &LabeledPolynomial<'a, F>> {
        vec![
            &self.a_star_polys.row,
            &self.a_star_polys.col,
            &self.a_star_polys.val,
            &self.a_star_polys.row_col,
            &self.b_star_polys.row,
            &self.b_star_polys.col,
            &self.b_star_polys.val,
            &self.b_star_polys.row_col,
            &self.c_star_polys.row,
            &self.c_star_polys.col,
            &self.c_star_polys.val,
            &self.c_star_polys.row_col,
        ]
        .into_iter()
    }
}

impl<F: PrimeField> AHP<F> {
    pub fn index<'a, C: ConstraintSynthesizer<F>>(c: C) -> Result<Index<'a, F>, Error> {
        let mut ics = IndexerConstraintSystem::new();
        c.generate_constraints(&mut ics)?;
        ics.make_matrices_square();
        ics.process_matrices();

        let num_inputs = ics.num_input_variables;
        let num_constraints = ics.num_constraints;
        let num_variables = ics.num_input_variables + ics.num_witness_variables;
        let num_non_zeros = ics.num_non_zeros();

        let domain_x =
            EvaluationDomain::new(num_inputs).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_h =
            EvaluationDomain::new(num_variables).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_k =
            EvaluationDomain::new(num_non_zeros).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_b = EvaluationDomain::new(3 * domain_k.size() - 3)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;

        let a = ics.a_matrix.expect("a should not be None");
        let b = ics.b_matrix.expect("b should not be None");
        let c = ics.c_matrix.expect("c should not be None");
        let a_star_polys =
            compose_matrix_polynomials("a", &a, domain_x, domain_h, domain_k, domain_b)?;
        let b_star_polys =
            compose_matrix_polynomials("b", &b, domain_x, domain_h, domain_k, domain_b)?;
        let c_star_polys =
            compose_matrix_polynomials("c", &c, domain_x, domain_h, domain_k, domain_b)?;

        let index_info = IndexInfo {
            num_constraints,
            num_variables,
            num_non_zeros,
        };

        Ok(Index {
            index_info,
            a,
            b,
            c,
            a_star_polys,
            b_star_polys,
            c_star_polys,
        })
    }
}
