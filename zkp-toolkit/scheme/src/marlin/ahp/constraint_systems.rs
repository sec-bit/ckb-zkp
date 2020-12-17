use math::Field;

use crate::r1cs::{
    ConstraintSystem, Index as VariableIndex, LinearCombination, SynthesisError, Variable,
};
use crate::{String, Vec};

use crate::marlin::ahp::arithmetic::{matrix_density, sort_matrix_columns, Matrix};

fn make_constraint_matrices_square<F: Field, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    num_formatted_variables: usize,
) {
    let num_constraints = cs.num_constraints();
    let num_paddings = ((num_formatted_variables as isize) - (num_constraints as isize)).abs();
    if num_formatted_variables < num_constraints {
        for i in 0..num_paddings {
            cs.alloc(|| format!("pad varible {}", i), || Ok(F::one()))
                .expect("alloc failed");
        }
    } else {
        for i in 0..num_paddings {
            use core::convert::identity;
            cs.enforce(
                || format!("pad constraint {}", i),
                identity,
                identity,
                identity,
            );
        }
    }
}

pub(crate) struct IndexerConstraintSystem<F: Field> {
    pub(crate) num_input_variables: usize,
    pub(crate) num_witness_variables: usize,
    pub(crate) num_constraints: usize,

    pub(crate) a: Vec<Vec<(F, VariableIndex)>>,
    pub(crate) b: Vec<Vec<(F, VariableIndex)>>,
    pub(crate) c: Vec<Vec<(F, VariableIndex)>>,

    pub(crate) a_matrix: Option<Matrix<F>>,
    pub(crate) b_matrix: Option<Matrix<F>>,
    pub(crate) c_matrix: Option<Matrix<F>>,
}

impl<F: Field> IndexerConstraintSystem<F> {
    pub(crate) fn new() -> Self {
        Self {
            num_input_variables: 1,
            num_witness_variables: 0,
            num_constraints: 0,
            a: Vec::new(),
            b: Vec::new(),
            c: Vec::new(),
            a_matrix: None,
            b_matrix: None,
            c_matrix: None,
        }
    }

    pub(crate) fn make_row(l: &LinearCombination<F>) -> Vec<(F, VariableIndex)> {
        l.as_ref()
            .iter()
            .map(|(var, coeff)| (*coeff, var.get_unchecked()))
            .collect()
    }

    pub(crate) fn make_matrices_square(&mut self) {
        let num_formatted_variables = self.num_input_variables + self.num_witness_variables;
        make_constraint_matrices_square(self, num_formatted_variables);
    }

    pub(crate) fn process_matrices(&mut self) {
        let mut a = Self::reindex(&self.a, self.num_input_variables);
        let mut b = Self::reindex(&self.b, self.num_input_variables);
        let mut c = Self::reindex(&self.c, self.num_input_variables);

        Self::balance_matrices(&mut a, &mut b);

        sort_matrix_columns(&mut a);
        sort_matrix_columns(&mut b);
        sort_matrix_columns(&mut c);

        self.a_matrix = Some(a);
        self.b_matrix = Some(b);
        self.c_matrix = Some(c);
    }

    pub(crate) fn num_non_zeros(&self) -> usize {
        let a_density = matrix_density(&self.a_matrix.as_ref().expect("a_matrix is not None"));
        let b_density = matrix_density(&self.b_matrix.as_ref().expect("b_matrix is not None"));
        let c_density = matrix_density(&self.c_matrix.as_ref().expect("c_matrix is not None"));
        *[a_density, b_density, c_density]
            .iter()
            .max()
            .expect("density iterator is not empty")
    }

    fn balance_matrices(a: &mut Matrix<F>, b: &mut Matrix<F>) {
        let mut a_density = matrix_density(a);
        let mut b_density = matrix_density(b);
        let mut a_is_denser = a_density > b_density;
        for (a_row, mut b_row) in a.0.iter_mut().zip(&mut b.0) {
            if a_is_denser {
                let a_row_size = a_row.len();
                let b_row_size = b_row.len();
                core::mem::swap(a_row, &mut b_row);
                a_density += b_row_size - a_row_size;
                b_density += a_row_size - b_row_size;
                a_is_denser = a_density > b_density;
            }
        }
    }

    fn reindex(matrix: &[Vec<(F, VariableIndex)>], num_input_variables: usize) -> Matrix<F> {
        let mut m = Vec::with_capacity(matrix.len());
        for row in matrix {
            let mut r = Vec::with_capacity(row.len());
            for (coeff, id) in row {
                let id = match id {
                    VariableIndex::Aux(i) => i + num_input_variables,
                    VariableIndex::Input(i) => *i,
                };
                r.push((*coeff, id));
            }
            m.push(r);
        }
        Matrix(m)
    }
}

impl<F: Field> ConstraintSystem<F> for IndexerConstraintSystem<F> {
    type Root = Self;

    fn alloc<FN, A, AR>(&mut self, _: A, _: FN) -> Result<Variable, SynthesisError>
    where
        FN: FnOnce() -> Result<F, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let index = self.num_witness_variables;
        self.num_witness_variables += 1;

        Ok(Variable::new_unchecked(VariableIndex::Aux(index)))
    }

    fn alloc_input<FN, A, AR>(&mut self, _: A, _: FN) -> Result<Variable, SynthesisError>
    where
        FN: FnOnce() -> Result<F, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let index = self.num_input_variables;
        self.num_input_variables += 1;

        Ok(Variable::new_unchecked(VariableIndex::Input(index)))
    }

    fn enforce<A, AR, LA, LB, LC>(&mut self, _: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
        LB: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
        LC: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
    {
        self.a.push(Self::make_row(&a(LinearCombination::zero())));
        self.b.push(Self::make_row(&b(LinearCombination::zero())));
        self.c.push(Self::make_row(&c(LinearCombination::zero())));

        self.num_constraints += 1;
    }

    fn push_namespace<NR, N>(&mut self, _: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn pop_namespace(&mut self) {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }

    fn num_constraints(&self) -> usize {
        self.num_constraints
    }
}

pub(crate) struct ProverConstraintSystem<F: Field> {
    pub(crate) num_input_variables: usize,
    pub(crate) num_witness_variables: usize,
    pub(crate) num_constraints: usize,
    pub(crate) formatted_input_assignment: Vec<F>,
    pub(crate) witness_assignment: Vec<F>,
}

impl<F: Field> ProverConstraintSystem<F> {
    pub(crate) fn new() -> Self {
        Self {
            num_input_variables: 1,
            num_witness_variables: 0,
            num_constraints: 0,
            formatted_input_assignment: vec![F::one()],
            witness_assignment: Vec::new(),
        }
    }

    pub(crate) fn make_matrices_square(&mut self) {
        let num_formatted_variables = self.num_input_variables + self.num_witness_variables;
        make_constraint_matrices_square(self, num_formatted_variables);
    }

    pub(crate) fn format_public_input(public_input: &[F]) -> Vec<F> {
        let mut input = vec![F::one()];
        input.extend_from_slice(public_input);
        input
    }
}

impl<F: Field> ConstraintSystem<F> for ProverConstraintSystem<F> {
    type Root = Self;

    fn alloc<FN, A, AR>(&mut self, _: A, f: FN) -> Result<Variable, SynthesisError>
    where
        FN: FnOnce() -> Result<F, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        self.witness_assignment.push(f()?);
        let index = self.num_witness_variables;
        self.num_witness_variables += 1;
        Ok(Variable::new_unchecked(VariableIndex::Aux(index)))
    }

    fn alloc_input<FN, A, AR>(&mut self, _: A, f: FN) -> Result<Variable, SynthesisError>
    where
        FN: FnOnce() -> Result<F, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        self.formatted_input_assignment.push(f()?);
        let index = self.num_input_variables;
        self.num_input_variables += 1;
        Ok(Variable::new_unchecked(VariableIndex::Input(index)))
    }

    fn enforce<A, AR, LA, LB, LC>(&mut self, _: A, _: LA, _: LB, _: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
        LB: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
        LC: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
    {
        self.num_constraints += 1;
    }

    fn push_namespace<NR, N>(&mut self, _: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn pop_namespace(&mut self) {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }

    fn num_constraints(&self) -> usize {
        self.num_constraints
    }
}
