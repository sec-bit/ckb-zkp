use crate::composer::{Composer, Field, Variable};

impl<F: Field> Composer<F> {
    pub fn boolean_gate(&mut self, a: Variable, pi: F) {
        self.permutation.insert_gate(a, a, a, Variable(0), self.n);

        self.w_0.push(a);
        self.w_1.push(a);
        self.w_2.push(a);
        self.w_3.push(Variable(0));
        self.pi.push(pi);

        self.q_0.push(F::zero());
        self.q_1.push(F::zero());
        self.q_2.push(-F::one());
        self.q_3.push(F::zero());
        self.q_m.push(F::one());
        self.q_c.push(F::zero());
        self.q_arith.push(F::one());

        self.n += 1;
    }
}
