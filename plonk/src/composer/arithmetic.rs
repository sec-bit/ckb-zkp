use crate::composer::{Composer, Field, Variable};

impl<F: Field> Composer<F> {
    /// q_m * l * r + q_l * l + q_r * r + q_o * o (+ q_aux * aux) + q_c + pi == 0
    #[allow(clippy::too_many_arguments)]
    fn create_poly_gate(
        &mut self,
        l: (Variable, F), // w_l, q_l
        r: (Variable, F), // w_r, q_r
        o: (Variable, F), // w_o, q_o
        aux: Option<(Variable, F)>,
        q_m: F,
        q_c: F,
        pi: F,
    ) {
        let index = self.n;

        let aux = match aux {
            Some(aux) => aux,
            None => (self.null_var, F::zero()),
        };

        self.permutation.insert_gate(aux.0, l.0, r.0, o.0, index);

        self.w_0.push(aux.0);
        self.w_1.push(l.0);
        self.w_2.push(r.0);
        self.w_3.push(o.0);
        self.pi.push(pi);

        self.q_0.push(aux.1);
        self.q_1.push(l.1);
        self.q_2.push(r.1);
        self.q_3.push(o.1);
        self.q_m.push(q_m);
        self.q_c.push(q_c);
        self.q_arith.push(F::one());

        self.n += 1;
    }

    /// var == q_c + pi
    pub fn constrain_to_constant(&mut self, var: Variable, value: F, pi: F) {
        self.create_poly_gate(
            (var, F::one()),
            (var, F::zero()),
            (var, F::zero()),
            None,
            F::zero(),
            -value,
            -pi,
        );
    }

    /// l == r
    pub fn assert_equal(&mut self, l: Variable, r: Variable) {
        self.create_poly_gate(
            (l, F::one()),
            (r, -F::one()),
            (self.null_var, F::zero()),
            None,
            F::zero(),
            F::zero(),
            F::zero(),
        )
    }

    /// q_l * l + q_r * r - o (+ q_aux * aux) + q_c + pi == 0
    pub fn create_add_gate(
        &mut self,
        l: (Variable, F),
        r: (Variable, F),
        o: Variable,
        aux: Option<(Variable, F)>,
        q_c: F,
        pi: F,
    ) {
        self.create_poly_gate(l, r, (o, -F::one()), aux, F::zero(), q_c, pi)
    }

    /// q_m * l * r - o (+ q_aux * aux) + q_c + pi == 0
    #[allow(clippy::too_many_arguments)]
    pub fn create_mul_gate(
        &mut self,
        l: Variable,
        r: Variable,
        o: Variable,
        aux: Option<(Variable, F)>,
        q_m: F,
        q_c: F,
        pi: F,
    ) {
        self.create_poly_gate(
            (l, F::zero()),
            (r, F::zero()),
            (o, -F::one()),
            aux,
            q_m,
            q_c,
            pi,
        )
    }
}
