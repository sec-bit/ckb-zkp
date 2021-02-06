use crate::composer::{Composer, Field, Variable};

impl<F: Field> Composer<F> {
    /// q_m * l * r + q_l * l + q_r * r + q_o * o (+ q_aux * aux) + q_c + pi == 0
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

        self.permutation.add_gate(aux.0, l.0, r.0, o.0, index);
        self.q_0.push(aux.1);
        self.q_1.push(l.1);
        self.q_2.push(r.1);
        self.q_3.push(o.1);
        self.q_m.push(q_m);
        self.q_c.push(q_c);
        self.pi.push(pi);

        self.q_arith.push(F::one());

        self.n += 1;
    }

    /// var == q_c
    pub fn constrain_to_constant(&mut self, var: Variable, value: F) {
        self.create_poly_gate(
            (var, F::one()),
            (var, F::zero()),
            (var, F::zero()),
            None,
            F::zero(),
            -value,
            F::zero(),
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
        self.create_poly_gate(
            l,
            r,
            (o, -F::one()),
            aux,
            F::zero(),
            q_c,
            pi,
        )
    }

    /// o = q_l * l + q_r * r (+ q_aux * aux) + q_c + pi
    pub fn add(
        &mut self,
        l: (Variable, F),
        r: (Variable, F),
        aux: Option<(Variable, F)>,
        q_c: F,
        pi: F,
    ) -> Variable {
        let (l, q_l) = l;
        let (r, q_r) = r;
        let (aux, q_aux) = match aux {
            Some((aux, q_aux)) => (aux, q_aux),
            None => (self.null_var, F::zero()),
        };

        let v_l = self.assignments[&l];
        let v_r = self.assignments[&r];
        let v_aux = self.assignments[&aux];
        let v_o = q_l * v_l + q_r * v_r + q_aux * v_aux + q_c + pi;

        let o = self.alloc_and_assign(v_o);
        self.create_add_gate(
            (l, q_l),
            (r, q_r),
            o,
            Some((aux, q_aux)),
            q_c,
            pi,
        );

        o
    }

    /// q_m * l * r - o (+ q_aux * aux) + q_c + pi == 0
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

    /// o = q_m * l * r (+ q_aux * aux) + q_c + pi
    pub fn mul(
        &mut self,
        l: Variable,
        r: Variable,
        aux: Option<(Variable, F)>,
        q_m: F,
        q_c: F,
        pi: F,
    ) -> Variable {
        let (aux, q_aux) = match aux {
            Some((aux, q_aux)) => (aux, q_aux),
            None => (self.null_var, F::zero()),
        };

        let v_l = self.assignments[&l];
        let v_r = self.assignments[&r];
        let v_aux = self.assignments[&aux];
        let v_o = q_m * v_l + v_r + q_aux * v_aux + q_c + pi;

        let o = self.alloc_and_assign(v_o);
        self.create_mul_gate(l, r, o, Some((aux, q_aux)), q_m, q_c, pi);

        o
    }
}
