//! Helpers for testing circuit implementations.
use math::PrimeField;
use math::ToBytes;
use scheme::r1cs::{ConstraintSystem, Index, LinearCombination, SynthesisError, Variable};

use blake2s_simd::{Params as Blake2sParams, State as Blake2sState};
use byteorder::{BigEndian, ByteOrder};
use core::cmp::Ordering;

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write; // TODO no-std

#[derive(Debug)]
enum NamedObject {
    Constraint(usize),
    Var(Variable),
    Namespace,
}

/// Constraint system for testing purposes.
pub struct TestConstraintSystem<F: PrimeField> {
    named_objects: HashMap<String, NamedObject>,
    current_namespace: Vec<String>,
    constraints: Vec<(
        LinearCombination<F>,
        LinearCombination<F>,
        LinearCombination<F>,
        String,
    )>,
    inputs: Vec<(F, String)>,
    aux: Vec<(F, String)>,
}

#[derive(Clone, Copy)]
struct OrderedVariable(Variable);

impl Eq for OrderedVariable {}
impl PartialEq for OrderedVariable {
    fn eq(&self, other: &OrderedVariable) -> bool {
        match (self.0.get_unchecked(), other.0.get_unchecked()) {
            (Index::Input(ref a), Index::Input(ref b)) => a == b,
            (Index::Aux(ref a), Index::Aux(ref b)) => a == b,
            _ => false,
        }
    }
}
impl PartialOrd for OrderedVariable {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for OrderedVariable {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.0.get_unchecked(), other.0.get_unchecked()) {
            (Index::Input(ref a), Index::Input(ref b)) => a.cmp(b),
            (Index::Aux(ref a), Index::Aux(ref b)) => a.cmp(b),
            (Index::Input(_), Index::Aux(_)) => Ordering::Less,
            (Index::Aux(_), Index::Input(_)) => Ordering::Greater,
        }
    }
}

#[allow(dead_code)]
fn proc_lc<F: PrimeField>(terms: &[(Variable, F)]) -> BTreeMap<OrderedVariable, F> {
    let mut map = BTreeMap::new();
    for &(var, coeff) in terms {
        map.entry(OrderedVariable(var))
            .or_insert_with(F::zero)
            .add_assign(&coeff);
    }

    // Remove terms that have a zero coefficient to normalize
    let mut to_remove = vec![];
    for (var, coeff) in map.iter() {
        if coeff.is_zero() {
            to_remove.push(var.clone())
        }
    }

    for var in to_remove {
        map.remove(&var);
    }

    map
}

#[allow(dead_code)]
fn hash_lc<F: PrimeField>(terms: &[(Variable, F)], h: &mut Blake2sState) {
    let map = proc_lc::<F>(terms);

    let mut buf = [0u8; 9 + 32];
    BigEndian::write_u64(&mut buf[0..8], map.len() as u64);
    h.update(&buf[0..8]);

    for (var, coeff) in map {
        match var.0.get_unchecked() {
            Index::Input(i) => {
                buf[0] = b'I';
                BigEndian::write_u64(&mut buf[1..9], i as u64);
            }
            Index::Aux(i) => {
                buf[0] = b'A';
                BigEndian::write_u64(&mut buf[1..9], i as u64);
            }
        }

        coeff.into_repr().write(&mut buf[9..]).unwrap();

        h.update(&buf);
    }
}

#[allow(dead_code)]
fn eval_lc<F: PrimeField>(
    terms: &[(Variable, F)],
    inputs: &[(F, String)],
    aux: &[(F, String)],
) -> F {
    let mut acc = F::zero();

    for &(var, ref coeff) in terms {
        let mut tmp = match var.get_unchecked() {
            Index::Input(index) => inputs[index].0,
            Index::Aux(index) => aux[index].0,
        };

        tmp.mul_assign(coeff);
        acc.add_assign(&tmp);
    }

    acc
}

#[allow(dead_code)]
impl<F: PrimeField> TestConstraintSystem<F> {
    pub fn new() -> TestConstraintSystem<F> {
        let mut map = HashMap::new();
        map.insert(
            "ONE".into(),
            NamedObject::Var(TestConstraintSystem::<F>::one()),
        );

        TestConstraintSystem {
            named_objects: map,
            current_namespace: vec![],
            constraints: vec![],
            inputs: vec![(F::one(), "ONE".into())],
            aux: vec![],
        }
    }

    pub fn pretty_print(&self) -> String {
        let mut s = String::new();

        let negone = -F::one();

        let powers_of_two = (0..F::size_in_bits())
            .map(|i| F::from(2u32).pow(&[i as u64]))
            .collect::<Vec<_>>();

        let pp = |s: &mut String, lc: &LinearCombination<F>| {
            write!(s, "(").unwrap();
            let mut is_first = true;
            for (var, coeff) in proc_lc::<F>(lc.as_ref()) {
                if coeff == negone {
                    write!(s, " - ").unwrap();
                } else if !is_first {
                    write!(s, " + ").unwrap();
                }
                is_first = false;

                if coeff != F::one() && coeff != negone {
                    for (i, x) in powers_of_two.iter().enumerate() {
                        if x == &coeff {
                            write!(s, "2^{} . ", i).unwrap();
                            break;
                        }
                    }

                    write!(s, "{} . ", coeff).unwrap();
                }

                match var.0.get_unchecked() {
                    Index::Input(i) => {
                        write!(s, "`{}`", &self.inputs[i].1).unwrap();
                    }
                    Index::Aux(i) => {
                        write!(s, "`{}`", &self.aux[i].1).unwrap();
                    }
                }
            }
            if is_first {
                // Nothing was visited, print 0.
                write!(s, "0").unwrap();
            }
            write!(s, ")").unwrap();
        };

        for &(ref a, ref b, ref c, ref name) in &self.constraints {
            write!(&mut s, "\n").unwrap();

            write!(&mut s, "{}: ", name).unwrap();
            pp(&mut s, a);
            write!(&mut s, " * ").unwrap();
            pp(&mut s, b);
            write!(&mut s, " = ").unwrap();
            pp(&mut s, c);
        }

        write!(&mut s, "\n").unwrap();

        s
    }

    pub fn hash(&self) -> String {
        let mut h = Blake2sParams::new().hash_length(32).to_state();
        {
            let mut buf = [0u8; 24];

            BigEndian::write_u64(&mut buf[0..8], self.inputs.len() as u64);
            BigEndian::write_u64(&mut buf[8..16], self.aux.len() as u64);
            BigEndian::write_u64(&mut buf[16..24], self.constraints.len() as u64);
            h.update(&buf);
        }

        for constraint in &self.constraints {
            hash_lc::<F>(constraint.0.as_ref(), &mut h);
            hash_lc::<F>(constraint.1.as_ref(), &mut h);
            hash_lc::<F>(constraint.2.as_ref(), &mut h);
        }

        let mut s = String::new();
        for b in h.finalize().as_ref() {
            s += &format!("{:02x}", b);
        }

        s
    }

    pub fn which_is_unsatisfied(&self) -> Option<&str> {
        for &(ref a, ref b, ref c, ref path) in &self.constraints {
            let mut a = eval_lc::<F>(a.as_ref(), &self.inputs, &self.aux);
            let b = eval_lc::<F>(b.as_ref(), &self.inputs, &self.aux);
            let c = eval_lc::<F>(c.as_ref(), &self.inputs, &self.aux);

            a.mul_assign(&b);

            if a != c {
                return Some(&*path);
            }
        }

        None
    }

    pub fn is_satisfied(&self) -> bool {
        self.which_is_unsatisfied().is_none()
    }

    pub fn num_constraints(&self) -> usize {
        self.constraints.len()
    }

    pub fn set(&mut self, path: &str, to: F) {
        match self.named_objects.get(path) {
            Some(&NamedObject::Var(ref v)) => match v.get_unchecked() {
                Index::Input(index) => self.inputs[index].0 = to,
                Index::Aux(index) => self.aux[index].0 = to,
            },
            Some(e) => panic!(
                "tried to set path `{}` to value, but `{:?}` already exists there.",
                path, e
            ),
            _ => panic!("no variable exists at path: {}", path),
        }
    }

    pub fn verify(&self, expected: &[F]) -> bool {
        assert_eq!(expected.len() + 1, self.inputs.len());

        for (a, b) in self.inputs.iter().skip(1).zip(expected.iter()) {
            if &a.0 != b {
                return false;
            }
        }

        true
    }

    pub fn num_inputs(&self) -> usize {
        self.inputs.len()
    }

    pub fn get_input(&mut self, index: usize, path: &str) -> F {
        let (assignment, name) = self.inputs[index].clone();

        assert_eq!(path, name);

        assignment
    }

    pub fn get(&mut self, path: &str) -> F {
        match self.named_objects.get(path) {
            Some(&NamedObject::Var(ref v)) => match v.get_unchecked() {
                Index::Input(index) => self.inputs[index].0,
                Index::Aux(index) => self.aux[index].0,
            },
            Some(e) => panic!(
                "tried to get value of path `{}`, but `{:?}` exists there (not a variable)",
                path, e
            ),
            _ => panic!("no variable exists at path: {}", path),
        }
    }

    fn set_named_obj(&mut self, path: String, to: NamedObject) {
        if self.named_objects.contains_key(&path) {
            panic!("tried to create object at existing path: {}", path);
        }

        self.named_objects.insert(path, to);
    }
}

fn compute_path(ns: &[String], this: String) -> String {
    if this.chars().any(|a| a == '/') {
        panic!("'/' is not allowed in names");
    }

    let mut name = String::new();

    let mut needs_separation = false;
    for ns in ns.iter().chain(Some(&this).into_iter()) {
        if needs_separation {
            name += "/";
        }

        name += ns;
        needs_separation = true;
    }

    name
}

impl<F: PrimeField> ConstraintSystem<F> for TestConstraintSystem<F> {
    type Root = Self;

    fn alloc<T, A, AR>(&mut self, annotation: A, f: T) -> Result<Variable, SynthesisError>
    where
        T: FnOnce() -> Result<F, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let index = self.aux.len();
        let path = compute_path(&self.current_namespace, annotation().into());
        self.aux.push((f()?, path.clone()));
        let var = Variable::new_unchecked(Index::Aux(index));
        self.set_named_obj(path, NamedObject::Var(var));

        Ok(var)
    }

    fn alloc_input<T, A, AR>(&mut self, annotation: A, f: T) -> Result<Variable, SynthesisError>
    where
        T: FnOnce() -> Result<F, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let index = self.inputs.len();
        let path = compute_path(&self.current_namespace, annotation().into());
        self.inputs.push((f()?, path.clone()));
        let var = Variable::new_unchecked(Index::Input(index));
        self.set_named_obj(path, NamedObject::Var(var));

        Ok(var)
    }

    fn enforce<A, AR, LA, LB, LC>(&mut self, annotation: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
        LB: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
        LC: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
    {
        let path = compute_path(&self.current_namespace, annotation().into());
        let index = self.constraints.len();
        self.set_named_obj(path.clone(), NamedObject::Constraint(index));

        let a = a(LinearCombination::zero());
        let b = b(LinearCombination::zero());
        let c = c(LinearCombination::zero());

        self.constraints.push((a, b, c, path));
    }

    fn push_namespace<NR, N>(&mut self, name_fn: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        let name = name_fn().into();
        let path = compute_path(&self.current_namespace, name.clone());
        self.set_named_obj(path.clone(), NamedObject::Namespace);
        self.current_namespace.push(name);
    }

    fn pop_namespace(&mut self) {
        assert!(self.current_namespace.pop().is_some());
    }

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }

    /// Output the number of constraints in the system.
    fn num_constraints(&self) -> usize {
        todo!();
    }
}

#[test]
fn test_cs() {
    use curve::bn_256::Fr;
    use num_traits::One;

    let mut cs = TestConstraintSystem::<Fr>::new();
    assert!(cs.is_satisfied());
    assert_eq!(cs.num_constraints(), 0);
    let a = cs
        .ns(|| "a")
        .alloc(|| "var", || Ok(Fr::from(10u32)))
        .unwrap();
    let b = cs
        .ns(|| "b")
        .alloc(|| "var", || Ok(Fr::from(4u32)))
        .unwrap();
    let c = cs.alloc(|| "product", || Ok(Fr::from(40u32))).unwrap();

    cs.enforce(|| "mult", |lc| lc + a, |lc| lc + b, |lc| lc + c);
    assert!(cs.is_satisfied());
    assert_eq!(cs.num_constraints(), 1);

    cs.set("a/var", Fr::from(4u32));

    let one = TestConstraintSystem::<Fr>::one();
    cs.enforce(|| "eq", |lc| lc + a, |lc| lc + one, |lc| lc + b);

    assert!(!cs.is_satisfied());
    assert!(cs.which_is_unsatisfied() == Some("mult"));

    assert!(cs.get("product") == Fr::from(40u32));

    cs.set("product", Fr::from(16u32));
    assert!(cs.is_satisfied());

    {
        let mut cs = cs.ns(|| "test1");
        let mut cs = cs.ns(|| "test2");
        cs.alloc(|| "hehe", || Ok(Fr::one())).unwrap();
    }

    assert!(cs.get("test1/test2/hehe") == Fr::one());
}
