use ark_ff::FftField as Field;

pub struct FirstMsg<F: Field> {
    pub beta: F,
    pub gamma: F,
}

pub struct SecondMsg<F: Field> {
    pub alpha: F,
}
