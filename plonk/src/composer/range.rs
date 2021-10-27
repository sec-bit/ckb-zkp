use crate::composer::{Composer, Field, Variable};
use ark_ff::{PrimeField, BigInteger};

//标识要约束到哪种范围
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum RangeType {
    U8,
    U16,
    U32,
    U64,
}

impl<F: PrimeField + Field> Composer<F> {
    //接口。（约束一个数需要多个具体小门
    pub fn create_range_gate(
        &mut self,
        var: Variable, //需要被约束范围的var（的id）
        range_type: RangeType,
    ){
        //var里的值。转为 大端u8数组（32个）
        let value:&F = self.assignment.get(&var).unwrap();
        let value_bigint = value.into_repr();
        let value_u8bytes_be = value_bigint.to_bytes_be();
        // for i in &value_u8bytes_be {
        //     println!("{}", i);
        // }

        let range_bytes = match range_type {
            RangeType::U8 => {1usize}
            RangeType::U16 => {2usize}
            RangeType::U32 => {4usize}
            RangeType::U64 => {8usize}
        };
        //验证确实在范围内（前面的byte=0）
        for i in 0..(32-range_bytes) {
            assert_eq!(0u8, *value_u8bytes_be.get(i).unwrap());
        }
        //acc要能装下最大的u64 todo
        let mut acc: Vec<u128> = vec![0; 4 * range_bytes + 1];
        acc[0] = 0;
        for i in 0..range_bytes {
            let u8tmp = *value_u8bytes_be.get(32-range_bytes + i).unwrap();
            //println!("{}", u8tmp);
            //todo 加括号！移位运算符 优先级很低
            acc[4*i + 1] = (acc[4*i] << 2) + (u8tmp >> 6) as u128;
            acc[4*i + 2] = (acc[4*i + 1] << 2) + (u8tmp << 2 >> 6) as u128;
            acc[4*i + 3] = (acc[4*i + 2] << 2) + (u8tmp << 4 >> 6) as u128;
            acc[4*i + 4] = (acc[4*i + 3] << 2) + (u8tmp << 6 >> 6) as u128;
        }
        println!("{}", acc[4*range_bytes]);

        let acc1 = self.alloc_and_assign(F::from(acc[1]));
        let acc2 = self.alloc_and_assign(F::from(acc[2]));
        let acc3 = self.alloc_and_assign(F::from(acc[3]));
        let aux = self.alloc_and_assign(F::from(acc[0]));
        //生成小门
        self.create_range_gate_component(
            (acc1, F::zero()),
            (acc2, F::zero()),
            (acc3, F::zero()),
            Option::from((aux, F::one())),
            F::zero(),
            F::zero(),
            F::zero(),
            F::one(),
            F::one(),
        );
        for i in 1..range_bytes {
            let acc1 = self.alloc_and_assign(F::from(acc[4*i +1]));
            let acc2 = self.alloc_and_assign(F::from(acc[4*i +2]));
            let acc3 = self.alloc_and_assign(F::from(acc[4*i +3]));
            let aux = self.alloc_and_assign(F::from(acc[4*i]));
            self.create_range_gate_component(
                (acc1, F::zero()),
                (acc2, F::zero()),
                (acc3, F::zero()),
                Option::from((aux, F::zero())),
                F::zero(),
                F::zero(),
                F::zero(),
                F::zero(),
                F::one(),
            )
        }
            //todo 不需要！画蛇添足
            // 此操作的index必须与紧接着创建的小门一致
            // let index = self.n;
            // self.permutation.add_range_constraint(var, Wire::W0(index));
            let varzero1 = self.alloc_and_assign(F::zero());
            let varzero2 = self.alloc_and_assign(F::zero());
            let varzero3 = self.alloc_and_assign(F::zero());
            self.create_range_gate_component(
                (varzero1, F::zero()),
                (varzero2, F::zero()),
                (varzero3, F::zero()),
                Option::from((var, F::zero())),
                F::zero(),
                F::zero(),
                F::zero(),
                F::zero(),
                F::zero(),
            );

    }

    //range gate 的具体的小门
    fn create_range_gate_component(
        &mut self,
        l: (Variable, F), // w_l, q_l
        r: (Variable, F), // w_r, q_r
        o: (Variable, F), // w_o, q_o
        aux: Option<(Variable, F)>, //w0
        q_m: F,
        q_c: F,
        pi: F,
        q_arith: F,
        q_range: F,
    ) {
        let aux = match aux {
            Some(aux) => aux,
            None => (self.null_var, F::zero()),
        };

        let index = self.n;
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
        self.q_arith.push(q_arith);
        self.q_range.push(q_range);
        self.q_mimc.push(F::zero());
        //self.q_mimc_c.push(F::zero());

        self.n += 1;
    }
}