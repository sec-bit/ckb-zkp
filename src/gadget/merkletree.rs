use math::PrimeField;
use scheme::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, SynthesisError, Variable,
};
use super::boolean::Boolean;

use super::test_constraint_system::TestConstraintSystem;

struct MerkletreeDemo<E: PrimeField> {
    // 树的深度，为树高的索引值
    tree_depth: u64,
    digest_size: u64,
    address_bits: Vec<Option<E>>,
    leaf_digest: Vec<Option<E>>,
    root_digest: Vec<Option<E>>,
    path: Vec<Vec<Option<E>>>,
}

impl<E: PrimeField> ConstraintSynthesizer<E> for MerkletreeDemo<E> {
    fn generate_constraints<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let mut left_digests: Vec<Vec<Option<E>>> = vec![vec![Some(E::from(0u32)); self.digest_size as usize]; self.tree_depth as usize];
        let mut right_digests: Vec<Vec<Option<E>>> = vec![vec![Some(E::from(0u32)); self.digest_size as usize]; self.tree_depth as usize];
        println!("tree_depth: {}", self.tree_depth);
        println!("digest_size: {}", self.digest_size);
        assert!(self.tree_depth > 0);
        assert!(self.tree_depth == self.address_bits.len() as u64);
        assert!(self.tree_depth == left_digests.len() as u64);
        assert!(self.tree_depth == right_digests.len() as u64);
        assert!(self.tree_depth == self.path.len() as u64);
        assert!(self.digest_size == self.leaf_digest.len() as u64);
        assert!(self.digest_size == self.root_digest.len() as u64);
        assert!(self.digest_size == self.path[0].len() as u64);

        // variable init
        let mut left_digests_var: Vec<Vec<Variable>> = vec![vec![]; self.tree_depth as usize];
        let mut right_digests_var: Vec<Vec<Variable>> = vec![vec![]; self.tree_depth as usize];
        let mut address_bits_var: Vec<Variable> = Vec::new();
        let mut leaf_digest_var: Vec<Variable> = Vec::new();


        // merkle_authentication_path_variable_withness
        for i in 0..self.tree_depth as usize {
            // address_bits一定为0或者为1，这里不需要添加约束
            if Some(E::one()) == self.address_bits[self.tree_depth as usize -1-i] {
                for j in 0..self.digest_size as usize {
                    left_digests[i][j] = self.path[i][j];
                }
            }else {
                for j in 0..self.digest_size as usize {
                    right_digests[i][j] = self.path[i][j];
                }
            }
        }

        // merkle_tree_check_read_gadget_withness
        let mut internal_output: Vec<Vec<Option<E>>> = vec![vec![Some(E::zero()); self.digest_size as usize]; self.tree_depth as usize - 1];
        let mut internal_output_var: Vec<Vec<Variable>> = vec![vec![]; self.tree_depth as usize];
        // let mut pre_hash: Vec<Option<E>> = Vec::with_capacity(256);
        let mut computed_root: Vec<Option<E>> = vec![Some(E::zero()); self.digest_size as usize];
        let mut root_digest_var: Vec<Variable> = Vec::new();
        let mut computed_root_var: Vec<Variable> = Vec::new();

        for i in (0..self.tree_depth as usize).rev() {
            // hash contraint TODO
            if i == self.tree_depth as usize -1 {
                if self.address_bits[self.tree_depth as usize-1-i] == Some(E::one()) {
                    for j in 0..self.digest_size as usize {
                        right_digests[i][j] = self.leaf_digest[j];
                    }
                }else {
                    for j in 0..self.digest_size as usize {
                        left_digests[i][j] = self.leaf_digest[j];
                    }
                }

                // // digest_selector_gadget constraint
                // for j in 0..digest_size as usize {
                //     cs.enforce(
                //         || format!("digest_selector_gadget[{}][{}]", i, j),
                //         |lc| lc + address_bits_var[tree_depth as usize-1-i],
                //         |lc| lc + right_digests_var[i][j] - left_digests_var[i][j],
                //         |lc| lc + leaf_digest_var[j] - left_digests_var[i][j],
                //     );
                // }

            } else {
                if self.address_bits[self.tree_depth as usize-1-i] == Some(E::one()) {
                    for j in 0..self.digest_size as usize {
                        right_digests[i][j] = internal_output[i][j];
                    }
                }else {
                    for j in 0..self.digest_size as usize {
                        left_digests[i][j] = internal_output[i][j];
                    }
                }

                // // constraint
                // let mut pre_hash_var:Vec<Variable> = Vec::new();
                // for j in 0..digest_size as usize {
                //     let mut tmp = cs.alloc(
                //         || format!("pre_hash_var[{}][{}]", i, j),
                //         || internal_output[i][j].ok_or(SynthesisError::AssignmentMissing),
                //     );
                // }

                // for j in 0..digest_size as usize {
                //     cs.enforce(
                //         || format!("digest_selector_gadget[{}][{}]", i, j),
                //         |lc| lc + address_bits_var[tree_depth as usize-1-i],
                //         |lc| lc + right_digests_var[i][j] - left_digests_var[i][j],
                //         |lc| lc + pre_hash_var[j] - left_digests_var[i][j],
                //     );
                // }
            }

            let mut tmp_left = left_digests[i].clone();
            let mut tmp_right = right_digests[i].clone();
            if i == 0 {
                // sha256Hash(left_digests[i], right_digests[i], computed_root);
                let mut content: Vec<Option<E>> = Vec::new();
                content.append(&mut tmp_left);
                content.append(&mut tmp_right);
                assert!(512 == content.len());
                let mut input_bits: Vec<_> = (0..512).map(|_| Boolean::Constant(false)).collect();
                for (i, x) in content.iter().enumerate() {
                    if Some(E::one()) == *x {
                        input_bits[i] = Boolean::Constant(true);
                    }
                }

                // sha256的接口cs的接口不是一个引用类型，如果直接传入cs，会造成cs的所有权转移。
                let mut cs1 = TestConstraintSystem::<E>::new();
                let mut r = sha256(cs1, &input_bits)?;
                assert!(r.len() == 256);

                for (j, x) in r.iter().enumerate() {
                    if Some(false) == x.get_value() {
                        computed_root[j] = Some(E::zero());
                    }else {
                        computed_root[j] = Some(E::one());
                    }
                }

                // 将sha256的计算结果输出线路接到computed_root之上
                for (j, x) in r.iter().enumerate() {
                    if Some(false) == x.get_value() {
                        computed_root_var.push(match x {
                            Boolean::Constant(c) => CS::one(),
                            Boolean::Is(ref v) => v.get_variable(),
                            Boolean::Not(ref v) => v.get_variable(),
                        });
                    }else {
                        computed_root_var.push(match x {
                            Boolean::Constant(c) => CS::one(),
                            Boolean::Is(ref v) => v.get_variable(),
                            Boolean::Not(ref v) => v.get_variable(),
                        });
                    }
                }

                assert!(256 == computed_root.len());
            }else {
                // sha256Hash(left_digests[i], right_digests[i], internal_output[i]);
                let mut content: Vec<Option<E>> = Vec::new();
                content.append(&mut tmp_left);
                content.append(&mut tmp_right);
                assert!(512 == content.len());
                let mut input_bits: Vec<_> = (0..512).map(|_| Boolean::Constant(false)).collect();
                for (i, x) in content.iter().enumerate() {
                    if Some(E::one()) == *x {
                        input_bits[i] = Boolean::Constant(true);
                    }
                }
                let mut cs1 = TestConstraintSystem::<E>::new();
                let mut r = sha256(cs1, &input_bits)?;
                assert!(r.len() == 256);

                for (j, x) in r.iter().enumerate() {
                    if Some(false) == x.get_value() {
                        internal_output[i-1][j] = Some(E::zero());
                    }else {
                        internal_output[i-1][j] = Some(E::one());
                    }
                }

                // 将sha256的计算结果输出线路接到internal_output_var之上
                for (j, x) in r.iter().enumerate() {
                    if Some(false) == x.get_value() {
                        internal_output_var[i-1].push(match x {
                            Boolean::Constant(c) => CS::one(),
                            Boolean::Is(ref v) => v.get_variable(),
                            Boolean::Not(ref v) => v.get_variable(),
                        });
                    }else {
                        internal_output_var[i-1].push(match x {
                            Boolean::Constant(c) =>  CS::one(),
                            Boolean::Is(ref v) => v.get_variable(),
                            Boolean::Not(ref v) => v.get_variable(), 
                        });
                    }
                }

                assert!(256 == internal_output[i-1].len());
            }
        }

        // merkle_authentication_path_variable_constraint
        // 上述变量E值在CS上分配Variable，便于后续在CS上通过Variable添加约束
        for i in 0..self.tree_depth as usize {
            let mut tmp = cs.alloc(
                || format!("address_bits[{}]", i),
                || self.address_bits[i].ok_or(SynthesisError::AssignmentMissing),
            );
            address_bits_var.push(tmp.unwrap());

            for j in 0..self.digest_size as usize {
                let mut tmp = cs.alloc(
                    || format!("left_digests[{}][{}]", i, j),
                    || left_digests[i][j].ok_or(SynthesisError::AssignmentMissing),
                );
                left_digests_var[i].push(tmp.unwrap());

                let mut tmp = cs.alloc(
                    || format!("right_digests[{}][{}]", i, j),
                    || right_digests[i][j].ok_or(SynthesisError::AssignmentMissing),
                );
                right_digests_var[i].push(tmp.unwrap());

                // internal_output 0..tree_depth-1
                // if i < self.tree_depth as usize - 1 {
                //     let mut tmp = cs.alloc(
                //         || format!("internal_output[{}][{}]", i, j),
                //         || internal_output[i][j].ok_or(SynthesisError::AssignmentMissing),
                //     );

                //     internal_output_var[i].push(tmp.unwrap());
                // }
            }
        }

        for i in 0..self.digest_size as usize {
            let mut tmp = cs.alloc(
                || format!("leaf_digest[{}]", i),
                || self.leaf_digest[i].ok_or(SynthesisError::AssignmentMissing),
            );
            leaf_digest_var.push(tmp.unwrap());

            let mut tmp = cs.alloc(
                || format!("root_digest[{}]", i),
                || self.root_digest[i].ok_or(SynthesisError::AssignmentMissing),
            );
            root_digest_var.push(tmp.unwrap());

            // let mut tmp = cs.alloc(
            //     || format!("computed_root[{}]", i),
            //     || computed_root[i].ok_or(SynthesisError::AssignmentMissing),
            // );
            // computed_root_var.push(tmp.unwrap());
        }

        // merkle_authentication_path_variable_constraint
        for i in 0..self.tree_depth as usize {
            for j in 0..self.digest_size as usize {
                cs.enforce(
                    || format!("left_digests_var_bool_constraint[{}][{}]", i, j),
                    |lc| lc + left_digests_var[i][j],
                    |lc| lc + CS::one() - left_digests_var[i][j],
                    |lc| lc,
                );

                cs.enforce(
                    || format!("right_digests_var_bool_constraint[{}][{}]", i, j),
                    |lc| lc + right_digests_var[i][j],
                    |lc| lc + CS::one() - right_digests_var[i][j],
                    |lc| lc,
                );
            }
        }


        // merkle_tree_check_read_gadget_contraint
        // 该部分一共有两个约束，一个是digest_selector_gadget的约束，一个是hash函数的约束
        println!("begin merkle_tree_check_read_gadget_contraint");
        for i in (0..self.tree_depth as usize).rev() {
            // digest_selector_gadget constraint
            if i == self.tree_depth as usize -1 {
                for j in 0..self.digest_size as usize {
                    
                    cs.enforce(
                        || format!("digest_selector_gadget[{}][{}]", i, j),
                        |lc| lc + address_bits_var[self.tree_depth as usize-1-i],
                        |lc| lc + right_digests_var[i][j] - left_digests_var[i][j],
                        |lc| lc + leaf_digest_var[j] - left_digests_var[i][j],
                    );
                }

            } else {
                for j in 0..self.digest_size as usize {
                    // let address_bits_val = AllocatedNum::<E>::getEFrValue(&address_bits[tree_depth as usize - 1 - i]);
                    // let right_digests_val = AllocatedNum::<E>::getEFrValue(&right_digests[i][j]);
                    // let left_digests_val = AllocatedNum::<E>::getEFrValue(&left_digests[i][j]);
                    // let internal_output_val = AllocatedNum::<E>::getEFrValue(&internal_output[i][j]);

                    // if address_bits_val*(right_digests_val-left_digests_val) != internal_output_val-left_digests_val {
                    //     print!("i: {}  j: {}  ", i , j);
                    //     AllocatedNum::<E>::PrintEFr(&address_bits[tree_depth as usize-1-i]);
                    //     AllocatedNum::<E>::PrintEFr(&right_digests[i][j]);
                    //     AllocatedNum::<E>::PrintEFr(&left_digests[i][j]);
                    //     AllocatedNum::<E>::PrintEFr(&internal_output[i][j]);
                    //     print!("\n");
                    //     break;
                    // }
                    cs.enforce(
                        || format!("digest_selector_gadget[{}][{}]", i, j),
                        |lc| lc + address_bits_var[self.tree_depth as usize-1-i],
                        |lc| lc + right_digests_var[i][j] - left_digests_var[i][j],
                        |lc| lc + internal_output_var[i][j] - left_digests_var[i][j],
                    );
                }
            }

            // SHA256 hash 的约束已经在求解hash的output的时候已经完成。
            // TODO
        }
        
        // 最后添加对计算结果检查的约束
        for i in 0..self.digest_size as usize {
            cs.enforce(
                || format!("root_digest[{}] == computed_root[{}]", i, i),
                |lc| lc + root_digest_var[i],
                |lc| lc + CS::one(),
                |lc| lc + computed_root_var[i], 
            );
        }

        Ok(())
    }
}

#[test]
fn test_merkletree() {
    use curve::bn_256::{Fr};
    use math::test_rng;
    use scheme::groth16::{
        create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
    };
    use rand::Rng;
    /*prepare test*/
    // 构造withness的过程
    type EFr = Option<Fr>;
    let mut cs = TestConstraintSystem::<Fr>::new();
    let mut digest_len: u64 = 256;
    let mut tree_depth: u64 = 16;
    // Vec::with_capacity(digest_len as usize); 只是申明最大容量，优化扩容过程
    let mut path: Vec<Vec<EFr>> = vec![vec![Some(Fr::from(0u32)); digest_len as usize]; tree_depth as usize];

    let mut pre_hash: Vec<Option<Fr>> = vec![Some(Fr::from(0u32)); digest_len as usize];
    for i in 0..digest_len {
        let mut randNum = test_rng().gen_range(0, 2);
        if 0 == randNum {
            pre_hash[i as usize] = Some(Fr::from(0u32));
        }else {
            pre_hash[i as usize] = Some(Fr::from(1u32));
        }
    }

    let mut leaf_digest = pre_hash.clone();
    let mut address_bits: Vec<EFr> = Vec::new();
    let mut address: u64 = 0;

    for i in (0..tree_depth).rev() {
        let randNum = test_rng().gen_range(0,2);
        let mut computed_is_right: bool = if randNum == 0 {false} else {true};
        address |= if computed_is_right == true {1 << (tree_depth-1- i as u64)} else {0};
        address_bits.push(if computed_is_right {Some(Fr::from(1u32))} else {Some(Fr::from(0u32))});

        let mut other: Vec<EFr> = vec![Some(Fr::from(0u32)); digest_len as usize];
        for i in 0..digest_len {
            let mut randNum = test_rng().gen_range(0, 2);
            if 0 == randNum {
                other[i as usize] = Some(Fr::from(0u32));
            }else {
                other[i as usize] = Some(Fr::from(1u32));
            }
        }
        let mut h: Vec<EFr> = vec![Some(Fr::from(0u32)); digest_len as usize];
        let mut content: Vec<EFr> = Vec::new();
        let mut tmp1 = other.clone();
        let mut tmp2 = pre_hash.clone();
        if true == computed_is_right {
            // block.append(&mut tmp1);
            // block.append(&mut tmp2);
            // SHA256TwoToOneHashGadget::gethash(&tmp1, &tmp2, &h);
            content.append(&mut tmp1);
            content.append(&mut tmp2);
        }else {
            // block.append(&mut tmp2);
            // block.append(&mut tmp1);
            // SHA256TwoToOneHashGadget::gethash(&tmp2, &tmp1, &h);
            content.append(&mut tmp2);
            content.append(&mut tmp1);
        }

        assert!(512 == content.len());
        let mut input_bits: Vec<_> = (0..512).map(|_| Boolean::Constant(false)).collect();
        for (i, x) in content.iter().enumerate() {
            if x.unwrap() == Fr::from(1u32) {
                input_bits[i] = Boolean::Constant(true);
            }
        }
        // cs1 仅仅用来求hash值
        let mut cs1 = TestConstraintSystem::<Fr>::new();
        let mut r = sha256(& mut cs1, &input_bits).unwrap();
        assert!(r.len() == 256);

        for (i, x) in r.iter().enumerate() {
            if false == x.get_value().unwrap() {
                h[i] = Some(Fr::from(0u32));
            }else {
                h[i] = Some(Fr::from(1u32));
            }
        }
        assert!(digest_len as usize == h.len());

        path[i as usize] = other.clone();
        pre_hash = h;
    }
    let mut root_digest: Vec<EFr> = pre_hash;

    /*execute test*/
    let rng = &mut test_rng();
    println!("Creating parameters...");

    // 构造空电路生成pk和vk
    let params = {
        let c = MerkletreeDemo::<Fr> {
            // tree_depth: tree_depth,
            // digest_size: digest_len,
            // address_bits: Vec::new(),
            // leaf_digest: Vec::new(),
            // root_digest: Vec::new(),
            // path: Vec::new(),
            tree_depth: tree_depth,
            digest_size: digest_len,
            address_bits: vec![None; tree_depth as usize],
            leaf_digest: vec![None; digest_len as usize],
            root_digest: vec![None; digest_len as usize],
            path: vec![vec![None; digest_len as usize]; tree_depth as usize],
        };

        generate_random_parameters(c, rng).unwrap()
    };

    let pvk = prepare_verifying_key(&params.vk);

    println!("Create proofs...");
    println!("tree_depth: {}", tree_depth);
    let c1 = MerkletreeDemo::<Fr> {
        tree_depth: tree_depth,
        digest_size: digest_len,
        address_bits: address_bits,
        leaf_digest: leaf_digest,
        root_digest: root_digest,
        path: path,
    };
    let proof = create_random_proof(c1, &params, rng).unwrap();
    println!("cs.num_contraints: {}", cs.num_constraints());
    assert!(verify_proof(&pvk, &proof, &[]).unwrap());

}