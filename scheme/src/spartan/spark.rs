use crate::spartan::commitments::packing_poly_commit;
use crate::spartan::data_structure::{
    AddrTimestamps, EncodeCommit, EncodeMemory, HashForMemoryChecking, MemoryLayer,
    ProdForMemoryChecking, ProductCircuit, SnarkParameters,
};
use crate::spartan::r1cs::{switch_matrix_to_list, R1CSInstance};
use math::{log2, Curve, One, Zero};
// use scheme::r1cs::constraint_system::ConstraintSystem;
use crate::math::PrimeField;
use crate::r1cs::SynthesisError;
use crate::Vec;
use core::cmp;
use rand::Rng;

pub fn encode<G: Curve, R: Rng>(
    params: &SnarkParameters<G>,
    r1cs: &R1CSInstance<G>,
    rng: &mut R,
) -> Result<(EncodeMemory<G>, EncodeCommit<G>), SynthesisError> {
    assert_eq!(r1cs.a_matrix.len(), r1cs.b_matrix.len());
    assert_eq!(r1cs.b_matrix.len(), r1cs.c_matrix.len());
    // convert matix to array
    let t = cmp::max(r1cs.num_aux, r1cs.num_inputs).next_power_of_two();
    let m = cmp::max(t * 2, r1cs.num_constraints).next_power_of_two();
    let (mut a_val, mut a_row, mut a_col) = switch_matrix_to_list::<G>(&r1cs.a_matrix, t).unwrap();
    let (mut b_val, mut b_row, mut b_col) = switch_matrix_to_list::<G>(&r1cs.b_matrix, t).unwrap();
    let (mut c_val, mut c_row, mut c_col) = switch_matrix_to_list::<G>(&r1cs.c_matrix, t).unwrap();
    assert_eq!(a_val.len(), a_row.len());
    assert_eq!(a_row.len(), a_col.len());
    assert_eq!(b_val.len(), b_row.len());
    assert_eq!(b_row.len(), b_col.len());
    assert_eq!(c_val.len(), c_row.len());
    assert_eq!(c_row.len(), c_col.len());

    let n = cmp::max(cmp::max(a_row.len(), b_row.len()), c_row.len()).next_power_of_two();
    a_row.resize(n, 0);
    b_row.resize(n, 0);
    c_row.resize(n, 0);
    a_col.resize(n, 0);
    b_col.resize(n, 0);
    c_col.resize(n, 0);
    a_val.resize(n, G::Fr::zero());
    b_val.resize(n, G::Fr::zero());
    c_val.resize(n, G::Fr::zero());
    let val_list = vec![a_val, b_val, c_val];

    // encode memory in the head
    let row_addr_ts = memory_in_the_head::<G>([a_row, b_row, c_row].to_vec(), n, m).unwrap();
    let col_addr_ts = memory_in_the_head::<G>([a_col, b_col, c_col].to_vec(), n, m).unwrap();
    // PC_SPARK: commit
    let mut ops_list = Vec::new();
    for list in row_addr_ts
        .addrs
        .iter()
        .chain(row_addr_ts.read_ts_list.iter())
        .chain(col_addr_ts.addrs.iter())
        .chain(col_addr_ts.read_ts_list.iter())
        .chain(val_list.iter())
        .into_iter()
    {
        ops_list.extend(list);
    }
    ops_list.resize(ops_list.len().next_power_of_two(), G::Fr::zero());

    let (ops_commit, _) = packing_poly_commit::<G, R>(
        &params.r1cs_eval_params.ops_params.gen_n.generators,
        &ops_list,
        &params.r1cs_eval_params.ops_params.gen_n.h,
        rng,
        false,
    )
    .unwrap();

    let mut mem_list = row_addr_ts.audit_ts.clone();
    mem_list.extend(&col_addr_ts.audit_ts);
    mem_list.resize(mem_list.len().next_power_of_two(), G::Fr::zero());
    let (mem_commit, _) = packing_poly_commit::<G, R>(
        &params.r1cs_eval_params.mem_params.gen_n.generators,
        &mem_list,
        &params.r1cs_eval_params.mem_params.gen_n.h,
        rng,
        false,
    )
    .unwrap();

    let encode_commit = EncodeCommit::<G> {
        n,
        m,
        ops_commit,
        mem_commit,
    };

    let encode_mem = EncodeMemory::<G> {
        row_addr_ts,
        col_addr_ts,
        val_list,
        ops_list,
        mem_list,
    };

    Ok((encode_mem, encode_commit))
}

pub fn equalize_length<G: Curve>(
    rx: &Vec<G::Fr>,
    ry: &Vec<G::Fr>,
) -> Result<(Vec<G::Fr>, Vec<G::Fr>), SynthesisError> {
    let xlen = rx.len();
    let ylen = ry.len();

    let mut rx_ext = rx.clone();
    let mut ry_ext = ry.clone();
    if xlen < ylen {
        let diff = ylen - xlen;
        rx_ext = vec![G::Fr::zero(); diff];
        rx_ext.extend(rx);
        ry_ext = ry.clone();
    } else if xlen > ylen {
        let diff = xlen - ylen;
        ry_ext = vec![G::Fr::zero(); diff];
        ry_ext.extend(ry);
        rx_ext = rx.clone();
    }
    assert_eq!(rx_ext.len(), ry_ext.len());

    Ok((rx_ext, ry_ext))
}

pub fn memory_in_the_head<G: Curve>(
    addrs_list: Vec<Vec<usize>>,
    n: usize,
    m: usize,
) -> Result<AddrTimestamps<G>, SynthesisError> {
    let mut audit_ts = vec![0; m];
    let mut read_ts_list = Vec::new();
    let mut addr_fr_list = Vec::new();

    for addrs in addrs_list.iter() {
        assert_eq!(addrs.len(), n);
        let mut read_ts = vec![0; addrs.len()];
        for (i, addr) in addrs.iter().enumerate() {
            let r_ts = audit_ts[*addr];
            let ts = r_ts + 1; // cmp::max(ts, r_ts) + 1;
            read_ts[i] = r_ts;
            // write_ts[i] = ts;
            audit_ts[*addr] = ts;
        }
        let read_ts = (0..read_ts.len())
            .map(|i| G::Fr::from_repr(<G::Fr as PrimeField>::BigInt::from(read_ts[i] as u64)))
            .collect::<Vec<G::Fr>>();
        let addrs_fr = (0..addrs.len())
            .map(|i| G::Fr::from_repr(<G::Fr as PrimeField>::BigInt::from(addrs[i] as u64)))
            .collect::<Vec<G::Fr>>();
        read_ts_list.push(read_ts);
        addr_fr_list.push(addrs_fr);
    }

    let audit_ts = (0..m)
        .map(|i| G::Fr::from_repr(<G::Fr as PrimeField>::BigInt::from(audit_ts[i] as u64)))
        .collect::<Vec<G::Fr>>();

    let ts = AddrTimestamps::<G> {
        addr_index: addrs_list,
        addrs: addr_fr_list,
        read_ts_list: read_ts_list,
        audit_ts: audit_ts,
    };
    Ok(ts)
}

pub fn circuit_eval_opt<G: Curve>(
    encode: &EncodeMemory<G>,
    gamma: (G::Fr, G::Fr),
    e_list: (&Vec<Vec<G::Fr>>, &Vec<Vec<G::Fr>>),
    mem: (&Vec<G::Fr>, &Vec<G::Fr>),
) -> Result<(MemoryLayer<G>, MemoryLayer<G>), SynthesisError> {
    let (mem_row, mem_col) = mem;
    let (e_row, e_col) = e_list;

    let row_layer = memory_checking::<G>(
        &encode.row_addr_ts.addrs,
        mem_row,
        &encode.row_addr_ts.read_ts_list,
        &encode.row_addr_ts.audit_ts,
        e_row,
        gamma,
    )
    .unwrap();

    let col_layer = memory_checking::<G>(
        &encode.col_addr_ts.addrs,
        mem_col,
        &encode.col_addr_ts.read_ts_list,
        &encode.col_addr_ts.audit_ts,
        e_col,
        gamma,
    )
    .unwrap();
    Ok((row_layer, col_layer))
}

pub fn memory_checking<G: Curve>(
    lists: &Vec<Vec<G::Fr>>,
    mem: &Vec<G::Fr>,
    read_ts_list: &Vec<Vec<G::Fr>>,
    audit_ts: &Vec<G::Fr>,
    e_list: &Vec<Vec<G::Fr>>,
    gamma: (G::Fr, G::Fr),
) -> Result<MemoryLayer<G>, SynthesisError> {
    let (gamma1, gamma2) = gamma;
    // let gamma2 = G::Fr::zero();

    assert_eq!(lists.len(), read_ts_list.len());
    assert_eq!(mem.len(), audit_ts.len());
    assert_eq!(lists.len(), e_list.len());
    // hash: H_gamma(A, V, T) = [h_gamma(A[i], V[i], T[i])], h_gamma(a, v, t) = a * gamma^2 + v * gamma + t
    let init_a = (0..mem.len())
        .map(|i| G::Fr::from_repr(<G::Fr as PrimeField>::BigInt::from(i as u64)))
        .collect::<Vec<G::Fr>>();
    let init_hash =
        circuit_hash::<G>(&init_a, &mem, &vec![G::Fr::zero(); mem.len()], gamma1).unwrap();

    let mut read_ts_hash_list = Vec::new();
    let mut write_ts_hash_list = Vec::new();
    for ((list, read_ts), e) in lists.iter().zip(read_ts_list.iter()).zip(e_list.iter()) {
        // assert_eq!(list.len(), read_ts.len());
        let write_ts = (0..read_ts.len())
            .map(|i| read_ts[i] + &G::Fr::one())
            .collect::<Vec<G::Fr>>();
        let read_ts_hash = circuit_hash::<G>(&list, &e, read_ts, gamma1).unwrap();
        let write_ts_hash = circuit_hash::<G>(&list, &e, &write_ts, gamma1).unwrap();
        read_ts_hash_list.push(read_ts_hash);
        write_ts_hash_list.push(write_ts_hash);
    }
    let audit_ts_hash = circuit_hash::<G>(&init_a, &mem, &audit_ts, gamma1).unwrap();
    let hash = HashForMemoryChecking::<G> {
        init_hash: init_hash.clone(),
        read_ts_hash_list: read_ts_hash_list.clone(),
        write_ts_hash_list: write_ts_hash_list.clone(),
        audit_ts_hash: audit_ts_hash.clone(),
    };
    // construct product circuit
    let init_vals = (0..init_hash.len())
        .map(|i| init_hash[i] - &gamma2)
        .collect::<Vec<G::Fr>>();
    let init_prod = construct_product_circuit::<G>(init_vals).unwrap();
    let mut read_ts_prod_list = Vec::new();
    for read_ts_hash in read_ts_hash_list.iter() {
        let read_vals = (0..read_ts_hash.len())
            .map(|i| read_ts_hash[i] - &gamma2)
            .collect::<Vec<G::Fr>>();
        let read_ts_prod = construct_product_circuit::<G>(read_vals).unwrap();
        read_ts_prod_list.push(read_ts_prod);
    }
    let mut write_ts_prod_list = Vec::new();
    for write_ts_hash in write_ts_hash_list.iter() {
        let write_vals = (0..write_ts_hash.len())
            .map(|i| write_ts_hash[i] - &gamma2)
            .collect::<Vec<G::Fr>>();
        let write_ts_prod = construct_product_circuit::<G>(write_vals).unwrap();
        write_ts_prod_list.push(write_ts_prod);
    }
    let audit_vals = (0..audit_ts_hash.len())
        .map(|i| audit_ts_hash[i] - &gamma2)
        .collect::<Vec<G::Fr>>();
    let audit_ts_prod = construct_product_circuit::<G>(audit_vals).unwrap();

    // check product
    let init = evaluate_product_circuit::<G>(&init_prod).unwrap();
    let read: G::Fr = (0..read_ts_prod_list.len())
        .map(|i| evaluate_product_circuit::<G>(&read_ts_prod_list[i]).unwrap())
        .product();

    let write = (0..write_ts_prod_list.len())
        .map(|i| evaluate_product_circuit::<G>(&write_ts_prod_list[i]).unwrap())
        .product();
    let audit = evaluate_product_circuit::<G>(&audit_ts_prod).unwrap();
    assert_eq!(init * &write, read * &audit);

    let prod = ProdForMemoryChecking::<G> {
        init_prod,
        read_ts_prod_list,
        write_ts_prod_list,
        audit_ts_prod,
    };

    let layer = MemoryLayer::<G> { hash, prod };
    Ok(layer)
}

pub fn circuit_hash<G: Curve>(
    a_list: &Vec<G::Fr>,
    v_list: &Vec<G::Fr>,
    t_list: &Vec<G::Fr>,
    gamma: G::Fr,
) -> Result<Vec<G::Fr>, SynthesisError> {
    assert_eq!(a_list.len(), v_list.len());
    assert_eq!(a_list.len(), t_list.len());

    let list = (0..a_list.len())
        .map(|i| a_list[i] * &gamma * &gamma + &(v_list[i] * &gamma) + &t_list[i])
        .collect::<Vec<G::Fr>>();

    Ok(list)
}

// TODO?
pub fn construct_product_circuit<G: Curve>(
    list: Vec<G::Fr>,
) -> Result<ProductCircuit<G>, SynthesisError> {
    let mut left_vec = Vec::new();
    let mut right_vec = Vec::new();
    let mut list = list.clone();

    let layer = log2(list.len()) as usize;
    for _ in 0..layer {
        let mut tlen = list.len() / 2;
        if tlen * 2 < list.len() {
            list.push(G::Fr::one());
            tlen = tlen + 1;
        }

        let outp_left = list[0..tlen].to_vec();
        let outp_right = list[tlen..list.len()].to_vec();

        list = (0..tlen)
            .map(|j| outp_left[j] * &outp_right[j])
            .collect::<Vec<G::Fr>>();

        left_vec.push(outp_left);
        right_vec.push(outp_right);
    }

    let circuit_prod = ProductCircuit::<G> {
        left_vec,
        right_vec,
    };

    Ok(circuit_prod)
}

pub fn evaluate_product_circuit<G: Curve>(
    prod_circuit: &ProductCircuit<G>,
) -> Result<G::Fr, SynthesisError> {
    assert_eq!(prod_circuit.left_vec.len(), prod_circuit.right_vec.len());

    let clen = prod_circuit.left_vec.len();
    assert_eq!(prod_circuit.left_vec[clen - 1].len(), 1);
    assert_eq!(prod_circuit.right_vec[clen - 1].len(), 1);

    Ok(prod_circuit.left_vec[clen - 1][0] * &prod_circuit.right_vec[clen - 1][0])
}

pub fn evaluate_dot_product_circuit<G: Curve>(
    row: &Vec<G::Fr>,
    col: &Vec<G::Fr>,
    val: &Vec<G::Fr>,
) -> Result<G::Fr, SynthesisError> {
    assert_eq!(row.len(), col.len());
    assert_eq!(col.len(), val.len());

    let result = (0..row.len()).map(|i| row[i] * &col[i] * &val[i]).sum();

    Ok(result)
}
