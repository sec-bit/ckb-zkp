---
title: "Zkp Toolkit_gadget汇总"
date: 2020-05-28T11:06:43+08:00
draft: true
---

# zkp-toolkit Gadget list

> 本文主要列出了zkp-toolkit库在第一阶段已经实现的gadget，实现过程中参照了bellman，libsnark以及ethsnarkgadget的代码。各个gadget的代码位于zkp-toolkit/src/gadget文件夹下，本文主要简略分析了各个gadget的实现。

## gadget list

- [x] rangeproof
- [x] isnonzero
- [x] lookup_1bit
- [x] lookup_2bit
- [x] lookup_3bit
- [x] merkletree
- [x] boolean
- [x] mimc

## gadget详解

### zkp-toolkit gadget写法

在 zkp-toolkit里面，有一个叫 ConstraintSynthesizer 的 trait，要在 groth16 中完成验证，就要继承这个 trait，在这个 trait 下，有一个函数 `generate_constraints`，这里面实现了电路的构造，代入或者不代入 witness 构造电路都是通过这个函数实现的，因此它会在被用到两次，一次是setup构造电路的时候，这里witness被置为 None，一次是生成证明,代入witness计算的时候。

```rust
/// Computations are expressed in terms of rank-1 constraint systems (R1CS).
/// The `generate_constraints` method is called to generate constraints for
/// both CRS generation and for proving.
pub trait ConstraintSynthesizer<F: Field> {
    /// Drives generation of new constraints inside `CS`.
    fn generate_constraints<CS: ConstraintSystem<F>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError>;
}
```

在上面实现的`generate_constraints`函数中实现好电路之后，需要对已有的电路进行测试，一般的测试步骤如下：

1. 通过生成的随机值以及空电路来生成pvk。

```rust
let mut rng = &mut test_rng();
    let n = 10u64; // range 0 ~ 2^10

    println!("Creating parameters...");
    let params = {
        let c = RangeProof::<Fr> {
            lhs: None,
            rhs: None,
            n: n,
        };

        generate_random_parameters::<Bn_256, _, _>(c, &mut rng).unwrap()
    };

    let pvk = prepare_verifying_key(&params.vk);
```

2. 将withness带入电路实例生成proof。

```rust
    println!("Creating proofs...");

    let c1 = RangeProof::<Fr> {
        lhs: Some(Fr::from(24u32)),
        rhs: Some(Fr::from(25u32)),
        n: n,
    };

    let proof = create_random_proof(c1, &params, &mut rng).unwrap();
```

3. 通过vk，proof，以及public input验证生成proof是否正确。

```rust
    println!("Proofs ok, start verify...");

    assert!(verify_proof(&pvk, &proof, &[Fr::from(2u32).pow(&[n])]).unwrap());
```

rangeproof的测试样例如下:

```rust
#[test]
fn test_rangeproof() {
    use curve::bn_256::{Bn_256, Fr};
    use math::fields::Field;
    use math::test_rng;
    use scheme::groth16::{
        create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
    };

    let mut rng = &mut test_rng();
    let n = 10u64; // range 0 ~ 2^10

    println!("Creating parameters...");
    let params = {
        let c = RangeProof::<Fr> {
            lhs: None,
            rhs: None,
            n: n,
        };

        generate_random_parameters::<Bn_256, _, _>(c, &mut rng).unwrap()
    };

    let pvk = prepare_verifying_key(&params.vk);

    println!("Creating proofs...");

    let c1 = RangeProof::<Fr> {
        lhs: Some(Fr::from(24u32)),
        rhs: Some(Fr::from(25u32)),
        n: n,
    };

    let proof = create_random_proof(c1, &params, &mut rng).unwrap();
    println!("Proofs ok, start verify...");

    assert!(verify_proof(&pvk, &proof, &[Fr::from(2u32).pow(&[n])]).unwrap());
}
```



### rangeproof

#### 功能

比较两个变量的大小(lhs,rhs)

#### 约束

- 计算 alpha_packed = 2^n + B - A，为了验证者两者相等，增加电路

  `1 * (2^n + B - A) = alpha_packed`

- alpha 数组表示 alpha_packed 的二进制表示方式，为了验证两者相等，增加电路

  `1 * sum(bits) = alpha_packed`

- 为了验证 alpha 数组每一位都是二进制

  `(1 - bits_i) * bits_i = 0`

计算 sum = ∑ bits_i （i=0..n-1）

当sum=0 时候，说明 lhs = rhs，令 output = 0，inv = 0

当sum != 0时候，说明 lhs ！= rhs，令 output = 1 ，inv = 1/sum，output （也就是not_all_zeros）表示了两个数是否相等的关系。

- 为了保证 output 为二进制数，验证 

  `(1 - output) * output = 0`

- 约束 output 和 sum 的关系，有两个等式约束，当 sum 不为 0 时，output 必然为 1

  `(1-output) * sum = 0`

- 当 sum = 0 时，output 也必须为 0

  `inv * sum = output`

- less_or_eq 就是 alpha[n] ，因而 less_or_eq 和 less 的关系可以表示为

  `less_or_eq  * output = less`

- 验证 < 关系是否成立：`less * 1 = 1`

#### 代码实现

![](../rangeproof.rs#L1)

### isnonezero

#### 功能

判断变量值是否为非零

#### 约束

ethsnark中该gadget一共有两个约束X是输入值，Y是输出值。两个约束分别为:

X*(1-Y)=0

X*(1/X)=0

zkp-toolkit中没有结果输出变量Y，因此约束为：

$X*(1/X)=0$

#### 代码实现

![](../isnonzero.rs#L1)

###  lookup_1bit

#### 功能

通过b的一位bit位的二进制值作为下标范围数组C中的值，并且将结果值赋值给r。

#### 约束

输入bit位b，变量数组c，结果值r

$(c[0] + b*c[1]-(b*c[0])) * 1 = r$

当b为0时c[0] = r

当b为1时c[1] = r

#### 代码实现

![](../lookup_1bit.rs#L1)

### lookup_2bit

#### 功能

通过b的二位bit位的二进制值作为下标范围数组C中的值，并且将结果值赋值给r。

#### 约束

输入2bit位b，变量数组c，结果值r

$(c[1] - c[0] + (b[1] * (c[3] - c[2] - c[1] + c[0])))*b[0]=-c[0] + r + (b[1] * (-c[2] + c[0]))$

上述约束参考了ethsnark中的写法，如果上面的约束等式成立必须要满足：

b: 00   r = c[0]

b: 01   r = c[1]

b: 10   r = c[2]

b: 11   r = c[3]

#### 代码实现

![](../lookup_2bit.rs#L1)

### lookup_3bit

#### 功能

通过b的三位bit位的二进制值作为下标范围数组C中的值，并且将结果值赋值给r。

#### 约束

$(c[0]+(b[0]*-c[0])+(b[0]*c[1])+(b[1]*-c[0])+(b[1]*c[2])+(b[0]*b[1]*(-c[1] + -c[2] + c[0]+c[3]))+(b[2]*(-c[0]+c[4])) + (b[0]*b[2]*(c[0]-c[1]-c[4]+c[5])) + (b[1]*b[2]*(c[0]-c[2]-c[4]+c[6])) + (b[0]*b[1]*b[2]*(-c[0]+c[1]+c[2]-c[3]+c[4]-c[5]-c[6]+c[7]))) * 1 = r$

上述约束参考了ethsnark中的写法，如果上面的约束等式成立必须要满足：

b: 000   r = c[0]

b: 001   r = c[1]

b: 010   r = c[2]

b: 011   r = c[3]

b: 100   r = c[4]

b: 101   r = c[5]

b: 110   r = c[6]

b: 111   r = c[7]

#### 代码实现

![](../lookup_3bit.rs#L1)

### merkletree

#### 功能

通过给定一条merkletree的验证路径，以及一个叶子节点和根节点。验证叶子节点在该条验证路径之上计算的结果是否预期的根节点相同。

#### 约束

merkletree一共有3类约束

* merkletree计算路径上各个left_digests和right_digests的约束。哈希上的每一位都需要满足$digests[i]*(1-digests[i]) = 0$ 因此这里的约束总数为 $(2*digest\_size-1)*tree\_depth$。
* 从merkletree最底层到根节点tree_depth(这里的tree_depth为实际树高减去1)个哈希的约束。假设每个哈希约束x，总约束为$tree\_depth*x$
* 通过address_bit的bit位来确定leaf哈希节点以及internal_output内部哈希节点的左右位置。每个哈希位的约束为：$is\_right * (right.bits[i] - left.bits[i]) = (input.bits[i] - left.bits[i])$  digest_size次该条约束，一共循环tree_depth 。 约束数量: $digest\_size*tree\_depth$。
* 最后是对电路计算的哈希结果和预期哈希结果相互比较，其电路约束为: $root\_digest[i] * 1 = computed\_root[i]$  一共digests_size个约束。

#### 代码实现

![](../merkletree.rs#L1)

### boolean

#### 功能

boolean逻辑gadget(这部分主要参考bellman/gadget/boolean.rs)，里面有各种关于boolean变量的gadget运算，Boolean是对AllocatedBit的封装。

#### 约束

一共实现了一下bool 操作的 gadget:

```rust
AllocatedBit:
xor: Performs an XOR operation over the two operands
and: Performs an AND operation over the two operands
and_not Calculates: a AND (NOT b)
nor: Calculates (NOT a) AND (NOT b)
u64_into_boolean_vec_le: u64 to Vec<Boolean>
field_into_boolean_vec_le: Field to Vec<Boolean>
field_into_allocated_bits_le: Vec<AllocatedBit>

```



#### 代码实现

![](../boolean.rs#L1)

### mimc

#### 功能

mimc哈希函数

#### 约束

xL, xR := xR + (xL + Ci)^3, xL

tmp = (xL + Ci)^2

new_xL = xR + (xL + Ci)^3

new_xL = xR + tmp * (xL + Ci)

new_xL - xR = tmp * (xL + Ci)

MIMC_ROUNDS轮new_xL = xR + (xL + Ci)^3 个约束

#### 代码实现

![](../mimc.rs#L1)


