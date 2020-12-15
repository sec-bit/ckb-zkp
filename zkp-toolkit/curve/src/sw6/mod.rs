// The following code is from (scipr-lab's zexe)[https://github.com/scipr-lab/zexe] and thanks for their work

#[cfg(feature = "sw6")]
mod curves;
mod fields;

#[cfg(feature = "sw6")]
pub use curves::*;
pub use fields::*;
