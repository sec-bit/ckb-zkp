use std::path::PathBuf;

const GADGET_DIR: &'static str = "./src/gadget";

mod args;
mod mimc;

use args::Gadget;

macro_rules! handle_gadget {
    ($gadget:ident, $p:expr) => {
        $gadget::setup($p);
    };
}

fn main() -> Result<(), ()> {
    let (g, force) = args::handle_args()?;

    let p = if force {
        let path = PathBuf::from(GADGET_DIR);
        if !path.exists() {
            println!("not found source code");
            return Err(());
        }
        Some(path)
    } else {
        None
    };

    match g {
        Gadget::Mimc => handle_gadget!(mimc, p),
    }

    Ok(())
}
