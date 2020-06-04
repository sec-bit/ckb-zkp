use std::env;

pub enum Gadget {
    Mimc,
}

pub fn handle_args() -> Result<(Gadget, bool), ()> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 3 && args.len() != 2 {
        println!("Show Parameters and print: trusted-setup mimc");
        println!("Override the source code : trusted-setup mimc --force");
        return Err(());
    }

    let g = match args[1].as_str() {
        "mimc" => Gadget::Mimc,
        _ => Gadget::Mimc,
    };

    let force = if args.len() == 3 {
        match args[2].as_str() {
            "--force" => true,
            _ => false,
        }
    } else {
        false
    };

    Ok((g, force))
}
