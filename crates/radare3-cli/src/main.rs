#![forbid(unsafe_code)]

fn main() {
    let mut args = std::env::args();
    let _program = args.next();

    match args.next().as_deref() {
        Some("--version" | "-V") => {
            println!("radare3 {}", env!("CARGO_PKG_VERSION"));
        }
        Some("--help" | "-h") | None => {
            println!(
                "radare3 {}\n\nUsage: radare3 [--version]\n\nAnalysis commands are not implemented yet.",
                env!("CARGO_PKG_VERSION")
            );
        }
        Some(other) => {
            eprintln!("radare3: unsupported argument: {other}");
            std::process::exit(2);
        }
    }
}
