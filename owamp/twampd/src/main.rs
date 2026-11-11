//! Binary-Einstieg — wie C `owampd/twampd.c`.

fn main() {
    if let Err(e) = owampd::twampd::main_twamp() {
        eprintln!("twampd: {e:#}");
        std::process::exit(1);
    }
}
