//! OWAMP control/test server — Port von `owampd/owampd.c`.

fn main() {
    if let Err(e) = owampd::run_server(false) {
        eprintln!("owampd: {e:#}");
        std::process::exit(1);
    }
}
