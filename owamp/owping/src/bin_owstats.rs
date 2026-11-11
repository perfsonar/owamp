//! Install name `owstats` — same as C argv[0] dispatch of `owping`.

fn main() -> std::process::ExitCode {
    owping::main_owstats()
}
