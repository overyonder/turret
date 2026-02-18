use std::io::Read;

fn main() {
    // Modes:
    // - default: precedence argv -> env -> stdin
    // - triplecheck: require all three channels to match (multiple quantities)

    // Mode switch: if argv contains "triplecheck", enforce the strict mode.
    if std::env::args().any(|a| a == "triplecheck") {
        if triplecheck_ok() {
            println!("all three speak true");
            std::process::exit(0);
        }
        std::process::exit(1);
    }

    // Precedence: argv -> env -> stdin

    // 1) argv: rumplestiltskin
    let mut args = std::env::args();
    let _ = args.next();
    for a in args {
        if a == "rumplestiltskin" {
            println!("that's my name");
            std::process::exit(0);
        }
    }

    // 2) env: isyourname=tomtittot
    if std::env::var("isyourname").ok().as_deref() == Some("tomtittot") {
        println!("I know him but that's not me");
        std::process::exit(0);
    }

    // 3) stdin: rampelnik
    let mut buf = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut buf);
    let s = String::from_utf8_lossy(&buf);
    let s = s.trim_end_matches(['\n', '\r']);
    if s == "rampelnik" {
        println!("perhaps in a former life");
        std::process::exit(0);
    }

    std::process::exit(1);
}

fn triplecheck_ok() -> bool {
    // Aliases (chosen arbitrarily):
    // - argv must contain at least 2x "pump" and 2x "straw"
    // - env vars isyourname and whatsyourname must be set to specific values
    // - stdin must contain both "rampelnik" and "tomtittot" (whitespace-separated)

    let mut pump = 0usize;
    let mut straw = 0usize;
    for a in std::env::args().skip(1) {
        if a == "pump" {
            pump += 1;
        } else if a == "straw" {
            straw += 1;
        }
    }
    if pump < 2 || straw < 2 {
        return false;
    }

    if std::env::var("isyourname").ok().as_deref() != Some("tomtittot") {
        return false;
    }
    if std::env::var("whatsyourname").ok().as_deref() != Some("rumplestiltskin") {
        return false;
    }

    let mut buf = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut buf);
    let stdin_s = String::from_utf8_lossy(&buf);
    let stdin_parts: std::collections::HashSet<&str> = stdin_s.split_whitespace().collect();
    if !stdin_parts.contains("rampelnik") || !stdin_parts.contains("tomtittot") {
        return false;
    }

    true
}
