//! Build script for generating shell completions and man page.
//!
//! Generates assets at build time for packaging.

use std::env;
use std::fs;

use clap::CommandFactory;
use clap_complete::{generate_to, Shell};
use clap_mangen::Man;

// Wrap the included file in a module to avoid import conflicts
mod cli {
    include!("src/cli/args.rs");
}

fn main() {
    // Only generate during release builds or when explicitly requested
    let profile = env::var("PROFILE").unwrap_or_default();
    let force_generate = env::var("PCAPSQL_GENERATE_ASSETS").is_ok();

    if profile != "release" && !force_generate {
        return;
    }

    let out_dir = std::path::PathBuf::from(
        env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"),
    )
    .parent()
    .expect("No parent directory")
    .join("target")
    .join("assets");

    // Create assets directory
    fs::create_dir_all(&out_dir).expect("Failed to create assets directory");

    let mut cmd = cli::Args::command();
    cmd = cmd.name("pcapsql");

    // Generate shell completions
    for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
        let path = generate_to(shell, &mut cmd, "pcapsql", &out_dir)
            .expect("Failed to generate completions");
        println!("cargo:warning=Generated completion: {}", path.display());
    }

    // Rename zsh completion to expected name
    let zsh_src = out_dir.join("_pcapsql");
    let zsh_dst = out_dir.join("pcapsql.zsh");
    if zsh_src.exists() {
        let _ = fs::rename(&zsh_src, &zsh_dst);
    }

    // Generate man page
    let man = Man::new(cmd);
    let man_path = out_dir.join("pcapsql.1");
    let mut man_file = fs::File::create(&man_path).expect("Failed to create man page file");
    man.render(&mut man_file)
        .expect("Failed to render man page");
    println!("cargo:warning=Generated man page: {}", man_path.display());

    // Tell cargo to rerun if args.rs changes
    println!("cargo:rerun-if-changed=src/cli/args.rs");
}
