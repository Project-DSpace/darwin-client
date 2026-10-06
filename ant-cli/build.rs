//! Records the git commit the binary was built from, so `darwin --version`
//! tells builds apart: the package version alone stays 0.3.9 across them.

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?.trim().to_string();
    (!text.is_empty()).then_some(text)
}

fn main() {
    let commit = git(&["rev-parse", "--short=7", "HEAD"]).unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=DARWIN_GIT_COMMIT={commit}");

    // Rerun when HEAD moves: a checkout changes HEAD, a commit changes the
    // branch ref. Only existing files are named, since a missing one would
    // rerun this script on every build. With none, cargo reruns it when any
    // file in the package changes.
    println!("cargo:rerun-if-changed=build.rs");
    let mut watched = vec!["HEAD".to_string()];
    if let Some(head_ref) = git(&["symbolic-ref", "-q", "HEAD"]) {
        watched.push(head_ref);
    }
    watched.push("packed-refs".into());
    for name in watched {
        if let Some(path) = git(&["rev-parse", "--path-format=absolute", "--git-path", &name]) {
            if std::path::Path::new(&path).exists() {
                println!("cargo:rerun-if-changed={path}");
            }
        }
    }
}
