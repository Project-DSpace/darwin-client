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

    // Rerun when HEAD moves. A checkout changes HEAD and a commit the branch
    // ref, but once `git gc` or `git pack-refs` has moved that ref into
    // packed-refs, the next commit writes it to a new file, not watched yet.
    // HEAD's reflog covers that: by default git appends to it on every
    // commit, checkout, reset and pull. Only existing files are named, since
    // a missing one would rerun this script on every build.
    println!("cargo:rerun-if-changed=build.rs");
    let mut watched = vec!["HEAD".to_string(), "logs/HEAD".to_string()];
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
