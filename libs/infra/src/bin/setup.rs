use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use walkdir::WalkDir;

const MAX_TEXT_REWRITE_BYTES: u64 = 10 * 1024 * 1024;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !Path::new("Cargo.toml").exists() {
        eprintln!("Error: This script should be run from the project root directory");
        std::process::exit(1);
    }

    println!("🛡️  Aroeira (ah-roh-EH-rah) Setup Wizard 🛡️");
    println!("----------------------------");
    println!("This utility will rename the project and reset git history.");
    println!("WARNING: This action is destructive and cannot be undone easily.\n");

    let new_name = get_validated_project_name()?;
    if confirm_rename(&new_name) {
        let root = env::current_dir()?;
        println!("Working in: {}", root.display());

        rename_files(&root, &new_name)?;
        replace_content(&root, &new_name)?;
        reset_git_if_requested()?;
    }

    println!("\n🚀 Setup Complete! You can now run:");
    println!("  cargo build");
    println!("  npm install");

    Ok(())
}

fn get_validated_project_name() -> Result<String, Box<dyn std::error::Error>> {
    print!("Enter new project name (kebab-case, e.g. my-awesome-app): ");
    io::stdout().flush()?;
    let mut new_name = String::new();
    io::stdin().read_line(&mut new_name)?;
    let new_name = new_name.trim();

    if new_name.is_empty() {
        println!("Aborting: Name cannot be empty.");
        std::process::exit(1);
    }

    if !is_valid_project_name(new_name) {
        println!("Aborting: Invalid project name. Use kebab-case.");
        std::process::exit(1);
    }

    Ok(new_name.to_string())
}

fn confirm_rename(name: &str) -> bool {
    print!("Are you sure you want to rename to '{name}'? (y/N): ");
    io::stdout().flush().ok();
    let mut confirm = String::new();
    io::stdin().read_line(&mut confirm).ok();
    confirm.trim().to_lowercase() == "y"
}

fn rename_files(root: &Path, new_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let old_names = vec!["Aroeira-gemini", "Aroeiramdmv"];
    let mut paths_to_rename = Vec::new();

    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            name != ".git" && name != "target" && name != "node_modules"
        })
        .filter_map(std::result::Result::ok)
    {
        let path = entry.path();
        if let Some(file_name) = path.file_name().map(|n| n.to_string_lossy()) {
            for old in &old_names {
                if file_name.contains(old) {
                    paths_to_rename.push(path.to_path_buf());
                    break;
                }
            }
        }
    }

    paths_to_rename.sort_by_key(|b| std::cmp::Reverse(b.components().count()));

    for path in paths_to_rename {
        if let Some(parent) = path.parent() {
            let file_name = path
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("Path has no file name"))?
                .to_string_lossy();

            let new_file_name = old_names
                .iter()
                .fold(file_name.to_string(), |acc, old| acc.replace(old, new_name));

            let new_path = parent.join(&new_file_name);
            if new_path.exists() && new_path != path {
                let src = path.file_name().map_or_else(
                    || "unknown".to_string(),
                    |f| f.to_string_lossy().to_string(),
                );
                let dst = new_path.file_name().map_or_else(
                    || "unknown".to_string(),
                    |f| f.to_string_lossy().to_string(),
                );
                return Err(
                    format!("Rename collision: target already exists: {dst} (from {src})").into(),
                );
            }

            let path_filename = path
                .file_name()
                .map_or_else(|| "unknown".into(), |f| f.to_string_lossy());
            let new_path_filename = new_path
                .file_name()
                .map_or_else(|| "unknown".into(), |f| f.to_string_lossy());
            println!("Renaming: {path_filename} -> {new_path_filename}");
            fs::rename(&path, &new_path)?;
        }
    }

    Ok(())
}

fn replace_content(root: &Path, new_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            name != ".git" && name != "target" && name != "node_modules"
        })
        .filter_map(std::result::Result::ok)
    {
        let path = entry.path();

        if path.is_file()
            && !path
                .symlink_metadata()
                .map(|meta| meta.file_type().is_symlink())
                .unwrap_or(false)
            && is_text_file(path)
        {
            let Ok(meta) = fs::metadata(path) else {
                continue;
            };

            if meta.len() > MAX_TEXT_REWRITE_BYTES {
                println!(
                    "Skipping large file ({} bytes): {}",
                    meta.len(),
                    path.file_name().map_or_else(
                        || "unknown_file".to_string(),
                        |f| f.to_string_lossy().to_string()
                    )
                );
                continue;
            }

            if let Ok(content) = fs::read_to_string(path) {
                let mut new_content = content.clone();
                let mut modified = false;

                for old in &["Aroeira-gemini", "Aroeiramdmv"] {
                    if new_content.contains(old) {
                        new_content = new_content.replace(old, new_name);
                        modified = true;
                    }
                }

                if modified {
                    println!(
                        "Updating content: {}",
                        path.file_name().map_or_else(
                            || "unknown_file".to_string(),
                            |f| f.to_string_lossy().to_string()
                        )
                    );
                    let tmp_path = path.with_extension("tmp.aroeira_setup");

                    // Refuse to write if the temp path already exists as a symlink (or at all).
                    if tmp_path
                        .symlink_metadata()
                        .map(|m| m.file_type().is_symlink() || m.is_file() || m.is_dir())
                        .unwrap_or(false)
                    {
                        return Err(format!(
                            "Refusing to write temp file because it already exists: {}",
                            "temporary_file"
                        )
                        .into());
                    }

                    {
                        let mut f = fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(&tmp_path)?;
                        f.write_all(new_content.as_bytes())?;
                        f.sync_all()?;
                    }
                    #[cfg(windows)]
                    {
                        // Windows cannot rename over an existing file
                        if path.exists() {
                            fs::remove_file(path)?;
                        }
                    }
                    fs::rename(&tmp_path, path)?;
                }
            }
        }
    }

    println!("\n✅ Content updated.");
    Ok(())
}

fn reset_git_if_requested() -> Result<(), Box<dyn std::error::Error>> {
    print!("Do you want to reset Git history? (y/N): ");
    io::stdout().flush().ok();
    let mut reset_git = String::new();
    io::stdin().read_line(&mut reset_git).ok();

    if reset_git.trim().to_lowercase() == "y" {
        let git_dir = Path::new(".git");
        if git_dir.exists() {
            if fs::symlink_metadata(git_dir)?.file_type().is_symlink() {
                return Err(".git is a symlink, refusing to delete for safety.".into());
            }
            println!("Removing .git directory...");
            fs::remove_dir_all(git_dir)?;
        }

        println!("Initializing new git repository...");
        let git_path = if let Some(git_path_env) = std::env::var_os("GIT_PATH") {
            if git_path_env.is_empty() {
                which::which("git").map_err(|_| "git command not found in PATH")?
            } else {
                std::path::PathBuf::from(git_path_env)
            }
        } else {
            which::which("git").map_err(|_| "git command not found in PATH")?
        };
        let git_path = std::fs::canonicalize(&git_path).unwrap_or(git_path);

        let temp_dir = std::env::temp_dir();
        let cwd = std::env::current_dir().ok();

        let in_temp = git_path.starts_with(&temp_dir);
        let in_cwd = cwd.as_ref().is_some_and(|c| git_path.starts_with(c));

        if in_temp || in_cwd {
            return Err(format!(
                "Security error: refusing to run git from user-writable location: {}",
                git_path.display()
            )
            .into());
        }

        let home_dir = dirs::home_dir();
        if let Some(home) = home_dir
            && git_path.starts_with(&home)
        {
            // Reject ALL git binaries from user-writable locations
            // including common package manager paths
            eprintln!(
                "❌ ERROR: Git binary is located in a user-writable directory: {}",
                git_path.display()
            );
            eprintln!(
                "   For security reasons, setup cannot use git from user-writable locations."
            );
            eprintln!();
            eprintln!("   Please install git from a system-wide location:");
            eprintln!("   - Linux/macOS: Use your package manager (apt, brew, etc.)");
            eprintln!("   - Windows: Download from https://git-scm.com/download/win");
            eprintln!();
            eprintln!(
                "   Alternatively, set the GIT_PATH environment variable to a secure git installation."
            );

            return Err(anyhow::Error::msg("Git binary is in an insecure location").into());
        }

        // Also verify the git binary is not in other user-writable locations
        // by checking file permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = std::fs::metadata(&git_path) {
                let permissions = metadata.permissions().mode();
                // Check if the file is writable by others or group
                if permissions & 0o022 != 0 {
                    eprintln!(
                        "❌ ERROR: Git binary has insecure permissions: {}",
                        git_path.display()
                    );
                    eprintln!("   The git binary must not be writable by other users.");
                    return Err(anyhow::Error::msg("Git binary has insecure permissions").into());
                }
            }
        }

        let status = std::process::Command::new(git_path).arg("init").status()?;
        if !status.success() {
            return Err("git init failed".into());
        }

        println!("✅ Git reset.");
    }

    Ok(())
}

fn is_text_file(path: &std::path::Path) -> bool {
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        let lower = name.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "dockerfile" | ".gitignore" | ".dockerignore" | ".env" | ".env.example"
        ) {
            return true;
        }
    }

    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let ext = ext.to_ascii_lowercase();
        return matches!(
            ext.as_str(),
            "txt"
                | "rs"
                | "js"
                | "ts"
                | "json"
                | "toml"
                | "yaml"
                | "yml"
                | "md"
                | "html"
                | "css"
                | "svelte"
                | "xml"
                | "lock"
                | "sh"
                | "py"
                | "go"
                | "sql"
        );
    }

    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if meta.len() > 50 * 1024 * 1024 {
        return false;
    }

    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };

    let mut sample = vec![0u8; 4096];
    let Ok(n) = std::io::Read::read(&mut f, &mut sample) else {
        return false;
    };
    sample.truncate(n);

    if sample.contains(&0) {
        return false;
    }

    std::str::from_utf8(&sample).is_ok()
}

fn is_valid_project_name(name: &str) -> bool {
    const RUST_KEYWORDS: &[&str] = &[
        "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn",
        "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref",
        "return", "self", "static", "struct", "super", "trait", "true", "type", "unsafe", "use",
        "where", "while", "async", "await", "dyn", "abstract", "become", "box", "do", "final",
        "macro", "override", "priv", "typeof", "unsized", "virtual", "yield", "try",
    ];

    if name.is_empty() || RUST_KEYWORDS.contains(&name) {
        return false;
    }

    !name.starts_with('-')
        && !name.ends_with('-')
        && !name.contains("--")
        && name
            .chars()
            .all(|c| matches!(c, 'a'..='z' | '0'..='9' | '-'))
}
