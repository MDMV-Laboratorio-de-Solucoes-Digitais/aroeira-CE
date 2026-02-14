// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    load_env_for_oauth_config();
    appsdesktop::run();
}

fn load_env_for_oauth_config() {
    #[cfg(debug_assertions)]
    {
        // Silently ignore missing .env file - it's optional in development.
        // Using .ok() is idiomatic for optional configuration files.
        let _ = dotenvy::dotenv();
    }
}
