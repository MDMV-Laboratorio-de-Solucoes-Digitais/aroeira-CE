// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    load_env_for_oauth_config();
    appsdesktop::run();
}

fn load_env_for_oauth_config() {
    if cfg!(debug_assertions) {
        let _ = dotenvy::dotenv();
    }
}
