use axum::{http::StatusCode, response::IntoResponse, Router};
use std::net::SocketAddr;
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::info;

mod config;
mod error;
mod models;
mod routes;

use config::Config;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub http_client: reqwest::Client,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aroeira_oauth_proxy=info,tower_http=info".into()),
        )
        .init();

    let config = Arc::new(Config::from_env()?);

    info!(
        "Starting Aroeira OAuth Proxy on {}",
        config.server_bind_address
    );

    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let state = AppState {
        config,
        http_client,
    };

    // Build CORS policy from config (supports exact origins and `*.` suffix entries)
    let allowed = state.config.allowed_origins.clone();
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(
            move |origin: &axum::http::HeaderValue, _req: &axum::http::request::Parts| {
                let Ok(origin_str) = origin.to_str() else {
                    return false;
                };
                // `Origin` is a serialized scheme+host(+port) (no paths)
                let Ok(origin_url) = url::Url::parse(origin_str) else {
                    return false;
                };

                let host = origin_url
                    .host_str()
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                let scheme = origin_url.scheme();

                // Only allow http/https origins
                if scheme != "http" && scheme != "https" {
                    return false;
                }

                allowed.iter().any(|rule| {
                    let rule = rule.trim();
                    if let Ok(rule_url) = url::Url::parse(rule) {
                        // Exact match for fully-qualified origins
                        return origin_str
                            .eq_ignore_ascii_case(rule_url.as_str().trim_end_matches('/'));
                    }

                    if let Some(suffix) = rule.strip_prefix("https://*.") {
                        // Controlled wildcard: https://*.example.com
                        return scheme == "https"
                            && host.ends_with(&format!(".{}", suffix.to_ascii_lowercase()));
                    }

                    if let Some(suffix) = rule.strip_prefix("http://*.") {
                        return scheme == "http"
                            && host.ends_with(&format!(".{}", suffix.to_ascii_lowercase()));
                    }

                    false
                })
            },
        ))
        .allow_methods([axum::http::Method::POST])
        .allow_headers([axum::http::header::CONTENT_TYPE, axum::http::header::ACCEPT]);

    let app = Router::new()
        .route("/health", axum::routing::get(health_check))
        .nest("/oauth", routes::router())
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(cors),
        )
        .with_state(state.clone());

    let addr: SocketAddr = state.config.server_bind_address.parse()?;
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    info!("Server listening on {}", addr);

    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "{\"status\":\"healthy\"}")
}
