use axum::{
    error_handling::HandleErrorLayer, extract::DefaultBodyLimit, http::StatusCode,
    response::IntoResponse, Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower::buffer::error::ServiceError;
use tower::{buffer::BufferLayer, limit::RateLimitLayer, BoxError, ServiceBuilder};
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
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let state = AppState {
        config,
        http_client,
    };

    let cors = build_cors_layer(&state);
    let app = build_app(state.clone(), cors);

    let addr: SocketAddr = state.config.server_bind_address.parse()?;
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    info!("Server listening on {}", addr);

    axum::serve(listener, app).await?;

    Ok(())
}

fn build_cors_layer(state: &AppState) -> CorsLayer {
    let allowed = state.config.allowed_origins.clone();
    CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(
            move |origin: &axum::http::HeaderValue, _req: &axum::http::request::Parts| {
                validate_origin(origin, &allowed)
            },
        ))
        .allow_methods([axum::http::Method::POST])
        .allow_headers([axum::http::header::CONTENT_TYPE, axum::http::header::ACCEPT])
}

fn validate_origin(origin: &axum::http::HeaderValue, allowed: &[String]) -> bool {
    let Ok(origin_str) = origin.to_str() else {
        return false;
    };
    let Ok(origin_url) = url::Url::parse(origin_str) else {
        return false;
    };

    // Reject authority tricks and non-origin forms early
    let has_userinfo = !origin_url.username().is_empty() || origin_url.password().is_some();
    if has_userinfo {
        return false;
    }

    let Some(host_str) = origin_url.host_str() else {
        return false;
    };

    if origin_url.path() != "/" || origin_url.query().is_some() || origin_url.fragment().is_some() {
        return false;
    }

    let scheme = origin_url.scheme();
    let host = host_str.to_ascii_lowercase();
    let port = origin_url.port_or_known_default();

    if scheme != "http" && scheme != "https" {
        return false;
    }

    allowed.iter().any(|rule| {
        let rule = rule.trim();

        if let Ok(rule_url) = url::Url::parse(rule) {
            // Reject rule URLs with userinfo (security hardening)
            let rule_has_userinfo =
                !rule_url.username().is_empty() || rule_url.password().is_some();
            if rule_has_userinfo {
                return false;
            }

            if rule_url.path() != "/" || rule_url.query().is_some() || rule_url.fragment().is_some()
            {
                return false;
            }

            return scheme.eq_ignore_ascii_case(rule_url.scheme())
                && host.eq_ignore_ascii_case(rule_url.host_str().unwrap_or_default())
                && port == rule_url.port_or_known_default();
        }

        if let Some(suffix) = rule.strip_prefix("https://*.") {
            let suffix = suffix.trim().trim_start_matches('.').to_ascii_lowercase();
            return scheme == "https"
                && port == Some(443)
                && host != suffix
                && host.ends_with(&format!(".{suffix}"));
        }

        if let Some(suffix) = rule.strip_prefix("http://*.") {
            let suffix = suffix.trim().trim_start_matches('.').to_ascii_lowercase();
            return scheme == "http"
                && port == Some(80)
                && host != suffix
                && host.ends_with(&format!(".{suffix}"));
        }

        false
    })
}

fn build_app(state: AppState, cors: CorsLayer) -> Router {
    Router::new()
        .route("/health", axum::routing::get(health_check))
        .nest("/oauth", routes::router())
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(cors)
                .layer(DefaultBodyLimit::max(16 * 1024))
                .layer(HandleErrorLayer::new(|err: BoxError| async move {
                    if let Some(service_err) = err.downcast_ref::<ServiceError>() {
                        if service_err.to_string().contains("full") {
                            return (
                                StatusCode::TOO_MANY_REQUESTS,
                                "Too many requests".to_string(),
                            );
                        }
                    }
                    tracing::error!("Unhandled middleware error: {}", err);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal server error".to_string(),
                    )
                }))
                .layer(BufferLayer::new(1024))
                .layer(RateLimitLayer::new(
                    state.config.rate_limit_requests.into(),
                    std::time::Duration::from_secs(state.config.rate_limit_window_secs),
                )),
        )
        .with_state(state)
}

async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "{\"status\":\"healthy\"}")
}
