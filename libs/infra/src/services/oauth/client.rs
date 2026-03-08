use oauth2::{HttpRequest, HttpResponse};
use std::sync::LazyLock;
use tracing::error;

/// Custom error type for OAuth HTTP client to handle both reqwest and IO errors
#[derive(Debug, thiserror::Error)]
pub enum OAuthHttpClientError {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub const MAX_OAUTH_HTTP_BODY_BYTES: usize = 1_048_576; // 1 MiB

// Static HTTP client for async_http_client callback (connection pooling)
pub static ASYNC_HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Failed to build reqwest client for OAuth")
});

/// Helper to read response body with a size limit to prevent `DoS`.
///
/// # Errors
///
/// Returns an error if response body size exceeds the limit.
pub async fn read_response_body_with_limit(
    mut response: reqwest::Response,
    limit: usize,
    error_context: &str,
) -> Result<Vec<u8>, String> {
    if response
        .content_length()
        .is_some_and(|len| len > limit as u64)
    {
        return Err(format!("{error_context} response too large"));
    }

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(format!("{error_context} response too large"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Custom async HTTP client for oauth2 crate with timeout and proper configuration.
///
/// # Errors
///
/// Returns an error if the request fails or response body exceeds the limit.
pub async fn async_http_client(request: HttpRequest) -> Result<HttpResponse, OAuthHttpClientError> {
    // Use static client for connection pooling
    let client = &*ASYNC_HTTP_CLIENT;

    let mut request_builder = client.request(request.method().clone(), request.uri().to_string());
    // Only set body for methods that typically have one (POST, PUT, PATCH)
    if *request.method() != oauth2::http::Method::GET && !request.body().is_empty() {
        request_builder = request_builder.body(request.body().clone());
    }

    let mut has_content_type = false;
    let mut has_user_agent = false;
    for (name, value) in request.headers() {
        if name.as_str().eq_ignore_ascii_case("content-length") {
            continue;
        }
        if name.as_str().eq_ignore_ascii_case("content-type") {
            has_content_type = true;
        }
        if name.as_str().eq_ignore_ascii_case("user-agent") {
            has_user_agent = true;
        }
        request_builder = request_builder.header(name, value);
    }

    if !has_user_agent {
        request_builder = request_builder.header(
            reqwest::header::USER_AGENT,
            reqwest::header::HeaderValue::from_static("Aroeira-Desktop"),
        );
    }

    if !has_content_type
        && *request.method() != oauth2::http::Method::GET
        && !request.body().is_empty()
    {
        request_builder = request_builder.header(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
    }

    let response = request_builder.send().await?;

    let status = response.status();
    let headers = response.headers().clone();

    let body = read_response_body_with_limit(response, MAX_OAUTH_HTTP_BODY_BYTES, "OAuth HTTP")
        .await
        .map_err(|e| {
            if e.contains("too large") {
                error!("OAuth HTTP response body exceeded maximum allowed size");
                OAuthHttpClientError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            } else {
                OAuthHttpClientError::Io(std::io::Error::other(e))
            }
        })?;

    let mut resp = HttpResponse::new(body);
    *resp.status_mut() = status;
    *resp.headers_mut() = headers;
    Ok(resp)
}
