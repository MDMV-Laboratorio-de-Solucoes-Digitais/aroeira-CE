#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::implicit_return,
    clippy::shadow_unrelated,
    clippy::tests_outside_test_module,
    clippy::std_instead_of_alloc
)]

use axum::http::{Request, StatusCode};
use std::sync::Arc;
use tower::ServiceExt;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::SmartIpKeyExtractor;
use tower_governor::GovernorLayer;

#[tokio::test]
async fn test_per_ip_rate_limiting() {
    let governor_config = GovernorConfigBuilder::default()
        .per_second(1)
        .burst_size(5)
        .key_extractor(SmartIpKeyExtractor)
        .finish()
        .expect("governor config requires burst_size > 0");

    let app = axum::Router::new()
        .route("/test", axum::routing::get(|| async { return "ok" }))
        .layer(GovernorLayer::new(Arc::new(governor_config)));

    for i in 0..5 {
        let req = Request::builder()
            .uri("/test")
            .header("X-Forwarded-For", "10.0.0.1")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Request {} from IP 10.0.0.1 should succeed",
            i + 1
        );
    }

    let req = Request::builder()
        .uri("/test")
        .header("X-Forwarded-For", "10.0.0.1")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "6th request from IP 10.0.0.1 should be rate limited"
    );

    let req = Request::builder()
        .uri("/test")
        .header("X-Forwarded-For", "10.0.0.2")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Request from IP 10.0.0.2 should succeed (different quota)"
    );
}

#[tokio::test]
async fn test_x_real_ip_header() {
    let governor_config = GovernorConfigBuilder::default()
        .per_second(1)
        .burst_size(3)
        .key_extractor(SmartIpKeyExtractor)
        .finish()
        .expect("governor config requires burst_size > 0");

    let app = axum::Router::new()
        .route("/test", axum::routing::get(|| async { return "ok" }))
        .layer(GovernorLayer::new(Arc::new(governor_config)));

    for i in 0..3 {
        let req = Request::builder()
            .uri("/test")
            .header("X-Real-IP", "192.168.1.1")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Request {} from IP via X-Real-IP should succeed",
            i + 1
        );
    }

    let req = Request::builder()
        .uri("/test")
        .header("X-Real-IP", "192.168.1.1")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "4th request should be rate limited"
    );

    let req = Request::builder()
        .uri("/test")
        .header("X-Real-IP", "192.168.1.2")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Request from different IP should succeed"
    );
}
