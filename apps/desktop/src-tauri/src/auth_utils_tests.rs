use super::extract_user_id;
use infra::services::auth::create_jwt;
use uuid::Uuid;

#[test]
fn test_extract_user_id_valid_token() {
    let user_id = Uuid::new_v4();
    let secret = "test_secret";
    let issuer = "test_issuer";
    let audience = "test_audience";

    let token = create_jwt(user_id, secret, 1, issuer, audience).unwrap();

    // Test raw token
    let extracted = extract_user_id(&token, secret, issuer, audience);
    assert_eq!(extracted.unwrap(), user_id);

    // Test Bearer prefix
    let bearer_token = format!("Bearer {token}");
    let extracted = extract_user_id(&bearer_token, secret, issuer, audience);
    assert_eq!(extracted.unwrap(), user_id);

    // Test lowercase bearer prefix
    let lower_bearer = format!("bearer {token}");
    let extracted = extract_user_id(&lower_bearer, secret, issuer, audience);
    assert_eq!(extracted.unwrap(), user_id);

    // Test Bearer prefix with multiple spaces
    let multi_space_bearer = format!("Bearer    {token}");
    let extracted = extract_user_id(&multi_space_bearer, secret, issuer, audience);
    assert_eq!(extracted.unwrap(), user_id);

    // Test Bearer prefix with leading/trailing spaces
    let leading_space_bearer = format!("   Bearer {token}   ");
    let extracted = extract_user_id(&leading_space_bearer, secret, issuer, audience);
    assert_eq!(extracted.unwrap(), user_id);
}

#[test]
fn test_extract_user_id_invalid_tokens() {
    let secret = "test_secret";
    let issuer = "test_issuer";
    let audience = "test_audience";

    assert!(extract_user_id("", secret, issuer, audience).is_err());
    assert!(extract_user_id("   ", secret, issuer, audience).is_err());
    assert!(extract_user_id("Bearer", secret, issuer, audience).is_err());
    assert!(extract_user_id("Bearer ", secret, issuer, audience).is_err());
    assert!(extract_user_id("Bearer token extra", secret, issuer, audience).is_err());
    assert!(extract_user_id("invalid_token", secret, issuer, audience).is_err());
}

#[test]
fn test_extract_user_id_expired_or_wrong_claims() {
    let user_id = Uuid::new_v4();
    let secret = "test_secret";
    let issuer = "test_issuer";
    let audience = "test_audience";

    // Wrong secret
    let token = create_jwt(user_id, "wrong_secret", 1, issuer, audience).unwrap();
    assert!(extract_user_id(&token, secret, issuer, audience).is_err());

    // Wrong issuer
    let token = create_jwt(user_id, secret, 1, "wrong_issuer", audience).unwrap();
    assert!(extract_user_id(&token, secret, issuer, audience).is_err());

    // Wrong audience
    let token = create_jwt(user_id, secret, 1, issuer, "wrong_audience").unwrap();
    assert!(extract_user_id(&token, secret, issuer, audience).is_err());
}
