//! A password change cuts off every session token issued before it, the stateless
//! access JWTs of password and app-password sessions included: an old access token
//! can't mint an app password (or do anything else) after the change, and an old
//! refresh token can't be refreshed. Tokens issued after the change work.

use rocket::http::{ContentType, Header, Status};
use rocket::local::asynchronous::{Client, LocalResponse};
use rocket::serde::json::json;

mod common;

const TEST_DID: &str = "did:plc:khvyd3oiw46vif5gm7hijslk";

async fn body(response: LocalResponse<'_>) -> (Status, serde_json::Value) {
    let status = response.status();
    let body = response
        .into_json()
        .await
        .unwrap_or(serde_json::Value::Null);
    (status, body)
}

/// createSession: (access, refresh).
async fn sign_in(client: &Client, identifier: &str, password: &str) -> (String, String) {
    let response = client
        .post("/xrpc/com.atproto.server.createSession")
        .header(ContentType::JSON)
        .body(json!({ "identifier": identifier, "password": password }).to_string())
        .dispatch()
        .await;
    let (status, body) = body(response).await;
    assert_eq!(status, Status::Ok, "{body}");
    (
        body["accessJwt"].as_str().unwrap().to_string(),
        body["refreshJwt"].as_str().unwrap().to_string(),
    )
}

async fn create_app_password(
    client: &Client,
    access: &str,
    name: &str,
) -> (Status, serde_json::Value) {
    let response = client
        .post("/xrpc/com.atproto.server.createAppPassword")
        .header(ContentType::JSON)
        .header(Header::new("Authorization", format!("Bearer {access}")))
        .body(json!({ "name": name }).to_string())
        .dispatch()
        .await;
    body(response).await
}

async fn refresh(client: &Client, refresh: &str) -> (Status, serde_json::Value) {
    let response = client
        .post("/xrpc/com.atproto.server.refreshSession")
        .header(Header::new("Authorization", format!("Bearer {refresh}")))
        .dispatch()
        .await;
    body(response).await
}

async fn authenticated(client: &Client, access: &str) -> Status {
    client
        .get("/xrpc/com.atproto.identity.getRecommendedDidCredentials")
        .header(Header::new("Authorization", format!("Bearer {access}")))
        .dispatch()
        .await
        .status()
}

async fn set_password(client: &Client, password: &str) {
    let response = client
        .post("/xrpc/com.atproto.admin.updateAccountPassword")
        .header(ContentType::JSON)
        .header(Header::new("Authorization", common::get_admin_token()))
        .body(json!({ "did": TEST_DID, "password": password }).to_string())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
}

/// The #279 review's case: after "turn off other apps" (a password change), a
/// password session's access token, still unexpired, tries to mint an app password.
#[tokio::test]
async fn a_password_change_cuts_off_access_tokens_issued_before_it() {
    let (_dir, client) = common::get_client().await;
    let (identifier, password) = common::create_account(&client).await;
    let (access, refresh_jwt) = sign_in(&client, &identifier, &password).await;
    assert_eq!(authenticated(&client, &access).await, Status::Ok);

    set_password(&client, "a-new-password-nobody-knows").await;

    // The old access token is refused everywhere, including createAppPassword.
    let (status, body) = create_app_password(&client, &access, "helixide").await;
    assert_eq!(status, Status::BadRequest, "{body}");
    assert_eq!(body["error"], "ExpiredToken", "{body}");
    assert_eq!(authenticated(&client, &access).await, Status::BadRequest);
    // So is the old refresh token.
    let (status, body) = refresh(&client, &refresh_jwt).await;
    assert_eq!(status, Status::BadRequest, "{body}");
    assert_eq!(body["error"], "ExpiredToken", "{body}");

    // A session opened after the change (JWT `iat` is in whole seconds, and the second
    // of the change is refused too) works, and can make the app password.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (access, refresh_jwt) = sign_in(&client, &identifier, "a-new-password-nobody-knows").await;
    assert_eq!(authenticated(&client, &access).await, Status::Ok);
    let (status, body) = create_app_password(&client, &access, "helixide").await;
    assert_eq!(status, Status::Ok, "{body}");
    let (status, body) = refresh(&client, &refresh_jwt).await;
    assert_eq!(status, Status::Ok, "{body}");
}

/// An app password's session is a password-change casualty too: its access token
/// stops at once, not when it expires.
#[tokio::test]
async fn a_password_change_cuts_off_app_password_sessions() {
    let (_dir, client) = common::get_client().await;
    let (identifier, password) = common::create_account(&client).await;
    let (access, _) = sign_in(&client, &identifier, &password).await;
    let (status, app) = create_app_password(&client, &access, "some-client").await;
    assert_eq!(status, Status::Ok, "{app}");
    let (app_access, _) = sign_in(&client, &identifier, app["password"].as_str().unwrap()).await;
    assert_eq!(authenticated(&client, &app_access).await, Status::Ok);

    set_password(&client, "another-new-password").await;

    assert_eq!(
        authenticated(&client, &app_access).await,
        Status::BadRequest
    );
}
