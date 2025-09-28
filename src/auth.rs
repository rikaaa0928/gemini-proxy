use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect},
    Form,
};
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use rand::{distributions::Alphanumeric, Rng};
use reqwest::Client;
use serde::Deserialize;
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{db, html, AppState};

/// 创建 OAuth2 客户端 (适配 oauth2 v4.4.0)
pub fn create_oauth_client() -> BasicClient {
    let google_client_id = ClientId::new(
        env::var("GOOGLE_CLIENT_ID").expect("Missing GOOGLE_CLIENT_ID from .env"),
    );
    let google_client_secret = ClientSecret::new(
        env::var("GOOGLE_CLIENT_SECRET").expect("Missing GOOGLE_CLIENT_SECRET from .env"),
    );
    let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
        .expect("Invalid authorization endpoint URL");
    let token_url = TokenUrl::new("https://oauth2.googleapis.com/token".to_string())
        .expect("Invalid token endpoint URL");

    let app_base_url = env::var("APP_BASE_URL").expect("Missing APP_BASE_URL from .env");
    let redirect_url = RedirectUrl::new(format!("{}/oauth/callback", app_base_url))
        .expect("Invalid redirect URL");

    BasicClient::new(
        google_client_id,
        Some(google_client_secret),
        auth_url,
        Some(token_url),
    )
    .set_redirect_uri(redirect_url)
}

/// 处理 /login 路由，重定向到 Google 登录页面
pub async fn login_handler(State(state): State<AppState>) -> impl IntoResponse {
    let (authorize_url, _csrf_state) = state
        .oauth_client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new(
            "https://www.googleapis.com/auth/cloud-platform".to_string(),
        ))
        .add_scope(Scope::new(
            "https://www.googleapis.com/auth/userinfo.email".to_string(),
        ))
        .add_extra_param("access_type", "offline") // 请求 refresh_token
        .add_extra_param("prompt", "consent") // 确保每次都显示同意屏幕以获取 refresh_token
        .url();

    Redirect::to(authorize_url.as_str())
}

#[derive(Deserialize)]
pub struct AuthRequest {
    code: String,
    #[allow(dead_code)]
    state: String,
}

#[derive(Deserialize, Debug)]
struct UserInfo {
    email: String,
}

/// 处理 /oauth/callback 路由
pub async fn oauth_callback_handler(
    Query(query): Query<AuthRequest>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // 1. 交换授权码以获取 token
    let token_result = state
        .oauth_client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(async_http_client)
        .await;

    let token = match token_result {
        Ok(token) => token,
        Err(e) => return Html(format!("<h1>Error</h1><p>OAuth failed: {}</p>", e)),
    };

    // 2. 使用 access_token 获取用户信息
    let client = Client::new();
    let user_info_response = client
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(token.access_token().secret())
        .send()
        .await;

    let user_info: UserInfo = match user_info_response {
        Ok(resp) => match resp.json().await {
            Ok(info) => info,
            Err(_) => return Html("<h1>Error</h1><p>Failed to parse user info.</p>".to_string()),
        },
        Err(_) => return Html("<h1>Error</h1><p>Failed to fetch user info.</p>".to_string()),
    };

    // 3. 准备 TokenRecord
    let static_token: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let expires_in = token.expires_in().map_or(3600, |d| d.as_secs());
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + expires_in;

    // 如果 Google 没有返回新的 refresh_token，我们应该尝试保留旧的（如果存在）。
    // 但在这个流程中，我们总是用新的覆盖，所以每次登录都需要用户同意以获取新的 refresh_token。
    let refresh_token = token
        .refresh_token()
        .map_or_else(|| "".to_string(), |rt| rt.secret().clone());

    let record = db::TokenRecord {
        user_email: user_info.email,
        static_token: static_token.clone(),
        access_token: token.access_token().secret().clone(),
        refresh_token,
        expires_at,
        project_id: None, // Project ID 将在第一次 API 调用时被发现
    };

    // 4. 保存到数据库
    let conn = state.db_pool.lock().await;
    if let Err(e) = db::save_token(&conn, &record) {
        return Html(format!("<h1>Error</h1><p>Failed to save token: {}</p>", e));
    }

    Html(html::token_display_page(&static_token))
}

#[derive(Deserialize)]
pub struct LogoutPayload {
    static_token: String,
}

/// 处理 /logout 的 POST 请求
pub async fn logout_handler(
    State(state): State<AppState>,
    Form(payload): Form<LogoutPayload>,
) -> impl IntoResponse {
    let conn = state.db_pool.lock().await;
    match db::delete_token(&conn, &payload.static_token) {
        Ok(rows_deleted) if rows_deleted > 0 => Html(html::logout_success_page()),
        Ok(_) => Html(html::logout_fail_page("Token not found.")),
        Err(e) => Html(html::logout_fail_page(&e.to_string())),
    }
}
