use log::{debug, error, info, warn};
use axum::{
    body::Body,
    extract::{Path, State},
    response::{IntoResponse, Response},
    Json,
};
use axum_extra::headers::{authorization::Bearer, Authorization};
use axum_extra::TypedHeader;
use bytes::Bytes;
use chrono::Utc;
use futures_util::stream::{self, Stream, StreamExt};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;


use crate::{
    db::{self, TokenRecord},
    AppState,
};

const CODE_ASSIST_ENDPOINT: &str = "https://cloudcode-pa.googleapis.com";
const CODE_ASSIST_API_VERSION: &str = "v1internal";
const OAUTH_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

// --- Structs for Standard Gemini API (Client-facing) ---
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct StandardGeminiRequest {
    pub contents: Vec<Value>,
    pub generation_config: Option<Value>,
    // ... other standard fields can be added here
}

// --- Structs for Internal Code Assist API (Backend-facing) ---
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct InternalRequestWrapper<'a> {
    model: &'a str,
    project: &'a str, // Project ID is needed for the internal API
    request: &'a StandardGeminiRequest,
}

// --- Structs for OAuth Token Refresh ---
#[derive(Deserialize)]
struct RefreshTokenResponse {
    access_token: String,
    expires_in: u64,
}

// --- Structs for Project ID Discovery ---
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LoadCodeAssistRequest<'a> {
    cloudaicompanion_project: &'a str,
    metadata: ClientMetadata<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientMetadata<'a> {
    ide_type: &'a str,
    platform: &'a str,
    plugin_type: &'a str,
    duet_project: &'a str,
}

#[derive(Deserialize)]
struct LoadCodeAssistResponse {
    #[serde(rename = "cloudaicompanionProject")]
    cloudaicompanion_project: Option<String>,
}

async fn call_code_assist_api<T: Serialize, U: for<'de> Deserialize<'de>>(
    client: &Client,
    access_token: &str,
    method: &str,
    body: &T,
) -> Result<U, Response> {
    let url = format!("{}/{}:{}", CODE_ASSIST_ENDPOINT, CODE_ASSIST_API_VERSION, method);
    let response = client
        .post(&url)
        .bearer_auth(access_token)
        .json(body)
        .send()
        .await
        .map_err(|e| {
            Response::builder()
                .status(500)
                .body(Body::from(format!("Backend request failed: {}", e)))
                .unwrap()
        })?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        return Err(Response::builder()
            .status(status)
            .body(Body::from(format!(
                "Code Assist API error: {} - {}",
                status, text
            )))
            .unwrap());
    }

    response.json::<U>().await.map_err(|e| {
        Response::builder()
            .status(500)
            .body(Body::from(format!("Failed to parse response: {}", e)))
            .unwrap()
    })
}


async fn ensure_valid_token(
    state: &AppState,
    static_token: &str,
) -> Result<TokenRecord, Response> {
    let mut token_record = {
        let conn = state.db_pool.lock().await;
        db::get_token(&conn, static_token).map_err(|_| {
            Response::builder()
                .status(500)
                .body(Body::from("Database error."))
                .unwrap()
        })?
    }
    .ok_or_else(|| {
        Response::builder()
            .status(401)
            .body(Body::from("Unauthorized: Invalid static token."))
            .unwrap()
    })?;

    let now = Utc::now().timestamp() as u64;
    if now < token_record.expires_at {
        return Ok(token_record);
    }

    // Token expired, try to refresh
    let client_id = env::var("GOOGLE_CLIENT_ID").expect("GOOGLE_CLIENT_ID not set");
    let client_secret = env::var("GOOGLE_CLIENT_SECRET").expect("GOOGLE_CLIENT_SECRET not set");

    let client = Client::new();
    let params = [
        ("client_id", &client_id),
        ("client_secret", &client_secret),
        ("refresh_token", &token_record.refresh_token),
        ("grant_type", &"refresh_token".to_string()),
    ];

    let response = client
        .post(OAUTH_TOKEN_URI)
        .form(&params)
        .send()
        .await
        .map_err(|_| {
            Response::builder()
                .status(500)
                .body(Body::from("Failed to send refresh token request."))
                .unwrap()
        })?;

    if !response.status().is_success() {
        return Err(Response::builder()
            .status(401)
            .body(Body::from("Failed to refresh OAuth token."))
            .unwrap());
    }

    let refresh_response: RefreshTokenResponse = response.json().await.map_err(|_| {
        Response::builder()
            .status(500)
            .body(Body::from("Failed to parse refresh token response."))
            .unwrap()
    })?;

    token_record.access_token = refresh_response.access_token;
    token_record.expires_at = now + refresh_response.expires_in - 60; // 60s buffer

    {
        let conn = state.db_pool.lock().await;
        db::save_token(&conn, &token_record).map_err(|_| {
            Response::builder()
                .status(500)
                .body(Body::from("Failed to save refreshed token."))
                .unwrap()
        })?;
    }

    Ok(token_record)
}

async fn discover_project_id(
    state: &AppState,
    token_record: &mut TokenRecord,
) -> Result<String, Response> {
    if let Some(project_id) = &token_record.project_id {
        return Ok(project_id.clone());
    }

    let client = Client::new();
    let initial_project_id = "default";

    let request_body = LoadCodeAssistRequest {
        cloudaicompanion_project: initial_project_id,
        metadata: ClientMetadata {
            ide_type: "IDE_UNSPECIFIED",
            platform: "PLATFORM_UNSPECIFIED",
            plugin_type: "GEMINI",
            duet_project: initial_project_id,
        },
    };

    let response: LoadCodeAssistResponse = call_code_assist_api(
        &client,
        &token_record.access_token,
        "loadCodeAssist",
        &request_body,
    )
    .await?;

    let discovered_project_id = response
        .cloudaicompanion_project
        .unwrap_or_else(|| initial_project_id.to_string());

    token_record.project_id = Some(discovered_project_id.clone());

    {
        let conn = state.db_pool.lock().await;
        db::save_token(&conn, token_record).map_err(|_| {
            Response::builder()
                .status(500)
                .body(Body::from("Failed to save project ID."))
                .unwrap()
        })?;
    }

    Ok(discovered_project_id)
}


pub async fn gemini_proxy_handler(
    State(state): State<AppState>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Path(path): Path<String>,
    Json(payload): Json<StandardGeminiRequest>,
) -> impl IntoResponse {
    // Parse path: expected format "model:streamGenerateContent"
    let parts: Vec<&str> = path.split(':').collect();
    if parts.len() != 2 || parts[1] != "streamGenerateContent" {
        warn!("Invalid path format received: {}", path);
        return Response::builder()
            .status(400)
            .body(Body::from("Invalid path format. Expected /v1beta/models/{model}:streamGenerateContent"))
            .unwrap();
    }
    let model = parts[0].to_string();
    info!("Proxying request for model: {}", model);
    debug!("Request payload: {:?}", payload);

    // 1. Get and refresh token
    let mut token_record = match ensure_valid_token(&state, auth.token()).await {
        Ok(record) => {
            info!("Successfully validated and refreshed token for static token ending with: ...{}", &auth.token().chars().skip(auth.token().len() - 4).collect::<String>());
            record
        }
        Err(response) => {
            error!("Token validation failed for static token ending with: ...{}", &auth.token().chars().skip(auth.token().len() - 4).collect::<String>());
            return response;
        }
    };

    // 2. Discover project ID if needed
    let project_id = match discover_project_id(&state, &mut token_record).await {
        Ok(id) => {
            info!("Discovered project ID: {}", id);
            id
        }
        Err(response) => {
            error!("Failed to discover project ID.");
            return response;
        }
    };

    // 3. Prepare and send request to backend
    let internal_request = InternalRequestWrapper {
        model: &model,
        project: &project_id,
        request: &payload,
    };

    let client = Client::new();
    let backend_url = format!(
        "{}/{}:streamGenerateContent?alt=sse",
        CODE_ASSIST_ENDPOINT, CODE_ASSIST_API_VERSION
    );
    info!("Sending request to backend URL: {}", &backend_url);
    debug!("Backend request body: {:?}", &internal_request);
    let backend_response = match client
        .post(&backend_url)
        .bearer_auth(&token_record.access_token)
        .json(&internal_request)
        .send()
        .await
    {
        Ok(res) => res,
        Err(e) => {
            error!("Backend request failed: {}", e);
            return Response::builder()
                .status(500)
                .body(Body::from(format!("Backend request failed: {}", e)))
                .unwrap();
        }
    };

    if !backend_response.status().is_success() {
        let status = backend_response.status();
        let text = backend_response.text().await.unwrap_or_default();
        error!("Backend API error: {} - {}", status, text);
        return Response::builder()
            .status(status)
            .body(Body::from(format!("Backend API error: {} - {}", status, text)))
            .unwrap();
    }
    info!("Successfully received response from backend.");

    // 4. Transform and stream response
    let stream = backend_response.bytes_stream();
    let transformed_stream = transform_stream(stream);

    Response::builder()
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-cache")
        .header("Connection", "keep-alive")
        .body(Body::from_stream(transformed_stream))
        .unwrap()
}

// 使用异步生成器块来处理流转换，更健壮
fn transform_stream(
    mut stream: impl Stream<Item = Result<Bytes, reqwest::Error>> + Unpin,
) -> impl Stream<Item = Result<Bytes, reqwest::Error>> {
    let mut buffer = String::new();

    stream::poll_fn(move |cx| {
        loop {
            if let Some(end_index) = buffer.find("\r\n") {
                let message_block = buffer.drain(..end_index + 2).collect::<String>();
                let mut transformed_lines = Vec::new();

                for line in message_block.lines() {
                    if line.starts_with("data:") {
                        let json_str = &line[5..].trim();
                        if let Ok(internal_sse) = serde_json::from_str::<Value>(json_str) {
                            if let Some(response) = internal_sse.get("response") {
                                if let Some(candidates) = response.get("candidates") {
                                    let standard_sse = serde_json::json!({ "candidates": candidates });
                                    if let Ok(formatted_sse) = serde_json::to_string(&standard_sse) {
                                        transformed_lines.push(format!("data: {}", formatted_sse));
                                    }
                                }
                            }
                        }
                    } else if !line.is_empty() {
                        // 保留其他行，例如 'id:' 或 'event:'
                        transformed_lines.push(line.to_string());
                    }
                }

                // 将处理过的行用 \r\n 连接，并以 \r\n\r\n 结尾，以符合 SSE 规范
                let final_message = format!("{}\r\n\r\n", transformed_lines.join("\r\n"));
                return std::task::Poll::Ready(Some(Ok(Bytes::from(final_message))));
            }

            // 如果缓冲区没有完整消息，从上游拉取更多数据
            match stream.poll_next_unpin(cx) {
                std::task::Poll::Ready(Some(Ok(chunk))) => {
                    if let Ok(s) = std::str::from_utf8(&chunk) {
                        // 将换行符规范化为 \n，以便可靠地查找消息边界
                        buffer.push_str(&s);
                        // 继续循环，检查新数据是否构成了完整的消息
                        continue;
                    }
                }
                std::task::Poll::Ready(Some(Err(e))) => return std::task::Poll::Ready(Some(Err(e))),
                std::task::Poll::Ready(None) => {
                    // 上游流结束
                    if !buffer.is_empty() {
                        // 处理缓冲区中剩余的任何数据
                        let rest = buffer.drain(..).collect::<String>();
                        return std::task::Poll::Ready(Some(Ok(Bytes::from(rest))));
                    }
                    return std::task::Poll::Ready(None);
                }
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
    })
}
