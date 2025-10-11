use axum::{routing::get, Router};
use oauth2::basic::BasicClient;
use rusqlite::Connection;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use url::Url;

// 声明即将创建的模块
mod auth;
mod db;
mod html;
mod proxy;

// AppState 将在所有 handler 之间共享
#[derive(Clone)]
pub struct AppState {
    db_pool: Arc<tokio::sync::Mutex<Connection>>,
    oauth_client: Arc<BasicClient>,
}

#[tokio::main]
async fn main() {
    // 加载 .env 文件中的环境变量
    dotenvy::dotenv().expect("Failed to load .env file");

    // 初始化日志记录器
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // 从 APP_BASE_URL 解析主机和端口
    let app_base_url_str = env::var("APP_BASE_URL").expect("Missing APP_BASE_URL from .env");
    let app_url = Url::parse(&app_base_url_str).expect("Invalid APP_BASE_URL");
    let host = env::var("APP_LISTEN").unwrap_or("127.0.0.1".to_string());
    let port = app_url.port().unwrap_or(3000);

    // 初始化数据库连接
    let db_pool = db::create_db_pool();

    // 初始化 OAuth 客户端
    let oauth_client = auth::create_oauth_client();

    // 创建共享状态
    let state = AppState {
        db_pool,
        oauth_client: Arc::new(oauth_client),
    };

    // 定义路由
    let app = Router::new()
        .route("/", get(html::root_handler))
        .route("/login", get(auth::login_handler))
        .route("/oauth/callback", get(auth::oauth_callback_handler))
        .route(
            "/logout",
            get(html::logout_form_handler).post(auth::logout_handler),
        )
        .route(
            "/v1beta/models/*path",
            axum::routing::post(proxy::gemini_proxy_handler),
        )
        .with_state(state);

    // 启动服务器
    let addr_str = format!("{}:{}", host, port);
    let addr: SocketAddr = addr_str.parse().expect("Invalid address format");

    log::info!("Gemini Proxy Server listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
