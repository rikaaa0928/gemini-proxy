
use axum::response::{Html, IntoResponse};

pub async fn root_handler() -> impl IntoResponse {
    Html(
        "<!DOCTYPE html>
        <html>
        <head><title>Gemini Proxy</title></head>
        <body>
            <h1>Welcome to Gemini Proxy Service</h1>
            <p>This service acts as a bridge between the standard Gemini API and the internal Gemini CLI API.</p>
            <ul>
                <li><a href=\"/login\">Login with Google</a> to get a static token.</li>
                <li><a href=\"/logout\">Logout</a> to invalidate your static token.</li>
            </ul>
        </body>
        </html>",
    )
}

pub fn token_display_page(static_token: &str) -> String {
    format!(
        "<!DOCTYPE html>
        <html>
        <head><title>Your Token</title></head>
        <body>
            <h1>Authentication Successful!</h1>
            <p>Your static token is:</p>
            <pre><code>{}</code></pre>
            <p>Please save this token. You will need it to make API calls.</p>
            <p>Example usage:</p>
            <pre>
curl -X POST http://127.0.0.1:3000/v1beta/models/gemini-2.5-flash-lite/streamGenerateContent \\
-H \"Content-Type: application/json\" \\
-H \"Authorization: Bearer {} \" \\
-d '{{
  \"contents\": [
    {{ \"role\": \"user\", \"parts\": [{{ \"text\": \"Hello\" }}] }}
  ]
}}'
            </pre>
            <a href=\"/\">Back to Home</a>
        </body>
        </html>",
        static_token, static_token
    )
}

pub async fn logout_form_handler() -> impl IntoResponse {
    Html(
        "<!DOCTYPE html>
        <html>
        <head><title>Logout</title></head>
        <body>
            <h1>Logout</h1>
            <form action=\"/logout\" method=\"post\">
                <label for=\"static_token\">Enter your static token to logout:</label><br>
                <input type=\"text\" id=\"static_token\" name=\"static_token\" size=\"40\" required><br><br>
                <button type=\"submit\">Logout</button>
            </form>
            <br>
            <a href=\"/\">Back to Home</a>
        </body>
        </html>",
    )
}

pub fn logout_success_page() -> String {
    "<!DOCTYPE html>
    <html>
    <head><title>Logout Successful</title></head>
    <body>
        <h1>Logout Successful</h1>
        <p>Your token has been invalidated.</p>
        <a href=\"/\">Back to Home</a>
    </body>
    </html>".to_string()
}

pub fn logout_fail_page(error: &str) -> String {
    format!(
        "<!DOCTYPE html>
        <html>
        <head><title>Logout Failed</title></head>
        <body>
            <h1>Logout Failed</h1>
            <p>Error: {}</p>
            <a href=\"/logout\">Try again</a> | <a href=\"/\">Back to Home</a>
        </body>
        </html>",
        error
    )
}
