use std::time::SystemTimeError;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use oauth2::{
    basic::{BasicClient, BasicErrorResponseType},
    reqwest::{async_http_client, Error as ReqwestError},
    url::{ParseError, Url},
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, RequestTokenError, Scope, StandardErrorResponse, TokenResponse,
    TokenUrl,
};
use rand_core::{OsRng, RngCore};
use thiserror::Error;
use totp_rs::{Rfc6238, Rfc6238Error, Secret, SecretParseError, TotpUrlError, TOTP};

/// The general error type for this crate
#[derive(Error, Debug)]
pub enum AuthError<B>
where
    B: Backend + ?Sized,
{
    #[error("invalid password")]
    PasswordInvalid,
    #[error("password stored incorrectly")]
    PasswordParseError,
    #[error(transparent)]
    BackendError(B::Error),
    #[error(transparent)]
    TotpLibError(TotpError),
    #[error("invalid TOTP code")]
    TotpCodeInvalid,
    #[error(transparent)]
    SystemTimeError(SystemTimeError),
    #[error("token expired")]
    TokenExpired,
    #[error("token revoked")]
    TokenRevoked,
    #[error("incorrect token type")]
    IncorrectTokenType,
    #[error("qr code error: {0}")]
    QrCodeError(String),
    #[error(transparent)]
    UrlParseError(ParseError),
    #[error(transparent)]
    OAuthTokenError(
        RequestTokenError<
            ReqwestError<reqwest::Error>,
            StandardErrorResponse<BasicErrorResponseType>,
        >,
    ),
    #[error("invalid oauth state param")]
    InvalidOAuthState,
}

impl<B> From<TotpError> for AuthError<B>
where
    B: Backend + ?Sized,
{
    fn from(value: TotpError) -> Self {
        Self::TotpLibError(value)
    }
}

impl<B> From<SystemTimeError> for AuthError<B>
where
    B: Backend + ?Sized,
{
    fn from(value: SystemTimeError) -> Self {
        Self::SystemTimeError(value)
    }
}

impl<B>
    From<
        RequestTokenError<
            ReqwestError<reqwest::Error>,
            StandardErrorResponse<BasicErrorResponseType>,
        >,
    > for AuthError<B>
where
    B: Backend + ?Sized,
{
    fn from(
        value: RequestTokenError<
            ReqwestError<reqwest::Error>,
            StandardErrorResponse<BasicErrorResponseType>,
        >,
    ) -> Self {
        Self::OAuthTokenError(value)
    }
}

/// Errors associated with using TOTP (two factor authentication)
#[derive(Error, Debug)]
pub enum TotpError {
    #[error(transparent)]
    RfcError(Rfc6238Error),
    #[error("invalid base32 input")]
    SecretParseError,
    #[error(transparent)]
    TotpUrlError(TotpUrlError),
}

impl From<Rfc6238Error> for TotpError {
    fn from(value: Rfc6238Error) -> Self {
        Self::RfcError(value)
    }
}

impl<B> From<Rfc6238Error> for AuthError<B>
where
    B: Backend + ?Sized,
{
    fn from(value: Rfc6238Error) -> Self {
        Self::TotpLibError(value.into())
    }
}

impl From<SecretParseError> for TotpError {
    fn from(_: SecretParseError) -> Self {
        Self::SecretParseError
    }
}

impl<B> From<SecretParseError> for AuthError<B>
where
    B: Backend + ?Sized,
{
    fn from(value: SecretParseError) -> Self {
        Self::TotpLibError(value.into())
    }
}

impl From<TotpUrlError> for TotpError {
    fn from(value: TotpUrlError) -> Self {
        Self::TotpUrlError(value)
    }
}

impl<B> From<TotpUrlError> for AuthError<B>
where
    B: Backend + ?Sized,
{
    fn from(value: TotpUrlError) -> Self {
        Self::TotpLibError(value.into())
    }
}

impl<B> From<ParseError> for AuthError<B>
where
    B: Backend + ?Sized,
{
    fn from(value: ParseError) -> Self {
        Self::UrlParseError(value)
    }
}

/// The type of token issued
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TokenType {
    /// A token that can be used to authenticate the user
    Auth,
    /// A token that can be used to complete the login process alongside a 2FA code
    TwoFactorRequired,
    /// A single token that can be used to complete the login process and get an auth token
    Magic,
}

/// A general type for user IDs, allows the backend to use either a numeric or text ID as the
/// implementer sees fit
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Id {
    Numeric(u64),
    Text(String),
}

/// Represents a full token
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Token {
    /// The ID of the user this token is for
    pub user_id: Id,
    /// The token itself
    pub token: String,
    /// The time this token was issued
    pub issued: DateTime<Utc>,
    /// The time this token expires
    pub expiry: DateTime<Utc>,
    /// The type of token
    pub r#type: TokenType,
    /// Whether this token has been revoked
    pub revoked: bool,
}

impl Token {
    /// Create a new token
    ///
    /// # Arguments
    /// * `user_id` - The ID of the user this token is for
    /// * `valid_for` - How long this token is valid for
    /// * `type` - The type of token
    pub fn new(
        user_id: impl Into<Id>,
        valid_for: impl Into<Duration>,
        r#type: impl Into<TokenType>,
    ) -> Self {
        let token = format!("{:x}", OsRng.next_u64());
        let issued = Utc::now();
        let expiry = issued + valid_for.into();
        Self {
            user_id: user_id.into(),
            token,
            issued,
            expiry,
            r#type: r#type.into(),
            revoked: false,
        }
    }

    /// Create a new token from a backend and context, taking the user ID from the context and the
    /// token expiry from the backend
    ///
    /// # Arguments
    /// * `backend` - The backend to use
    /// * `ctx` - The context to use
    /// * `type` - The type of token
    pub fn from_ctx<B>(backend: &B, ctx: &B::Context, r#type: impl Into<TokenType>) -> Self
    where
        B: Backend + ?Sized,
    {
        let r#type = r#type.into();
        Self::new(
            backend.get_user_id(ctx),
            backend.get_token_valid_duration(ctx, &r#type),
            r#type,
        )
    }

    /// Check if this token is valid, returns `Ok(())` if it is valid, otherwise returns an error
    ///
    /// # Errors
    /// * `AuthError::TokenRevoked` - The token has been revoked
    /// * `AuthError::TokenExpired` - The token has expired
    pub fn check_validity<B>(&self) -> Result<(), AuthError<B>>
    where
        B: Backend + ?Sized,
    {
        if self.revoked {
            Err(AuthError::TokenRevoked)
        } else if self.expiry <= Utc::now() {
            Err(AuthError::TokenExpired)
        } else {
            Ok(())
        }
    }
}

/// Represents an OAuth2 session
/// This is used to start the OAuth2 flow
/// The `auth_url` field should be used to redirect the user to the OAuth2 provider
/// The remainder of this session should be stored in the backend and used to complete the
/// authentication when the user is redirected back
#[derive(Debug)]
pub struct OAuthSession {
    client: BasicClient,
    /// The authentication URL to redirect the user to
    pub auth_url: Url,
    csrf_token: CsrfToken,
    pkce_verifier: PkceCodeVerifier,
}

#[derive(Debug)]
pub struct OAuthResult {
    /// The authentication token that was generated
    pub token: Token,
    /// The OAuth2 access token
    pub access_token: String,
    /// The OAuth2 refresh token
    pub refresh_token: Option<String>,
    /// The OAuth2 access token expiry
    pub expires_in: Option<std::time::Duration>,
    /// The OAuth2 scopes that were granted
    pub scopes: Option<Vec<String>>,
}

/// The backend trait, implement this for your backend
#[async_trait]
pub trait Backend {
    /// The context type, this is used to store any backend specific data that is required
    /// Generally, user data such as the email, 2FA token, password hash, etc will be stored in
    /// here and this trait will syncronously ask the implementer for this data with the provided
    /// context when required.
    type Context: Send + Sync;
    /// The error type, this is used to store any backend specific errors that may occur
    type Error: std::error::Error + std::fmt::Display;
    /// The issuer to use for TOTP
    const TOTP_ISSUER: &'static str;

    /// Hash a password
    #[inline]
    fn hash_password(&self, password: &str) -> String {
        password_auth::generate_hash(password.as_bytes())
    }

    /// Verify a password
    #[inline]
    fn verify_password(&self, input: &str, hash: &str) -> Result<(), password_auth::VerifyError> {
        password_auth::verify_password(input, hash)
    }

    /// Login with a password
    /// This will hash the password and verify it against the stored hash
    /// If the password is correct, a token will be generated and returned
    /// If two factor authentication is enabled, a token of type `TwoFactorRequired` will be
    ///
    /// # Arguments
    /// * `ctx` - The context to use
    /// * `input` - The password to verify
    ///
    /// # Errors
    /// * `AuthError::PasswordParseError` - The stored password hash is invalid
    /// * `AuthError::PasswordInvalid` - The password is incorrect
    /// * `AuthError::BackendError` - A backend error occurred while generating the token
    async fn login_with_password(
        &self,
        ctx: &Self::Context,
        input: &str,
    ) -> Result<Token, AuthError<Self>> {
        let password = self.get_password_hash(ctx);
        self.verify_password(input, password).map_err(|e| match e {
            password_auth::VerifyError::Parse(_) => AuthError::PasswordParseError,
            password_auth::VerifyError::PasswordInvalid => AuthError::PasswordInvalid,
        })?;
        let is_two_factor_enabled = self.is_two_factor_enabled(ctx);

        self.generate_token(
            ctx,
            match is_two_factor_enabled {
                true => TokenType::TwoFactorRequired,
                false => TokenType::Auth,
            },
        )
        .await
    }

    /// Get the duration a token of the given type is valid for
    /// This is used to determine the expiry of the token
    /// The default implementation returns 15 minutes for `Magic` tokens, 5 minutes for
    /// `TwoFactorRequired` tokens and the value returned by `get_auth_token_valid_duration` for
    /// `Auth` tokens
    ///
    /// # Arguments
    /// * `ctx` - The context to use
    /// * `type` - The type of token
    #[inline]
    fn get_token_valid_duration(&self, ctx: &Self::Context, r#type: &TokenType) -> Duration {
        match r#type {
            TokenType::Magic => Duration::minutes(15),
            TokenType::TwoFactorRequired => Duration::minutes(5),
            TokenType::Auth => self.get_auth_token_valid_duration(ctx),
        }
    }

    /// Get the password hash for the given context
    ///
    /// # Arguments
    /// * `ctx` - The context to use
    fn get_password_hash<'c>(&self, ctx: &'c Self::Context) -> &'c str;
    /// Get whether two factor authentication is enabled for the given context
    ///
    /// # Arguments
    /// * `ctx` - The context to use
    fn is_two_factor_enabled(&self, ctx: &Self::Context) -> bool;
    /// Get the duration an auth token is valid for
    ///
    /// # Arguments
    /// * `ctx` - The context to use
    fn get_auth_token_valid_duration(&self, ctx: &Self::Context) -> Duration;
    /// Get the user ID for the given context
    ///
    /// # Arguments
    /// * `ctx` - The context to use
    fn get_user_id(&self, ctx: &Self::Context) -> Id;
    /// Save the given token to the backend
    ///
    /// # Arguments
    /// * `ctx` - The context to use
    /// * `token` - The token to save
    async fn save_token(&self, ctx: &Self::Context, token: &Token) -> Result<(), Self::Error>;
    /// Get the token with the given token string
    ///
    /// # Arguments
    /// * `ctx` - The context to use
    /// * `token` - The token string to get
    async fn get_token(&self, ctx: &Self::Context, token: &str) -> Result<Token, Self::Error>;
    /// Revoke the given token
    ///
    /// # Arguments
    /// * `ctx` - The context to use
    /// * `token` - The token to revoke
    async fn revoke_token(&self, ctx: &Self::Context, token: &Token) -> Result<(), Self::Error>;
    /// Store that the given TOTP code has been used
    ///
    /// # Arguments
    /// * `ctx` - The context to use
    /// * `code` - The code to store
    async fn store_totp_code_used(
        &self,
        ctx: &Self::Context,
        code: &str,
    ) -> Result<(), Self::Error>;
    /// Get the TOTP secret for the given context
    ///
    /// # Arguments
    /// * `ctx` - The context to use
    fn get_totp_secret<'c>(&self, ctx: &'c Self::Context) -> &'c str;
    /// Get the TOTP account name for the given context
    ///
    /// # Arguments
    /// * `ctx` - The context to use
    fn get_totp_account_name(&self, ctx: &Self::Context) -> String;
    /// Check if the given TOTP code has been used
    ///
    /// # Arguments
    /// * `ctx` - The context to use
    /// * `code` - The code to check
    async fn has_totp_code_been_used(
        &self,
        ctx: &Self::Context,
        code: &str,
    ) -> Result<bool, Self::Error>;

    /// Get a TOTP instance for the given context and secret
    /// This will return an error if the secret is invalid
    ///
    /// # Arguments
    /// * `ctx` - The context to use
    /// * `secret` - The secret to use
    ///
    /// # Errors
    /// * `AuthError::TotpLibError` - The secret is invalid
    #[inline]
    fn totp(&self, ctx: &Self::Context, secret: &str) -> Result<TOTP, AuthError<Self>> {
        Ok(TOTP::from_rfc6238(Rfc6238::new(
            8,
            Secret::Encoded(secret.to_string()).to_bytes()?,
            Some(Self::TOTP_ISSUER.to_string()),
            self.get_totp_account_name(ctx),
        )?)?)
    }

    /// Get a TOTP instance for the given context
    ///
    /// # Arguments
    /// * `ctx` - The context to use
    ///
    /// # Errors
    /// * `AuthError::TotpLibError` - The secret is invalid
    #[inline]
    fn totp_from_ctx(&self, ctx: &Self::Context) -> Result<TOTP, AuthError<Self>> {
        self.totp(ctx, self.get_totp_secret(ctx))
    }

    /// Use the given TOTP code
    /// This will check the code is valid, has not been used before and store that it has been used
    /// If all of these checks pass, `Ok(true)` will be returned, otherwise `Ok(false)` will be
    ///
    /// # Arguments
    /// * `ctx` - The context to use
    /// * `code` - The code to use
    ///
    /// # Errors
    /// * `AuthError::TotpLibError` - The secret is invalid
    /// * `AuthError::BackendError` - A backend error occurred while checking the code
    async fn use_totp_code(
        &self,
        ctx: &Self::Context,
        code: &str,
    ) -> Result<bool, AuthError<Self>> {
        Ok(self.totp_from_ctx(ctx)?.check_current(code)?
            && !self
                .has_totp_code_been_used(ctx, code)
                .await
                .map_err(AuthError::BackendError)?
            && self
                .store_totp_code_used(ctx, code)
                .await
                .map_err(AuthError::BackendError)
                .map(|()| true)?)
    }

    /// Submit a TOTP code
    /// This will check the code is valid and has not been used before
    /// If all of these checks pass, a authentication token will be generated and returned
    /// If the checks fail, an error will be returned
    /// If the token is generated, the old token will be revoked
    /// This will return an error if the token is not of type `TwoFactorRequired`
    ///
    /// # Arguments
    /// * `ctx` - The context to use
    /// * `token` - The token to submit
    /// * `code` - The code to use
    ///
    /// # Errors
    /// * `AuthError::TotpLibError` - The secret is invalid
    /// * `AuthError::BackendError` - A backend error occurred while checking the code
    /// * `AuthError::TotpCodeInvalid` - The code is invalid
    /// * `AuthError::IncorrectTokenType` - The token is not of type `TwoFactorRequired`
    async fn submit_totp(
        &self,
        ctx: &Self::Context,
        token: &str,
        code: &str,
    ) -> Result<Token, AuthError<Self>> {
        let token = self
            .get_token(ctx, token)
            .await
            .map_err(AuthError::BackendError)?;
        token.check_validity()?;
        if let TokenType::TwoFactorRequired = token.r#type {
            if self.use_totp_code(ctx, code).await? {
                self.revoke_token(ctx, &token)
                    .await
                    .map_err(AuthError::BackendError)?;
                self.generate_token(ctx, TokenType::Auth).await
            } else {
                Err(AuthError::TotpCodeInvalid)
            }
        } else {
            Err(AuthError::IncorrectTokenType)
        }
    }

    /// Get the current TOTP code
    ///
    /// # Arguments
    /// * `ctx` - The context to use
    ///
    /// # Errors
    /// * `AuthError::TotpLibError` - The secret is invalid
    #[inline]
    fn get_current_totp_code(&self, ctx: &Self::Context) -> Result<String, AuthError<Self>> {
        Ok(self.totp_from_ctx(ctx)?.generate_current()?)
    }

    /// Generate a Base32 TOTP secret
    #[inline]
    fn generate_totp_secret_base_32(&self) -> String {
        Secret::generate_secret().to_encoded().to_string()
    }

    /// Generate a magic token
    /// This will generate a token of type `Magic` and save it to the backend
    /// This token can be used to complete the login process
    ///
    /// # Arguments
    /// * `ctx` - The context to use
    ///
    /// # Errors
    /// * `AuthError::BackendError` - A backend error occurred while generating the token
    #[inline]
    async fn generate_magic_token(&self, ctx: &Self::Context) -> Result<Token, AuthError<Self>> {
        self.generate_token(ctx, TokenType::Magic).await
    }

    /// Generate a token
    /// This will generate a token of the given type and save it to the backend
    ///
    /// # Arguments
    /// * `ctx` - The context to use
    /// * `type` - The type of token to generate
    ///
    /// # Errors
    /// * `AuthError::BackendError` - A backend error occurred while saving the token
    async fn generate_token(
        &self,
        ctx: &Self::Context,
        r#type: TokenType,
    ) -> Result<Token, AuthError<Self>> {
        let token = Token::from_ctx(self, ctx, r#type);
        self.save_token(ctx, &token)
            .await
            .map_err(AuthError::BackendError)?;
        Ok(token)
    }

    /// Redeem a magic token
    /// This will check the token is valid and has not been used before
    /// If all of these checks pass, a authentication token will be generated and returned
    /// If the checks fail, an error will be returned
    /// If the token is generated, the old token will be revoked
    /// This will return an error if the token is not of type `Magic`
    ///
    /// # Arguments
    /// * `ctx` - The context to use
    /// * `token` - The token to redeem
    ///
    /// # Errors
    /// * `AuthError::BackendError` - A backend error occurred while checking the token
    /// * `AuthError::TokenExpired` - The token has expired
    /// * `AuthError::TokenRevoked` - The token has been revoked
    /// * `AuthError::IncorrectTokenType` - The token is not of type `Magic`
    /// * `AuthError::BackendError` - A backend error occurred while generating the token
    async fn redeem_magic_token(
        &self,
        ctx: &Self::Context,
        token: &str,
    ) -> Result<Token, AuthError<Self>> {
        let token = self
            .get_token(ctx, token)
            .await
            .map_err(AuthError::BackendError)?;
        token.check_validity()?;
        if let TokenType::Magic = token.r#type {
            self.revoke_token(ctx, &token)
                .await
                .map_err(AuthError::BackendError)?;
            self.generate_token(ctx, TokenType::Auth).await
        } else {
            Err(AuthError::IncorrectTokenType)
        }
    }

    /// Get the TOTP URL for the given context
    ///
    /// # Arguments
    /// * `ctx` - The context to use
    #[inline]
    fn get_totp_url(&self, ctx: &Self::Context) -> Result<String, AuthError<Self>> {
        Ok(self.totp_from_ctx(ctx)?.get_url())
    }

    /// Get the TOTP QR code for the given context
    /// The result is a base64 encoded PNG image
    ///
    /// # Arguments
    /// * `ctx` - The context to use
    ///
    /// # Errors
    /// * `AuthError::QrCodeError` - An error occurred while generating the QR code
    #[inline]
    fn get_totp_qr_code(&self, ctx: &Self::Context) -> Result<String, AuthError<Self>> {
        self.totp_from_ctx(ctx)?
            .get_qr()
            .map_err(AuthError::QrCodeError)
    }

    /// Start an OAuth2 session
    /// This will return an `OAuthSession` that can be used to start the OAuth2 flow
    /// The `auth_url` field should be used to redirect the user to the OAuth2 provider
    /// The remainder of this session should be stored in the backend and used to complete the
    /// authentication when the user is redirected back
    ///
    /// # Arguments
    /// * `ctx` - The context to use
    /// * `scopes` - The scopes to request
    ///
    /// # Errors
    /// * `AuthError::UrlParseError` - An error occurred while parsing the OAuth2 URLs
    fn start_oauth_session<O>(
        &self,
        _ctx: &Self::Context,
        scopes: impl Iterator<Item = String>,
    ) -> Result<OAuthSession, AuthError<Self>>
    where
        O: OAuthProvider,
    {
        let client = BasicClient::new(
            ClientId::new(O::CLIENT_ID.to_string()),
            Some(ClientSecret::new(O::CLIENT_SECRET.to_string())),
            AuthUrl::new(O::AUTH_URL.to_string())?,
            Some(TokenUrl::new(O::TOKEN_URL.to_string())?),
        )
        .set_redirect_uri(RedirectUrl::new(O::REDIRECT_URL.to_string())?);

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let (auth_url, csrf_token) = client
            .authorize_url(CsrfToken::new_random)
            .add_scopes(scopes.map(Scope::new))
            .set_pkce_challenge(pkce_challenge)
            .url();

        Ok(OAuthSession {
            client,
            auth_url,
            csrf_token,
            pkce_verifier,
        })
    }

    /// Finish an OAuth2 session
    /// This will complete the OAuth2 flow and return an `OAuthResult` with the authentication
    /// token and OAuth2 tokens
    ///
    /// # Arguments
    /// * `ctx` - The context to use
    /// * `oauth_session` - The OAuth2 session to finish
    /// * `code` - The OAuth2 code to use
    /// * `state` - The OAuth2 state to use
    ///
    /// # Errors
    /// * `AuthError::InvalidOAuthState` - The OAuth2 state is invalid
    /// * `AuthError::OAuthTokenError` - An error occurred while exchanging the OAuth2 code
    /// * `AuthError::BackendError` - A backend error occurred while generating the token
    async fn finish_oauth_session(
        &self,
        ctx: &Self::Context,
        oauth_session: OAuthSession,
        code: impl ToString + Send + Sync,
        state: &str,
    ) -> Result<OAuthResult, AuthError<Self>> {
        if state != oauth_session.csrf_token.secret() {
            return Err(AuthError::InvalidOAuthState);
        }
        let token_result = oauth_session
            .client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .set_pkce_verifier(oauth_session.pkce_verifier)
            .request_async(async_http_client)
            .await?;
        let access_token = token_result.access_token().secret().to_string();
        let refresh_token = token_result.refresh_token().map(|i| i.secret().to_string());
        let expires_in = token_result.expires_in();
        let scopes = token_result
            .scopes()
            .map(|i| i.iter().map(|s| s.to_string()).collect());
        let token = self.generate_token(ctx, TokenType::Auth).await?;
        Ok(OAuthResult {
            token,
            access_token,
            refresh_token,
            expires_in,
            scopes,
        })
    }

    // TODO: OAuth2 server support

    // TODO: SAML support
}

/// Implement this trait for each OAuth2 Provider and provide the required configuration constants
pub trait OAuthProvider {
    /// The OAuth2 client ID
    const CLIENT_ID: &'static str;
    /// The OAuth2 client secret
    const CLIENT_SECRET: &'static str;
    /// The OAuth2 authorization URL
    const AUTH_URL: &'static str;
    /// The OAuth2 token URL
    const TOKEN_URL: &'static str;
    /// The OAuth2 redirect URL
    const REDIRECT_URL: &'static str;
}
