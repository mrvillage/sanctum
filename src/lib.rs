use std::time::SystemTimeError;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use oauth2::{
    basic::{BasicClient, BasicErrorResponseType},
    reqwest::{async_http_client, Error as ReqwestError},
    url::{ParseError, Url},
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, RequestTokenError, Scope, StandardErrorResponse,
    StandardTokenResponse, TokenResponse, TokenUrl,
};
use rand_core::{OsRng, RngCore};
use thiserror::Error;
use totp_rs::{Rfc6238, Rfc6238Error, Secret, SecretParseError, TotpUrlError, TOTP};

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

#[derive(Debug)]
pub enum TokenType {
    Auth,
    TwoFactorRequired,
    Magic,
}

#[derive(Debug)]
pub enum Id {
    Numeric(u64),
    Text(String),
}

#[derive(Debug)]
pub struct Token {
    pub user_id: Id,
    pub token: String,
    pub issued: DateTime<Utc>,
    pub expiry: DateTime<Utc>,
    pub r#type: TokenType,
    pub revoked: bool,
}

impl Token {
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

#[derive(Debug)]
pub struct OAuthSession {
    client: BasicClient,
    pub auth_url: Url,
    csrf_token: CsrfToken,
    pkce_verifier: PkceCodeVerifier,
}

#[derive(Debug)]
pub struct OAuthResult {
    pub token: Token,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<std::time::Duration>,
    pub scopes: Option<Vec<String>>,
}

#[async_trait]
pub trait Backend {
    type Context: Send + Sync;
    type Error: std::error::Error + std::fmt::Display;
    const TOTP_ISSUER: &'static str;

    #[inline(always)]
    fn hash_password(&self, password: &str) -> String {
        password_auth::generate_hash(password.as_bytes())
    }

    #[inline(always)]
    fn verify_password(&self, input: &str, hash: &str) -> Result<(), password_auth::VerifyError> {
        password_auth::verify_password(input, hash)
    }

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

    #[inline(always)]
    fn get_token_valid_duration(&self, ctx: &Self::Context, r#type: &TokenType) -> Duration {
        match r#type {
            TokenType::Magic => Duration::minutes(15),
            TokenType::TwoFactorRequired => Duration::minutes(5),
            TokenType::Auth => self.get_auth_token_valid_duration(ctx),
        }
    }

    fn get_password_hash<'c>(&self, ctx: &'c Self::Context) -> &'c str;
    fn is_two_factor_enabled(&self, ctx: &Self::Context) -> bool;
    fn get_auth_token_valid_duration(&self, ctx: &Self::Context) -> Duration;
    fn get_user_id(&self, ctx: &Self::Context) -> Id;
    async fn save_token(&self, ctx: &Self::Context, token: &Token) -> Result<(), Self::Error>;
    async fn get_token(&self, ctx: &Self::Context, token: &str) -> Result<Token, Self::Error>;
    async fn revoke_token(&self, ctx: &Self::Context, token: &Token) -> Result<(), Self::Error>;
    async fn store_totp_code_used(
        &self,
        ctx: &Self::Context,
        code: &str,
    ) -> Result<(), Self::Error>;
    fn get_totp_secret<'c>(&self, ctx: &'c Self::Context) -> &'c str;
    fn get_totp_account_name(&self, ctx: &Self::Context) -> String;
    async fn has_totp_code_been_used(
        &self,
        ctx: &Self::Context,
        code: &str,
    ) -> Result<bool, Self::Error>;

    #[inline(always)]
    fn totp(&self, ctx: &Self::Context, secret: &str) -> Result<TOTP, AuthError<Self>> {
        Ok(TOTP::from_rfc6238(Rfc6238::new(
            8,
            Secret::Encoded(secret.to_string()).to_bytes()?,
            Some(Self::TOTP_ISSUER.to_string()),
            self.get_totp_account_name(ctx),
        )?)?)
    }

    #[inline(always)]
    fn totp_from_ctx(&self, ctx: &Self::Context) -> Result<TOTP, AuthError<Self>> {
        self.totp(ctx, self.get_totp_secret(ctx))
    }

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

    #[inline(always)]
    fn get_current_totp_code(&self, ctx: &Self::Context) -> Result<String, AuthError<Self>> {
        Ok(self.totp_from_ctx(ctx)?.generate_current()?)
    }

    #[inline(always)]
    fn generate_totp_secret_base_32(&self) -> String {
        Secret::generate_secret().to_encoded().to_string()
    }

    #[inline(always)]
    async fn generate_magic_token(&self, ctx: &Self::Context) -> Result<Token, AuthError<Self>> {
        self.generate_token(ctx, TokenType::Magic).await
    }

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

    #[inline(always)]
    fn get_totp_url(&self, ctx: &Self::Context) -> Result<String, AuthError<Self>> {
        Ok(self.totp_from_ctx(ctx)?.get_url())
    }

    #[inline(always)]
    fn get_totp_qr_code(&self, ctx: &Self::Context) -> Result<String, AuthError<Self>> {
        self.totp_from_ctx(ctx)?
            .get_qr()
            .map_err(AuthError::QrCodeError)
    }

    fn start_oauth_session<O>(
        &self,
        _ctx: &Self::Context,
        scopes: impl Iterator<Item = String>,
    ) -> Result<OAuthSession, AuthError<Self>>
    where
        O: OAuthProvider,
    {
        let client = BasicClient::new(
            ClientId::new(O::get_client_id()),
            Some(ClientSecret::new(O::get_client_secret())),
            AuthUrl::new(O::get_auth_url())?,
            Some(TokenUrl::new(O::get_token_url())?),
        )
        .set_redirect_uri(RedirectUrl::new(O::get_redirect_url())?);

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

pub trait OAuthProvider {
    fn get_client_id() -> String;
    fn get_client_secret() -> String;
    fn get_auth_url() -> String;
    fn get_token_url() -> String;
    fn get_redirect_url() -> String;
}
