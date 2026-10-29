use crate::utils::serde_base64_url_safe_no_pad;
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use libsignal_core::{Aci, ServiceIdKind};
use reqwest::Method;
use serde::Serialize;

use crate::content::ServiceError;
use crate::push_service::response::error_mapper;
use crate::push_service::response::SignalServiceResponse;

use super::{Identified, SignalWebSocket, Unidentified};

// Signal-Server: controllers/AccountController.java:415
// (PUT /v1/accounts/username_link)
error_mapper! {
    put_username_link_errors:
        // 409: username hash not set, AccountController.java:427
        CONFLICT => UsernameHashNotSet,
}

impl SignalWebSocket<Unidentified> {
    pub async fn look_up_username(
        &mut self,
        username: &usernames::Username,
    ) -> Result<Option<Aci>, ServiceError> {
        self.look_up_username_hash(&username.hash()).await
    }

    // Based on libsignal-net
    pub async fn look_up_username_hash(
        &mut self,
        hash: &[u8],
    ) -> Result<Option<Aci>, ServiceError> {
        #[derive(serde::Deserialize)]
        struct UsernameHashResponse {
            uuid: String,
        }

        let response = self
            .http_request(
                Method::GET,
                format!(
                    "/v1/accounts/username_hash/{}",
                    BASE64_URL_SAFE_NO_PAD.encode(hash)
                ),
            )?
            .send()
            .await?;

        if response.status() == 404 {
            tracing::debug!("username not found");
            return Ok(None);
        }

        let result: UsernameHashResponse =
            response.service_error_for_status().await?.json().await?;

        Ok(Some(
            Aci::parse_from_service_id_string(&result.uuid).ok_or_else(
                || ServiceError::InvalidAddressType(ServiceIdKind::Aci),
            )?,
        ))
    }

    /// Looks up the encrypted username stored at a username link handle and
    /// decrypts it.
    ///
    /// `link` must be a full `https://signal.me/#eu/<payload>` URL. The payload
    /// is the URL-safe base64 encoding of the 32-byte link entropy followed by
    /// the 16-byte link handle UUID.
    // Based on libsignal-net
    pub async fn look_up_username_link(
        &mut self,
        link: &url::Url,
    ) -> Result<Option<usernames::Username>, ServiceError> {
        #[derive(serde::Deserialize)]
        struct UsernameLinkResponse {
            #[serde(rename = "usernameLinkEncryptedValue")]
            #[serde(with = "serde_base64_url_safe_no_pad")]
            encrypted_username: Vec<u8>,
        }

        let (uuid, entropy) = parse_username_link(link)?;

        let response = self
            .http_request(
                Method::GET,
                format!("/v1/accounts/username_link/{uuid}"),
            )?
            .send()
            .await?;

        if response.status() == 404 {
            tracing::debug!("username link not found");
            return Ok(None);
        }

        let result: UsernameLinkResponse =
            response.service_error_for_status().await?.json().await?;

        let plaintext_username =
            usernames::decrypt_username(&entropy, &result.encrypted_username)
                .map_err(|error| {
                tracing::error!(%error, "undecryptable username");
                ServiceError::InvalidFrame {
                    reason: "undecryptable username link",
                }
            })?;

        let validated_username = usernames::Username::new(&plaintext_username).map_err(|e| {
            // Exhaustively match UsernameError to make sure there's nothing we shouldn't log.
            #[allow(clippy::let_unit_value)]
            let _username_error_carries_no_information_that_would_be_bad_to_log = match e {
                usernames::UsernameError::MissingSeparator
                | usernames::UsernameError::NicknameCannotBeEmpty
                | usernames::UsernameError::NicknameCannotStartWithDigit
                | usernames::UsernameError::BadNicknameCharacter
                | usernames::UsernameError::NicknameTooShort
                | usernames::UsernameError::NicknameTooLong
                | usernames::UsernameError::DiscriminatorCannotBeEmpty
                | usernames::UsernameError::DiscriminatorCannotBeZero
                | usernames::UsernameError::DiscriminatorCannotBeSingleDigit
                | usernames::UsernameError::DiscriminatorCannotHaveLeadingZeros
                | usernames::UsernameError::BadDiscriminatorCharacter
                | usernames::UsernameError::DiscriminatorTooLarge => {}
            };
            tracing::warn!(error=%e, "username link decrypted to an invalid username");
            tracing::debug!(error=%e,
                "username link decrypted to '{plaintext_username}', which is not valid"
            );
            // The user didn't ever type this username, so the precise way in which it's invalid
            // isn't important. Treat this equivalent to having found garbage data in the link. This
            // simplifies error handling for callers.
            ServiceError::InvalidFrame {
                reason: "undecryptable username link",
            }
        })?;

        Ok(Some(validated_username))
    }
}

/// Splits a username link into its link handle UUID and link entropy.
///
/// `link` must be a full `https://signal.me/#eu/<payload>` URL. The payload is
/// URL-safe base64 (no padding) of the 32-byte entropy followed by the 16-byte
/// handle UUID.
fn parse_username_link(
    link: &url::Url,
) -> Result<
    (
        uuid::Uuid,
        [u8; usernames::constants::USERNAME_LINK_ENTROPY_SIZE],
    ),
    ServiceError,
> {
    if link.scheme() != "https" || link.host_str() != Some("signal.me") {
        return Err(ServiceError::InvalidFrame {
            reason: "username link base is not https://signal.me",
        });
    }

    let fragment =
        link.fragment().ok_or_else(|| ServiceError::InvalidFrame {
            reason: "username link missing fragment",
        })?;
    let mut segments = fragment.split('/');
    if segments.next() != Some("eu") {
        return Err(ServiceError::InvalidFrame {
            reason: "username link must start with #eu/",
        });
    }
    let payload =
        segments.next().ok_or_else(|| ServiceError::InvalidFrame {
            reason: "username link payload missing",
        })?;
    if segments.next().is_some() {
        return Err(ServiceError::InvalidFrame {
            reason: "username link has extra path segments",
        });
    }

    let bytes = BASE64_URL_SAFE_NO_PAD.decode(payload)?;

    let (entropy, rest) = bytes
        .split_first_chunk::<{ usernames::constants::USERNAME_LINK_ENTROPY_SIZE }>()
        .ok_or_else(|| ServiceError::InvalidFrame {
            reason: "username link payload shorter than entropy",
        })?;

    let handle_uuid = uuid::Uuid::from_slice(rest).map_err(|_| {
        ServiceError::InvalidFrame {
            reason: "username link payload missing handle UUID",
        }
    })?;

    Ok((handle_uuid, *entropy))
}

// Signal-Server: controllers/AccountController.java
// (PUT /v1/accounts/username_hash/reserve)
error_mapper! {
    reserve_username_errors:
        // none of the hashes is free
        CONFLICT => UsernameTaken,
}

// (PUT /v1/accounts/username_hash/confirm)
error_mapper! {
    confirm_username_errors:
        // no (matching) reservation any more
        CONFLICT => UsernameReservationInvalid,
        // the username can't be used
        GONE => UsernameTaken,
}

impl SignalWebSocket<Identified> {
    /// Reserves the first free one of `hashes` and returns it.
    // Based on libsignal-net
    pub async fn reserve_username_hash(
        &mut self,
        hashes: &[[u8; 32]],
    ) -> Result<[u8; 32], ServiceError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct ReserveRequest {
            username_hashes: Vec<String>,
        }

        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct ReserveResponse {
            #[serde(with = "serde_base64_url_safe_no_pad")]
            username_hash: Vec<u8>,
        }

        let response = self
            .http_request(Method::PUT, "/v1/accounts/username_hash/reserve")?
            .send_json(ReserveRequest {
                username_hashes: hashes
                    .iter()
                    .map(|h| BASE64_URL_SAFE_NO_PAD.encode(h))
                    .collect(),
            })
            .await?
            .service_error_for_status_with(reserve_username_errors)
            .await?;
        let result: ReserveResponse = response.json().await?;
        result
            .username_hash
            .try_into()
            .map_err(|_| ServiceError::InvalidFrame {
                reason: "reserved username hash is not 32 bytes",
            })
    }

    /// Makes a reserved username the account's, with its link encrypted
    /// value (see `usernames::create_for_username`); returns the link handle.
    // Based on libsignal-net
    pub async fn confirm_username_hash(
        &mut self,
        hash: &[u8; 32],
        proof: &[u8],
        encrypted_username: &[u8],
    ) -> Result<uuid::Uuid, ServiceError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct ConfirmRequest {
            username_hash: String,
            zk_proof: String,
            encrypted_username: String,
        }

        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct ConfirmResponse {
            username_link_handle: Option<uuid::Uuid>,
        }

        let response = self
            .http_request(Method::PUT, "/v1/accounts/username_hash/confirm")?
            .send_json(ConfirmRequest {
                username_hash: BASE64_URL_SAFE_NO_PAD.encode(hash),
                zk_proof: BASE64_URL_SAFE_NO_PAD.encode(proof),
                encrypted_username: BASE64_URL_SAFE_NO_PAD.encode(encrypted_username),
            })
            .await?
            .service_error_for_status_with(confirm_username_errors)
            .await?;
        let result: ConfirmResponse = response.json().await?;
        result.username_link_handle.ok_or(ServiceError::InvalidFrame {
            reason: "confirmed username without a link handle",
        })
    }

    /// Sets the account's username, as Signal's apps do: a nickname without a
    /// discriminator gets the first free one of a set of random candidates,
    /// "nickname.42" is taken as it is. Returns the username and its link.
    pub async fn set_username(
        &mut self,
        nickname: &str,
    ) -> Result<(usernames::Username, url::Url), ServiceError> {
        let invalid = |_| ServiceError::InvalidFrame {
            reason: "invalid username",
        };
        let candidates: Vec<usernames::Username> = if nickname.contains('.') {
            vec![usernames::Username::new(nickname).map_err(invalid)?]
        } else {
            usernames::Username::candidates_from(
                &mut rand::rng(),
                nickname,
                usernames::NicknameLimits::default(),
            )
            .map_err(invalid)?
            .iter()
            .map(|c| usernames::Username::new(c))
            .collect::<Result<_, _>>()
            .map_err(invalid)?
        };
        let hashes: Vec<[u8; 32]> = candidates.iter().map(|c| c.hash()).collect();
        let reserved = self.reserve_username_hash(&hashes).await?;
        let username = candidates
            .into_iter()
            .find(|c| c.hash() == reserved)
            .ok_or(ServiceError::InvalidFrame {
                reason: "server reserved a username hash that was not asked for",
            })?;

        let mut randomness = [0u8; 32];
        rand::Rng::fill(&mut rand::rng(), &mut randomness);
        let proof = username.proof(&randomness).map_err(invalid)?;
        let (entropy, encrypted) = usernames::create_for_username(
            &mut rand::rng(),
            username.to_string(),
            None,
        )
        .map_err(|_e| ServiceError::InvalidFrame {
            reason: "username too long to encrypt",
        })?;
        let handle = self
            .confirm_username_hash(&reserved, &proof, &encrypted)
            .await?;
        Ok((username, generate_username_link(handle, &entropy)))
    }
    /// Sets the account's username link to encrypt `username` and returns the
    /// shareable `https://signal.me/#eu/...` link.
    ///
    /// Generates fresh entropy and, unless `keep_link_handle` is `true` and the
    /// account already has a link handle, a fresh server-assigned handle.
    // Based on libsignal-net
    pub async fn set_username_link(
        &mut self,
        username: &usernames::Username,
        keep_link_handle: bool,
    ) -> Result<url::Url, ServiceError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct SetUsernameLinkRequest {
            #[serde(with = "serde_base64_url_safe_no_pad")]
            username_link_encrypted_value: Vec<u8>,
            keep_link_handle: bool,
        }

        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct UsernameLinkHandleResponse {
            username_link_handle: uuid::Uuid,
        }

        let (entropy, ciphertext) = usernames::create_for_username(
            &mut rand::rng(),
            username.to_string(),
            None,
        )
        .map_err(|_e| ServiceError::InvalidFrame {
            reason: "username too long to encrypt",
        })?;

        let response = self
            .http_request(Method::PUT, "/v1/accounts/username_link")?
            .send_json(SetUsernameLinkRequest {
                username_link_encrypted_value: ciphertext,
                keep_link_handle,
            })
            .await?
            .service_error_for_status_with(put_username_link_errors)
            .await?;

        let result: UsernameLinkHandleResponse = response.json().await?;

        Ok(generate_username_link(
            result.username_link_handle,
            &entropy,
        ))
    }
}

/// Builds the `https://signal.me/#eu/<base64url>` link from its parts.
///
/// `entropy` is the 32-byte link entropy; `handle` is the server-assigned
/// link handle UUID. The payload is the URL-safe base64 (no padding) of
/// `entropy || handle`.
pub fn generate_username_link(
    handle: uuid::Uuid,
    entropy: &[u8; usernames::constants::USERNAME_LINK_ENTROPY_SIZE],
) -> url::Url {
    let mut payload = entropy.to_vec();
    payload.extend_from_slice(handle.as_bytes());
    let mut result = String::from("https://signal.me/#eu/");
    BASE64_URL_SAFE_NO_PAD.encode_string(&payload, &mut result);

    url::Url::parse(&result).expect("can only generate valid URLs")
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn generate_and_parse_link_round_trip() {
        let entropy = [0x42; usernames::constants::USERNAME_LINK_ENTROPY_SIZE];
        let handle = uuid::uuid!("9d0652a3-dcc3-4d11-975f-74d61598733f");
        // deliberately chosen to round-trip cleanly through URL-safe base64
        let link = generate_username_link(handle, &entropy);
        assert!(link.as_str().starts_with("https://signal.me/#eu/"));

        let (parsed_handle, parsed_entropy) =
            parse_username_link(&link).unwrap();
        assert_eq!(parsed_handle, handle);
        assert_eq!(parsed_entropy, entropy);
    }

    #[test]
    fn parse_link_rejects_wrong_base() {
        let entropy = [0x42; usernames::constants::USERNAME_LINK_ENTROPY_SIZE];
        let handle = uuid::uuid!("9d0652a3-dcc3-4d11-975f-74d61598733f");
        let bad_link = generate_username_link(handle, &entropy)
            .to_string()
            .replace("signal.me", "example.com");
        let bad_link = url::Url::parse(&bad_link).unwrap();
        assert!(parse_username_link(&bad_link).is_err());
    }

    #[test]
    fn parse_link_rejects_missing_eu_marker() {
        let bad_link = url::Url::parse(
            "https://signal.me/#foo/R_rHg5IQLE60Qad5l8rV-6x2TMcVnDYvOV-igYXJj6GK1NuNeE9LKI3V_VZ8IH2p",
        )
        .unwrap();
        assert!(parse_username_link(&bad_link).is_err());
    }

    #[test]
    fn parse_link_rejects_extra_fragment_segments() {
        let bad_link =
            url::Url::parse("https://signal.me/#eu/payload/extra").unwrap();
        assert!(parse_username_link(&bad_link).is_err());
    }
}
