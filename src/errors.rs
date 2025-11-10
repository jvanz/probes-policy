use thiserror::Error;

/// This file contain the error types used in the settings and policy validation.
/// These errors are used to indicate validation failures and provide meaningful
/// messages to the users.
///
/// The validation errors are categorized into different enums to allow an easy
/// way to embed them into higher level errors, such as container validation errors.

#[derive(Error, Debug)]
pub enum SettingsValidationError {
    #[error("at least one of liveness or readiness probe enforcement must be enabled")]
    NoneEnforcement,
    #[error("at least one of minimum or limit must be set")]
    MissingMinimumAndLimit,
    #[error("minimum cannot be greater than limit")]
    MinimumGreaterThanLimit,
    #[error("minimum must be greater than zero")]
    MinimumLessThanEqualZero,
    #[error("limit must be greater than zero")]
    LimitLessThanEqualZero,
}

#[derive(Error, Debug)]
pub enum ProbeSettingError {
    #[error("{0} validation failed: {1}")]
    InvalidField(String, #[source] SettingsValidationError),
}

#[derive(Error, Debug)]
pub enum SettingsError {
    #[error("invalid liveness probe settings: {0}")]
    InvalidLivenessSettings(#[source] ProbeSettingError),
    #[error("invalid readiness probe settings: {0}")]
    InvalidReadinessSettings(#[source] ProbeSettingError),
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum PolicyValidationError {
    #[error("{0} is below the minimum of {1}")]
    BelowMinimum(i64, i64),
    #[error("{0} is above the limit of {1}")]
    AboveLimit(i64, i64),
    #[error("missing value")]
    MissingValue,
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ProbeError {
    #[error("{0} validation failed: {1}")]
    FieldValidationError(String, #[source] PolicyValidationError),
    #[error("container {0} without liveness probe is not accepted")]
    MissingLivenessProbe(String),
    #[error("container {0} without readiness probe is not accepted")]
    MissingReadinessProbe(String),
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ContainerError {
    #[error("container {0} is invalid: {1}")]
    Container(String, #[source] ProbeError),
    #[error("init container {0} is invalid: {1}")]
    InitContainer(String, #[source] ProbeError),
    #[error("ephemeral container {0} is invalid: {1}")]
    EphemeralContainer(String, #[source] ProbeError),
}
