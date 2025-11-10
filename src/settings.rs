use serde::{Deserialize, Serialize};

use crate::errors::{ProbeSettingError, SettingsError, SettingsValidationError};

// Describe the settings your policy expects when
// loaded by the policy server.
#[derive(Serialize, Deserialize, Default, Debug)]
pub(crate) struct Settings {
    pub liveness: ProbeConfiguration,
    pub readiness: ProbeConfiguration,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub(crate) struct ProbeConfiguration {
    pub enforce: bool,
    pub period_seconds: Option<ProbeTimeConfiguration<i32>>,
    pub failure_threshold: Option<ProbeTimeConfiguration<i32>>,
    pub initial_delay_seconds: Option<ProbeTimeConfiguration<i32>>,
    pub success_threshold: Option<ProbeTimeConfiguration<i32>>,
    pub termination_grace_period_seconds: Option<ProbeTimeConfiguration<i64>>,
    pub timeout_seconds: Option<ProbeTimeConfiguration<i32>>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub(crate) struct ProbeTimeConfiguration<T>
where
    T: Into<i64> + Copy,
{
    pub minimum: Option<T>,
    pub limit: Option<T>,
}

// The policy should validate the probes by default. Otherwise, there is no
// point in using this policy.
impl Default for ProbeConfiguration {
    fn default() -> Self {
        ProbeConfiguration {
            enforce: true,
            period_seconds: None,
            failure_threshold: None,
            initial_delay_seconds: None,
            success_threshold: None,
            termination_grace_period_seconds: None,
            timeout_seconds: None,
        }
    }
}

impl kubewarden::settings::Validatable for Settings {
    fn validate(&self) -> Result<(), String> {
        if !self.liveness.enforce && !self.readiness.enforce {
            return Err(SettingsValidationError::NoneEnforcement.to_string());
        }
        self.liveness
            .validate()
            .map_err(|e| SettingsError::InvalidLivenessSettings(e).to_string())?;
        self.readiness
            .validate()
            .map_err(|e| SettingsError::InvalidReadinessSettings(e).to_string())
    }
}

impl ProbeConfiguration {
    pub fn validate(&self) -> Result<(), ProbeSettingError> {
        if let Some(ref self_period_seconds) = self.period_seconds {
            self_period_seconds
                .validate()
                .map_err(|e| ProbeSettingError::InvalidField("periodSeconds".to_owned(), e))?;
        }
        if let Some(ref self_failure_threshold) = self.failure_threshold {
            self_failure_threshold
                .validate()
                .map_err(|e| ProbeSettingError::InvalidField("failureThreshold".to_string(), e))?;
        }
        if let Some(ref self_initial_delay_seconds) = self.initial_delay_seconds {
            self_initial_delay_seconds.validate().map_err(|e| {
                ProbeSettingError::InvalidField("initialDelaySeconds".to_owned(), e)
            })?;
        }
        if let Some(ref self_success_threshold) = self.success_threshold {
            self_success_threshold
                .validate()
                .map_err(|e| ProbeSettingError::InvalidField("successThreshold".to_owned(), e))?;
        }
        if let Some(ref self_termination_grace_period_seconds) =
            self.termination_grace_period_seconds
        {
            self_termination_grace_period_seconds
                .validate()
                .map_err(|e| {
                    ProbeSettingError::InvalidField("terminationGracePeriodSeconds".to_owned(), e)
                })?;
        }
        if let Some(ref self_timeout_seconds) = self.timeout_seconds {
            self_timeout_seconds
                .validate()
                .map_err(|e| ProbeSettingError::InvalidField("timeoutSeconds".to_owned(), e))?;
        }
        Ok(())
    }
}

impl<T> ProbeTimeConfiguration<T>
where
    T: Into<i64> + Copy,
{
    pub fn validate(&self) -> Result<(), SettingsValidationError> {
        if self.minimum.is_none() && self.limit.is_none() {
            return Err(SettingsValidationError::MissingMinimumAndLimit);
        }

        let minimum = self.minimum.as_ref().map(|v| Into::<i64>::into(*v));
        let limit = self.limit.as_ref().map(|v| Into::<i64>::into(*v));

        if let Some(min) = minimum
            && min <= 0
        {
            return Err(SettingsValidationError::MinimumLessThanEqualZero);
        }
        if let Some(limit) = limit
            && limit <= 0
        {
            return Err(SettingsValidationError::LimitLessThanEqualZero);
        }
        if let (Some(min), Some(limit)) = (minimum, limit)
            && min > limit
        {
            return Err(SettingsValidationError::MinimumGreaterThanLimit);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    use kubewarden_policy_sdk::settings::Validatable;

    #[rstest]
    #[case::default_settings(Settings {
            ..Default::default()
        }, None)]
    #[case(Settings {
            liveness: ProbeConfiguration {
                enforce: false,
                ..Default::default()
            },
            readiness: ProbeConfiguration {
                enforce: false,
                ..Default::default()
            },
        }, Some(SettingsValidationError::NoneEnforcement))]
    #[case::validate_settings_with_invalid_period_seconds_range(Settings {
            readiness: ProbeConfiguration {
                enforce: true,
                period_seconds: Some(ProbeTimeConfiguration {
                    minimum: Some(15),
                    limit: Some(10),
                }),
                ..Default::default()
            },
                ..Default::default()
        }, Some(SettingsValidationError::MinimumGreaterThanLimit))]
    #[case::missing_minimum_and_limit(Settings {
            liveness: ProbeConfiguration {
                enforce: true,
                period_seconds: Some(ProbeTimeConfiguration {
                    minimum: None,
                    limit: None,
                }),
                ..Default::default()
            },
                ..Default::default()
        }, Some(SettingsValidationError::MissingMinimumAndLimit))]
    #[case::minimum_less_than_zero(Settings {
            liveness: ProbeConfiguration {
                enforce: true,
                period_seconds: Some(ProbeTimeConfiguration {
                    minimum: Some(-1),
                    limit: None,
                }),
                ..Default::default()
            },
                ..Default::default()
        }, Some(SettingsValidationError::MinimumLessThanEqualZero))]
    #[case::limit_less_than_zero(Settings {
            liveness: ProbeConfiguration {
                enforce: true,
                period_seconds: Some(ProbeTimeConfiguration {
                    minimum: None,
                    limit: Some(-1),
                }),
                ..Default::default()
            },
                ..Default::default()
        }, Some(SettingsValidationError::LimitLessThanEqualZero))]
    fn validate_settings(
        #[case] settings: Settings,
        #[case] expected_error: Option<SettingsValidationError>,
    ) {
        let result = settings.validate();
        if let Some(expected) = expected_error {
            let error = result.expect_err("validation should fail");
            assert!(
                error.contains(&expected.to_string()),
                "expected error: {:?}, got: {}",
                expected,
                error
            );
        } else {
            assert!(result.is_ok());
        }
    }
}
