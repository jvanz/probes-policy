use serde::{Deserialize, Serialize};

const NONE_ENFORCEMENT_ERROR: &str =
    "at least one of liveness or readiness probe enforcement must be enabled";
const MISSING_MINIMUM_AND_LIMIT_ERROR: &str = "at least one of minimum or limit must be set";
const MINIMUM_GREATER_THAN_LIMIT_ERROR: &str = "minimum cannot be greater than limit";
const MINIMUM_LESS_THAN_EQUAL_ZERO_ERROR: &str = "minimum must be greater than zero";
const LIMIT_LESS_THAN_EQUAL_ZERO_ERROR: &str = "limit must be greater than zero";

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
            return Err(NONE_ENFORCEMENT_ERROR.to_string());
        }
        self.liveness
            .validate()
            .map_err(|e| format!("Invalid liveness probe: {}", e))?;
        self.readiness
            .validate()
            .map_err(|e| format!("Invalid readiness probe: {}", e))
    }
}

impl ProbeConfiguration {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref self_period_seconds) = self.period_seconds {
            self_period_seconds
                .validate()
                .map_err(|e| format!("periodSeconds: {}", e))?;
        }
        if let Some(ref self_failure_threshold) = self.failure_threshold {
            self_failure_threshold
                .validate()
                .map_err(|e| format!("failureThreshold: {}", e))?;
        }
        if let Some(ref self_initial_delay_seconds) = self.initial_delay_seconds {
            self_initial_delay_seconds
                .validate()
                .map_err(|e| format!("initialDelaySeconds: {}", e))?;
        }
        if let Some(ref self_success_threshold) = self.success_threshold {
            self_success_threshold
                .validate()
                .map_err(|e| format!("successThreshold: {}", e))?;
        }
        if let Some(ref self_termination_grace_period_seconds) =
            self.termination_grace_period_seconds
        {
            self_termination_grace_period_seconds
                .validate()
                .map_err(|e| format!("terminationGracePeriodSeconds: {}", e))?;
        }
        if let Some(ref self_timeout_seconds) = self.timeout_seconds {
            self_timeout_seconds
                .validate()
                .map_err(|e| format!("timeoutSeconds: {}", e))?;
        }
        Ok(())
    }
}

impl<T> ProbeTimeConfiguration<T>
where
    T: Into<i64> + Copy,
{
    pub fn validate(&self) -> Result<(), String> {
        if self.minimum.is_none() && self.limit.is_none() {
            return Err(MISSING_MINIMUM_AND_LIMIT_ERROR.to_owned());
        }

        let minimum = self.minimum.as_ref().map(|v| Into::<i64>::into(*v));
        let limit = self.limit.as_ref().map(|v| Into::<i64>::into(*v));

        if let Some(min) = minimum
            && min <= 0
        {
            return Err(MINIMUM_LESS_THAN_EQUAL_ZERO_ERROR.to_owned());
        }
        if let Some(limit) = limit
            && limit <= 0
        {
            return Err(LIMIT_LESS_THAN_EQUAL_ZERO_ERROR.to_owned());
        }
        if let (Some(min), Some(limit)) = (minimum, limit)
            && min > limit
        {
            return Err(MINIMUM_GREATER_THAN_LIMIT_ERROR.to_owned());
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
        }, Some(NONE_ENFORCEMENT_ERROR))]
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
        }, Some(MINIMUM_GREATER_THAN_LIMIT_ERROR))]
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
        }, Some(MISSING_MINIMUM_AND_LIMIT_ERROR))]
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
        }, Some(MINIMUM_LESS_THAN_EQUAL_ZERO_ERROR))]
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
        }, Some(LIMIT_LESS_THAN_EQUAL_ZERO_ERROR))]
    fn validate_settings(#[case] settings: Settings, #[case] expected_error: Option<&str>) {
        let result = settings.validate();
        if expected_error.is_some() {
            assert!(
                result
                    .expect_err("validation should fail")
                    .to_owned()
                    .contains(expected_error.unwrap())
            );
            return;
        }
        assert!(result.is_ok());
    }
}
