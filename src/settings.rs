use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ProbeConfiguration {
    pub enforce: bool,
}
// Describe the settings your policy expects when
// loaded by the policy server.
#[derive(Serialize, Deserialize, Default, Debug)]
pub(crate) struct Settings {
    pub liveness: ProbeConfiguration,
    pub readiness: ProbeConfiguration,
}

impl kubewarden::settings::Validatable for Settings {
    fn validate(&self) -> Result<(), String> {
        if !self.liveness.enforce && !self.readiness.enforce {
            return Err(
                "at least one of liveness or readiness probe enforcement must be enabled"
                    .to_string(),
            );
        }
        Ok(())
    }
}

// The policy should validate the probes by default. Otherwise, there is no
// point in using this policy.
impl Default for ProbeConfiguration {
    fn default() -> Self {
        ProbeConfiguration { enforce: true }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use kubewarden_policy_sdk::settings::Validatable;

    #[test]
    fn validate_settings() {
        let settings = Settings {
            ..Default::default()
        };

        settings.validate().expect("validation should pass");
    }

    #[test]
    fn validate_settings_fail() {
        let settings = Settings {
            liveness: ProbeConfiguration { enforce: false },
            readiness: ProbeConfiguration { enforce: false },
        };

        let err = settings.validate().expect_err("validation should fail");
        assert_eq!(
            err,
            "at least one of liveness or readiness probe enforcement must be enabled"
        );
    }
}
