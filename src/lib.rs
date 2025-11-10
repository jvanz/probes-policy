use anyhow::{Result, anyhow};
use lazy_static::lazy_static;

use guest::prelude::*;
use kubewarden_policy_sdk::wapc_guest as guest;

use k8s_openapi::api::core::v1 as apicore;

extern crate kubewarden_policy_sdk as kubewarden;
use kubewarden::{logging, protocol_version_guest, request::ValidationRequest, validate_settings};

mod errors;
mod settings;
use settings::Settings;

use slog::{Logger, info, o, warn};

use crate::errors::{ContainerError, PolicyValidationError, ProbeError};

lazy_static! {
    static ref LOG_DRAIN: Logger = Logger::root(
        logging::KubewardenDrain::new(),
        o!("policy" => "probes-policy")
    );
}

#[unsafe(no_mangle)]
pub extern "C" fn wapc_init() {
    register_function("validate", validate);
    register_function("validate_settings", validate_settings::<Settings>);
    register_function("protocol_version", protocol_version_guest);
}

// This function is used to validate the probe periods configurations.
fn validate_time_configuration<T>(
    time_value: Option<T>,
    probe_time_conf: Option<&settings::ProbeTimeConfiguration<T>>,
) -> Result<(), PolicyValidationError>
where
    T: Into<i64> + Copy,
{
    let time_value = time_value.map(|v| v.into());

    if let Some(time_config) = probe_time_conf {
        if let Some(time) = time_value {
            let time_config_min = time_config.minimum.map(|v| v.into());
            if let Some(minimum) = &time_config_min
                && time < *minimum
            {
                return Err(PolicyValidationError::BelowMinimum(time, *minimum));
            }

            let time_config_limit = time_config.limit.map(|v| v.into());
            if let Some(limit) = &time_config_limit
                && time > *limit
            {
                return Err(PolicyValidationError::AboveLimit(time, *limit));
            }
        } else {
            return Err(PolicyValidationError::MissingValue);
        }
    }

    Ok(())
}

// Validate all the period/threshold values from probe configuration.
fn validate_probe(
    probe: &apicore::Probe,
    probe_settings: &settings::ProbeConfiguration,
) -> Result<(), ProbeError> {
    validate_time_configuration(probe.period_seconds, probe_settings.period_seconds.as_ref())
        .map_err(|e| ProbeError::FieldValidationError("periodSeconds".to_owned(), e))?;

    validate_time_configuration(
        probe.failure_threshold,
        probe_settings.failure_threshold.as_ref(),
    )
    .map_err(|e| ProbeError::FieldValidationError("failureThreshold".to_owned(), e))?;

    validate_time_configuration(
        probe.success_threshold,
        probe_settings.success_threshold.as_ref(),
    )
    .map_err(|e| ProbeError::FieldValidationError("successThreshold".to_owned(), e))?;

    validate_time_configuration(
        probe.termination_grace_period_seconds,
        probe_settings.termination_grace_period_seconds.as_ref(),
    )
    .map_err(|e| ProbeError::FieldValidationError("terminationGracePeriodSeconds".to_owned(), e))?;

    validate_time_configuration(
        probe.timeout_seconds,
        probe_settings.timeout_seconds.as_ref(),
    )
    .map_err(|e| ProbeError::FieldValidationError("timeoutSeconds".to_owned(), e))?;

    validate_time_configuration(
        probe.initial_delay_seconds,
        probe_settings.initial_delay_seconds.as_ref(),
    )
    .map_err(|e| ProbeError::FieldValidationError("initialDelaySeconds".to_owned(), e))?;

    Ok(())
}

fn validate_container(
    container: &apicore::Container,
    settings: &Settings,
) -> Result<(), ProbeError> {
    if container.liveness_probe.is_none() && settings.liveness.enforce {
        info!(
            LOG_DRAIN,
            "rejecting pod";
            "container_name" => &container.name
        );
        return Err(ProbeError::MissingLivenessProbe(container.name.clone()));
    }
    if container.liveness_probe.is_some() && settings.liveness.enforce {
        validate_probe(
            container.liveness_probe.as_ref().unwrap(),
            &settings.liveness,
        )?;
    }
    if container.readiness_probe.is_none() && settings.readiness.enforce {
        info!(
            LOG_DRAIN,
            "rejecting pod";
            "container_name" => &container.name
        );
        return Err(ProbeError::MissingReadinessProbe(container.name.clone()));
    }
    if container.readiness_probe.is_some() && settings.readiness.enforce {
        validate_probe(
            container.readiness_probe.as_ref().unwrap(),
            &settings.readiness,
        )?;
    }
    Ok(())
}

fn validate_ephemeral_container(
    container: &apicore::EphemeralContainer,
    settings: &Settings,
) -> Result<(), ProbeError> {
    if container.liveness_probe.is_none() && settings.liveness.enforce {
        info!(
            LOG_DRAIN,
            "rejecting pod";
            "container_name" => &container.name
        );
        return Err(ProbeError::MissingLivenessProbe(container.name.clone()));
    }
    if container.readiness_probe.is_none() && settings.readiness.enforce {
        info!(
            LOG_DRAIN,
            "rejecting pod";
            "container_name" => &container.name
        );
        return Err(ProbeError::MissingReadinessProbe(container.name.clone()));
    }
    Ok(())
}

fn validate_pod(pod: &apicore::PodSpec, settings: &Settings) -> Result<()> {
    let mut err_message = String::new();
    for container in &pod.containers {
        let container_valid = validate_container(container, settings)
            .map_err(|e| ContainerError::Container(container.name.clone(), e));
        if let Err(e) = container_valid {
            err_message = err_message + &e.to_string();
        };
    }
    if let Some(init_containers) = &pod.init_containers {
        for container in init_containers {
            let container_valid = validate_container(container, settings)
                .map_err(|e| ContainerError::InitContainer(container.name.clone(), e));
            if let Err(e) = container_valid {
                err_message = err_message + &e.to_string();
            }
        }
    }
    if let Some(ephemeral_containers) = &pod.ephemeral_containers {
        for container in ephemeral_containers {
            let container_valid = validate_ephemeral_container(container, settings)
                .map_err(|e| ContainerError::EphemeralContainer(container.name.clone(), e));
            if let Err(e) = container_valid {
                err_message = err_message + &e.to_string();
            }
        }
    }
    if err_message.is_empty() {
        return Ok(());
    }
    Err(anyhow!(err_message))
}

fn validate(payload: &[u8]) -> CallResult {
    let validation_request: ValidationRequest<Settings> = ValidationRequest::new(payload)?;

    info!(LOG_DRAIN, "starting validation");
    match validation_request.extract_pod_spec_from_object() {
        Ok(pod_spec) => {
            if let Some(pod_spec) = pod_spec {
                return match validate_pod(&pod_spec, &validation_request.settings) {
                    Ok(_) => kubewarden::accept_request(),
                    Err(err) => kubewarden::reject_request(Some(err.to_string()), None, None, None),
                };
            };
            // If there is not pod spec, just accept it. There is no data to be
            // validated.
            kubewarden::accept_request()
        }
        Err(_) => {
            warn!(
                LOG_DRAIN,
                "cannot unmarshal resource: this policy does not know how to evaluate this resource; accept it"
            );
            kubewarden::reject_request(
                Some("Cannot parse validation request".to_string()),
                None,
                None,
                None,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    use kubewarden_policy_sdk::test::Testcase;

    #[rstest]
    #[case::failure_threshold_below_minimum(
        &apicore::Probe {
            failure_threshold: Some(4),
            ..Default::default()
        },
        &settings::ProbeConfiguration {
            enforce: true,
            failure_threshold: Some(settings::ProbeTimeConfiguration {
                minimum: Some(5),
                limit: Some(15),
            }),
            ..Default::default()
        },
        Some(ProbeError::FieldValidationError("failureThreshold".to_string(), PolicyValidationError::BelowMinimum(4,5)))
    )]
    #[case::failure_threshold_above_minimum(
        &apicore::Probe {
            failure_threshold: Some(16),
            ..Default::default()
        },
        &settings::ProbeConfiguration {
            enforce: true,
            failure_threshold: Some(settings::ProbeTimeConfiguration {
                minimum: Some(5),
                limit: Some(15),
            }),
            ..Default::default()
        },
        Some(ProbeError::FieldValidationError("failureThreshold".to_string(), PolicyValidationError::AboveLimit(16,15)))
    )]
    #[case::failure_threshold_between_expected_range(
        &apicore::Probe {
            failure_threshold: Some(10),
            ..Default::default()
        },
        &settings::ProbeConfiguration {
            enforce: true,
            failure_threshold: Some(settings::ProbeTimeConfiguration {
                minimum: Some(5),
                limit: Some(15),
            }),
            ..Default::default()
        },
        None,
    )]
    #[case::initial_delay_seconds_below_minimum(
        &apicore::Probe {
            initial_delay_seconds: Some(4),
            ..Default::default()
        },
        &settings::ProbeConfiguration {
            enforce: true,
            initial_delay_seconds: Some(settings::ProbeTimeConfiguration {
                minimum: Some(5),
                limit: Some(15),
            }),
            ..Default::default()
        },
        Some(ProbeError::FieldValidationError("initialDelaySeconds".to_string(), PolicyValidationError::BelowMinimum(4,5)))
    )]
    #[case::initial_delay_seconds_above_minimum(
        &apicore::Probe {
            initial_delay_seconds: Some(16),
            ..Default::default()
        },
        &settings::ProbeConfiguration {
            enforce: true,
            initial_delay_seconds: Some(settings::ProbeTimeConfiguration {
                minimum: Some(5),
                limit: Some(15),
            }),
            ..Default::default()
        },
        Some(ProbeError::FieldValidationError("initialDelaySeconds".to_string(), PolicyValidationError::AboveLimit(16,15)))
    )]
    #[case::initial_delay_seconds_between_expected_range(
        &apicore::Probe {
            initial_delay_seconds: Some(10),
            ..Default::default()
        },
        &settings::ProbeConfiguration {
            enforce: true,
            initial_delay_seconds: Some(settings::ProbeTimeConfiguration {
                minimum: Some(5),
                limit: Some(15),
            }),
            ..Default::default()
        },
        None,
    )]
    #[case::period_seconds_below_minimum(
        &apicore::Probe {
            period_seconds: Some(4),
            ..Default::default()
        },
        &settings::ProbeConfiguration {
            enforce: true,
            period_seconds: Some(settings::ProbeTimeConfiguration {
                minimum: Some(5),
                limit: Some(15),
            }),
            ..Default::default()
        },
        Some(ProbeError::FieldValidationError("periodSeconds".to_string(), PolicyValidationError::BelowMinimum(4,5)))
    )]
    #[case::period_seconds_above_minimum(
        &apicore::Probe {
            period_seconds: Some(16),
            ..Default::default()
        },
        &settings::ProbeConfiguration {
            enforce: true,
            period_seconds: Some(settings::ProbeTimeConfiguration {
                minimum: Some(5),
                limit: Some(15),
            }),
            ..Default::default()
        },
        Some(ProbeError::FieldValidationError("periodSeconds".to_string(), PolicyValidationError::AboveLimit(16,15)))
    )]
    #[case::period_seconds_between_expected_range(
        &apicore::Probe {
            period_seconds: Some(10),
            ..Default::default()
        },
        &settings::ProbeConfiguration {
            enforce: true,
            period_seconds: Some(settings::ProbeTimeConfiguration {
                minimum: Some(5),
                limit: Some(15),
            }),
            ..Default::default()
        },
        None,
    )]
    #[case::success_threshold_below_minimum(
        &apicore::Probe {
            success_threshold: Some(4),
            ..Default::default()
        },
        &settings::ProbeConfiguration {
            enforce: true,
            success_threshold: Some(settings::ProbeTimeConfiguration {
                minimum: Some(5),
                limit: Some(15),
            }),
            ..Default::default()
        },
        Some(ProbeError::FieldValidationError("successThreshold".to_string(), PolicyValidationError::BelowMinimum(4,5)))
    )]
    #[case::success_threshold_above_minimum(
        &apicore::Probe {
            success_threshold: Some(16),
            ..Default::default()
        },
        &settings::ProbeConfiguration {
            enforce: true,
            success_threshold: Some(settings::ProbeTimeConfiguration {
                minimum: Some(5),
                limit: Some(15),
            }),
            ..Default::default()
        },
        Some(ProbeError::FieldValidationError("successThreshold".to_string(), PolicyValidationError::AboveLimit(16,15)))
    )]
    #[case::success_threshold_between_expected_range(
        &apicore::Probe {
            success_threshold: Some(10),
            ..Default::default()
        },
        &settings::ProbeConfiguration {
            enforce: true,
            success_threshold: Some(settings::ProbeTimeConfiguration {
                minimum: Some(5),
                limit: Some(15),
            }),
            ..Default::default()
        },
        None,
    )]
    #[case::termination_grace_period_seconds_below_minimum(
        &apicore::Probe {
            termination_grace_period_seconds: Some(4),
            ..Default::default()
        },
        &settings::ProbeConfiguration {
            enforce: true,
            termination_grace_period_seconds: Some(settings::ProbeTimeConfiguration {
                minimum: Some(5),
                limit: Some(15),
            }),
            ..Default::default()
        },
        Some(ProbeError::FieldValidationError("terminationGracePeriodSeconds".to_string(), PolicyValidationError::BelowMinimum(4,5)))
    )]
    #[case::termination_grace_period_seconds_above_minimum(
        &apicore::Probe {
            termination_grace_period_seconds: Some(16),
            ..Default::default()
        },
        &settings::ProbeConfiguration {
            enforce: true,
            termination_grace_period_seconds: Some(settings::ProbeTimeConfiguration {
                minimum: Some(5),
                limit: Some(15),
            }),
            ..Default::default()
        },
        Some(ProbeError::FieldValidationError("terminationGracePeriodSeconds".to_string(), PolicyValidationError::AboveLimit(16,15)))
    )]
    #[case::termination_grace_period_seconds_between_expected_range(
        &apicore::Probe {
            termination_grace_period_seconds: Some(10),
            ..Default::default()
        },
        &settings::ProbeConfiguration {
            enforce: true,
            termination_grace_period_seconds: Some(settings::ProbeTimeConfiguration {
                minimum: Some(5),
                limit: Some(15),
            }),
            ..Default::default()
        },
        None,
    )]
    #[case::timeout_seconds_below_minimum(
        &apicore::Probe {
            timeout_seconds: Some(4),
            ..Default::default()
        },
        &settings::ProbeConfiguration {
            enforce: true,
            timeout_seconds: Some(settings::ProbeTimeConfiguration {
                minimum: Some(5),
                limit: Some(15),
            }),
            ..Default::default()
        },
        Some(ProbeError::FieldValidationError("timeoutSeconds".to_string(), PolicyValidationError::BelowMinimum(4,5)))
    )]
    #[case::timeout_seconds_above_minimum(
        &apicore::Probe {
            timeout_seconds: Some(16),
            ..Default::default()
        },
        &settings::ProbeConfiguration {
            enforce: true,
            timeout_seconds: Some(settings::ProbeTimeConfiguration {
                minimum: Some(5),
                limit: Some(15),
            }),
            ..Default::default()
        },
        Some(ProbeError::FieldValidationError("timeoutSeconds".to_string(), PolicyValidationError::AboveLimit(16, 15)))
    )]
    #[case::timeout_seconds_between_expected_range(
        &apicore::Probe {
            timeout_seconds: Some(10),
            ..Default::default()
        },
        &settings::ProbeConfiguration {
            enforce: true,
            timeout_seconds: Some(settings::ProbeTimeConfiguration {
                minimum: Some(5),
                limit: Some(15),
            }),
            ..Default::default()
        },
        None,
    )]
    #[case::missing_configuration_value(
        &apicore::Probe {
            timeout_seconds: None,
            ..Default::default()
        },
        &settings::ProbeConfiguration {
            enforce: true,
            timeout_seconds: Some(settings::ProbeTimeConfiguration {
                minimum: Some(5),
                limit: Some(15),
            }),
            ..Default::default()
        },
        Some(ProbeError::FieldValidationError("timeoutSeconds".to_string(), PolicyValidationError::MissingValue)),
    )]
    fn test_probe_fields_validation(
        #[case] probe: &apicore::Probe,
        #[case] settings: &settings::ProbeConfiguration,
        #[case] error_message: Option<ProbeError>,
    ) {
        let result = validate_probe(probe, settings);
        if let Some(e) = error_message {
            let err = result.expect_err("probe should be invalid");
            assert_eq!(
                err,
                e,
                "probe validation did not return the expected error. Got: {:?}, expected: {:?}",
                err.to_string(),
                e.to_string()
            );
            return;
        }
        result.expect("probe should be valid");
    }

    #[test]
    fn accept_pod_with_probes() -> Result<(), ()> {
        let request_file = "test_data/pod_creation.json";
        let tc = Testcase {
            name: String::from("Valid name"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                ..Default::default()
            },
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name,
        );

        Ok(())
    }

    #[test]
    fn reject_pod_without_liveness() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_invalid_liveness.json";
        let tc = Testcase {
            name: String::from("Bad name"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {
                ..Default::default()
            },
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name,
        );

        Ok(())
    }

    #[test]
    fn reject_pod_without_readiness() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_invalid_readiness.json";
        let tc = Testcase {
            name: String::from("Bad name"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {
                ..Default::default()
            },
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name,
        );

        Ok(())
    }

    #[test]
    fn accept_pod_init_containers_with_probes() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_init_container.json";
        let tc = Testcase {
            name: String::from("Valid name"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                ..Default::default()
            },
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name,
        );

        Ok(())
    }

    #[test]
    fn reject_pod_init_containers_without_liveness() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_invalid_liveness_init_container.json";
        let tc = Testcase {
            name: String::from("Bad name"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {
                ..Default::default()
            },
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name,
        );

        Ok(())
    }

    #[test]
    fn reject_pod_init_containers_without_readiness() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_invalid_readiness_init_container.json";
        let tc = Testcase {
            name: String::from("Bad name"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {
                ..Default::default()
            },
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name,
        );

        Ok(())
    }
}
