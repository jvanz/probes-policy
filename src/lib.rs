use anyhow::{Result, anyhow};
use lazy_static::lazy_static;

use guest::prelude::*;
use kubewarden_policy_sdk::wapc_guest as guest;

use k8s_openapi::api::core::v1 as apicore;

extern crate kubewarden_policy_sdk as kubewarden;
use kubewarden::{logging, protocol_version_guest, request::ValidationRequest, validate_settings};

mod settings;
use settings::Settings;

use slog::{Logger, info, o, warn};

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

// This function is used to validate the probe periods configurations. It's a
// genetic function because the time values can be either i32 or i64 depending on
// the field.
fn validate_time_configuration<T>(
    time_value: Option<T>,
    settings: Option<&settings::ProbeTimeConfiguration<T>>,
) -> Result<()>
where
    T: PartialOrd + std::fmt::Display,
{
    if let Some(time_config) = settings
        && let Some(time) = time_value
    {
        if let Some(minimum) = &time_config.minimum
            && time < *minimum
        {
            return Err(anyhow!("{} is below the minimum of {}", time, minimum));
        }
        if let Some(limit) = &time_config.limit
            && time > *limit
        {
            return Err(anyhow!("{} is above the limit of {}", time, limit));
        }
    }
    Ok(())
}

// Validate all the period/threshold values from probe configuration.
fn validate_probe(
    probe: &apicore::Probe,
    probe_settings: &settings::ProbeConfiguration,
) -> Result<()> {
    validate_time_configuration(probe.period_seconds, probe_settings.period_seconds.as_ref())
        .map_err(|e| anyhow!("periodSeconds validation failed: {}", e.to_string()))?;
    validate_time_configuration(
        probe.failure_threshold,
        probe_settings.failure_threshold.as_ref(),
    )
    .map_err(|e| anyhow!("failureThreshold validation failed: {}", e.to_string()))?;
    validate_time_configuration(
        probe.success_threshold,
        probe_settings.success_threshold.as_ref(),
    )
    .map_err(|e| anyhow!("successThreshold validation failed: {}", e.to_string()))?;
    validate_time_configuration(
        probe.termination_grace_period_seconds,
        probe_settings.termination_grace_period_seconds.as_ref(),
    )
    .map_err(|e| {
        anyhow!(
            "terminationGracePeriodSeconds validation failed: {}",
            e.to_string()
        )
    })?;
    validate_time_configuration(
        probe.timeout_seconds,
        probe_settings.timeout_seconds.as_ref(),
    )
    .map_err(|e| anyhow!("timeoutSeconds validation failed: {}", e.to_string()))?;
    validate_time_configuration(
        probe.initial_delay_seconds,
        probe_settings.initial_delay_seconds.as_ref(),
    )
    .map_err(|e| anyhow!("initialDelaySeconds validation failed: {}", e.to_string()))
}

fn validate_container(container: &apicore::Container, settings: &Settings) -> Result<()> {
    if container.liveness_probe.is_none() && settings.liveness.enforce {
        info!(
            LOG_DRAIN,
            "rejecting pod";
            "container_name" => &container.name
        );
        return Err(anyhow!(
            "container {} without liveness probe is not accepted",
            &container.name
        ));
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
        return Err(anyhow!(
            "container {} without readiness probe is not accepted",
            &container.name
        ));
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
) -> Result<()> {
    if container.liveness_probe.is_none() && settings.liveness.enforce {
        info!(
            LOG_DRAIN,
            "rejecting pod";
            "container_name" => &container.name
        );
        return Err(anyhow!(
            "container {} without liveness probe is not accepted",
            &container.name
        ));
    }
    if container.readiness_probe.is_none() && settings.readiness.enforce {
        info!(
            LOG_DRAIN,
            "rejecting pod";
            "container_name" => &container.name
        );
        return Err(anyhow!(
            "container {} without readiness probe is not accepted",
            &container.name
        ));
    }
    Ok(())
}

fn validate_pod(pod: &apicore::PodSpec, settings: &Settings) -> Result<()> {
    let mut err_message = String::new();
    for container in &pod.containers {
        let container_valid = validate_container(container, settings);
        if container_valid.is_err() {
            err_message = err_message
                + &format!(
                    "container {} is invalid: {}\n",
                    container.name,
                    container_valid.unwrap_err()
                );
        }
    }
    if let Some(init_containers) = &pod.init_containers {
        for container in init_containers {
            let container_valid = validate_container(container, settings);
            if container_valid.is_err() {
                err_message = err_message
                    + &format!(
                        "init container {} is invalid: {}\n",
                        container.name,
                        container_valid.unwrap_err()
                    );
            }
        }
    }
    if let Some(ephemeral_containers) = &pod.ephemeral_containers {
        for container in ephemeral_containers {
            let container_valid = validate_ephemeral_container(container, settings);
            if container_valid.is_err() {
                err_message = err_message
                    + &format!(
                        "ephemeral container {} is invalid: {}\n",
                        container.name,
                        container_valid.unwrap_err()
                    );
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
        Some("failureThreshold validation failed: 4 is below the minimum of 5")
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
        Some("failureThreshold validation failed: 16 is above the limit of 15")
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
        Some("initialDelaySeconds validation failed: 4 is below the minimum of 5")
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
        Some("initialDelaySeconds validation failed: 16 is above the limit of 15")
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
        Some("periodSeconds validation failed: 4 is below the minimum of 5")
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
        Some("periodSeconds validation failed: 16 is above the limit of 15")
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
        Some("successThreshold validation failed: 4 is below the minimum of 5")
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
        Some("successThreshold validation failed: 16 is above the limit of 15")
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
        Some("terminationGracePeriodSeconds validation failed: 4 is below the minimum of 5")
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
        Some("terminationGracePeriodSeconds validation failed: 16 is above the limit of 15")
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
        Some("timeoutSeconds validation failed: 4 is below the minimum of 5")
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
        Some("timeoutSeconds validation failed: 16 is above the limit of 15")
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
    fn test_probe_fields_validation(
        #[case] probe: &apicore::Probe,
        #[case] settings: &settings::ProbeConfiguration,
        #[case] error_message: Option<&str>,
    ) {
        let result = validate_probe(probe, settings);
        if error_message.is_some() {
            let err = result.expect_err("probe should be invalid");
            assert_eq!(err.to_string(), error_message.unwrap());
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
