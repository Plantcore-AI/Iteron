use super::{
    IMPLEMENTATION_PROTOCOL, ImplementationRequest, ImplementationRequestEnvelope,
    ImplementationResponse, ImplementationRuntime, ImplementationRuntimeError,
    MAX_IMPLEMENTATION_STDIN_BYTES, Output,
};
use crate::implementation_protocol::{
    ImplementationProtocolError, MAX_IMPLEMENTATION_MESSAGE_BYTES,
    parse_implementation_observation, parse_implementation_request,
    parse_implementation_response_for,
};
use std::sync::mpsc;
use std::time::Instant;

impl ImplementationRuntime {
    pub(super) fn exchange(
        &mut self,
        operation: &'static str,
        payload: ImplementationRequest,
        end: Instant,
    ) -> Result<ImplementationResponse, ImplementationRuntimeError> {
        let request = self.envelope(payload);
        let frame =
            serde_json::to_vec(&request).map_err(|error| ImplementationRuntimeError::Io {
                operation: "serialize",
                message: error.to_string(),
            })?;
        if let Err(error) = parse_implementation_request(&frame) {
            return self.fail(error.into());
        }
        if frame.len() + 1 > MAX_IMPLEMENTATION_MESSAGE_BYTES
            || self.stdin_bytes.saturating_add(frame.len() + 1) > MAX_IMPLEMENTATION_STDIN_BYTES
        {
            return self.fail(ImplementationRuntimeError::StdinTooLarge {
                max: MAX_IMPLEMENTATION_STDIN_BYTES,
            });
        }
        self.stdin_bytes += frame.len() + 1;
        let Some(input) = self.input.as_ref() else {
            return self.fail(ImplementationRuntimeError::ProcessExited { operation });
        };
        if input.send(super::Input::Frame(frame)).is_err() {
            return self.fail(ImplementationRuntimeError::ProcessExited { operation });
        }
        loop {
            match self.next_output(operation, end)? {
                Output::Stdout(bytes) if response_shape(&bytes) => {
                    let response = match parse_implementation_response_for(&bytes, &request) {
                        Ok(response) => response,
                        Err(error) => return self.fail(error.into()),
                    };
                    return match response.payload {
                        ImplementationResponse::Failed { code, message } => {
                            self.fail(ImplementationRuntimeError::ProviderFailed { code, message })
                        }
                        payload => Ok(payload),
                    };
                }
                Output::Stdout(bytes) => {
                    let observation = self.parse_observation(&bytes)?;
                    self.pending_observations.push_back(observation);
                }
                _ => unreachable!("next_output returns only stdout frames"),
            }
        }
    }

    fn envelope(&mut self, payload: ImplementationRequest) -> ImplementationRequestEnvelope {
        let request_id = format!("host-{}", self.next_request);
        self.next_request += 1;
        ImplementationRequestEnvelope {
            protocol: IMPLEMENTATION_PROTOCOL.to_owned(),
            request_id,
            implementation_id: self.plan.implementation_id().to_owned(),
            module: self.plan.module(),
            payload,
        }
    }

    pub(super) fn parse_observation(
        &mut self,
        bytes: &[u8],
    ) -> Result<crate::ImplementationObservationEnvelope, ImplementationRuntimeError> {
        let observation = match parse_implementation_observation(bytes) {
            Ok(value) => value,
            Err(error) => return self.fail(error.into()),
        };
        if observation.implementation_id != self.plan.implementation_id()
            || observation.module != self.plan.module()
            || self.active_run.as_deref() != Some(observation.run_id.as_str())
            || self
                .last_sequence
                .is_some_and(|last| observation.sequence <= last)
        {
            return self.fail(ImplementationProtocolError::Correlation.into());
        }
        self.evidence.observations += 1;
        self.evidence.observation_bytes += bytes.len();
        if self.evidence.observations > self.plan.evidence_limits().observations {
            return self.fail(ImplementationRuntimeError::TooManyObservations {
                max: self.plan.evidence_limits().observations,
            });
        }
        self.last_sequence = Some(observation.sequence);
        if observation.terminal {
            self.active_run = None;
            self.last_sequence = None;
            self.state = super::RuntimeState::Loaded;
        }
        Ok(observation)
    }

    pub(super) fn next_output(
        &mut self,
        operation: &'static str,
        end: Instant,
    ) -> Result<Output, ImplementationRuntimeError> {
        loop {
            let Some(remaining) = end.checked_duration_since(Instant::now()) else {
                return self.fail(ImplementationRuntimeError::Deadline { operation });
            };
            let event = match self.output.recv_timeout(remaining) {
                Ok(event) => event,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    return self.fail(ImplementationRuntimeError::Deadline { operation });
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return self.fail(ImplementationRuntimeError::ProcessExited { operation });
                }
            };
            match event {
                Output::Stdout(bytes) => {
                    self.evidence.stdout_bytes += bytes.len() + 1;
                    return Ok(Output::Stdout(bytes));
                }
                Output::Stderr(bytes) => self.evidence.stderr.extend_from_slice(&bytes),
                Output::StderrEof => self.stderr_eof = true,
                Output::StdoutEof => {
                    self.stdout_eof = true;
                    return self.fail(ImplementationRuntimeError::ProcessExited { operation });
                }
                Output::TooLarge(stream, max) => {
                    return self.fail(ImplementationRuntimeError::OutputTooLarge { stream, max });
                }
                Output::Io(operation, message) => {
                    return self.fail(ImplementationRuntimeError::Io { operation, message });
                }
            }
        }
    }
}

fn response_shape(bytes: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|value| {
            value
                .as_object()
                .map(|object| object.contains_key("request_id"))
        })
        .unwrap_or(false)
}
