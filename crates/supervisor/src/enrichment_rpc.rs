use std::collections::HashSet;

use discovery::{
    DiscoverySchedulerHandle, EnrichmentBatchRequest, EnrichmentDemand, EnrichmentPriority,
    MAX_ENRICHMENT_BATCH_SIZE,
};
use domain::{
    AppError, ErrorCode, ProcessInstanceKey, RequestProcessEnrichmentRequest,
    RequestProcessEnrichmentResponse,
};
use protocol::RequestEnvelope;
use protocol::names::method::PROCESS_REQUEST_ENRICHMENT;
use serde::{Serialize, Serializer};

use crate::AuthenticatedPeerRequest;

/// Closed response set for ephemeral process enrichment requests. The inner
/// DTO is serialized directly without a dispatcher-specific wire wrapper.
pub enum EnrichmentRpcResponse {
    Requested(RequestProcessEnrichmentResponse),
}

impl Serialize for EnrichmentRpcResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Requested(response) => response.serialize(serializer),
        }
    }
}

pub enum EnrichmentRpcDispatch {
    Handled(EnrichmentRpcResponse),
    NotHandled,
}

/// Typed routing for bounded, non-persistent UI enrichment demand. Transport
/// and listener ownership remain outside this dispatcher.
pub struct EnrichmentRpcDispatcher<'scheduler> {
    discovery_scheduler: &'scheduler DiscoverySchedulerHandle,
}

impl<'scheduler> EnrichmentRpcDispatcher<'scheduler> {
    pub fn new(discovery_scheduler: &'scheduler DiscoverySchedulerHandle) -> Self {
        Self {
            discovery_scheduler,
        }
    }

    pub async fn dispatch(
        &self,
        request: &AuthenticatedPeerRequest<'_>,
    ) -> Result<EnrichmentRpcDispatch, AppError> {
        let envelope = request.envelope();
        if envelope.method() != PROCESS_REQUEST_ENRICHMENT {
            return Ok(EnrichmentRpcDispatch::NotHandled);
        }
        require_ephemeral_operation(envelope)?;
        let request = decode_params(envelope)?;
        validate_request(envelope, &request)?;

        let selected_key = request.selected_process_instance_key.as_ref();
        let mut batch_requests = Vec::with_capacity(
            request.visible_process_instance_keys.len()
                + if selected_key.is_some() { 1 } else { 0 },
        );
        if let Some(instance_key) = selected_key {
            batch_requests.push(EnrichmentBatchRequest {
                instance_key: instance_key.clone(),
                priority: EnrichmentPriority::Selected,
                demand: EnrichmentDemand::MetadataAndPorts,
            });
        }
        batch_requests.extend(
            request
                .visible_process_instance_keys
                .iter()
                .filter(|instance_key| selected_key != Some(*instance_key))
                .cloned()
                .map(|instance_key| EnrichmentBatchRequest {
                    instance_key,
                    priority: EnrichmentPriority::Visible,
                    demand: EnrichmentDemand::Metadata,
                }),
        );

        let mut batches = Vec::with_capacity(2);
        let mut batch = Vec::with_capacity(MAX_ENRICHMENT_BATCH_SIZE);
        for request in batch_requests {
            batch.push(request);
            if batch.len() == MAX_ENRICHMENT_BATCH_SIZE {
                batches.push(std::mem::take(&mut batch));
            }
        }
        if !batch.is_empty() {
            batches.push(batch);
        }

        let mut response = RequestProcessEnrichmentResponse {
            visible_accepted: 0,
            selected_accepted: false,
        };
        for batch in batches {
            for result in self
                .discovery_scheduler
                .request_enrichment_batch(batch)
                .await?
            {
                match result.result {
                    Ok(_) if selected_key == Some(&result.instance_key) => {
                        response.selected_accepted = true;
                    }
                    Ok(_) => {
                        response.visible_accepted += 1;
                    }
                    Err(error) if error.code == ErrorCode::NotFound => {}
                    Err(error) => return Err(error),
                }
            }
        }

        Ok(EnrichmentRpcDispatch::Handled(
            EnrichmentRpcResponse::Requested(response),
        ))
    }
}

fn require_ephemeral_operation(envelope: &RequestEnvelope) -> Result<(), AppError> {
    if envelope.operation_id().is_none() {
        return Ok(());
    }
    Err(invalid_request(
        envelope,
        "operationId",
        "must be null for process.request_enrichment",
    ))
}

fn decode_params(envelope: &RequestEnvelope) -> Result<RequestProcessEnrichmentRequest, AppError> {
    if !has_exact_request_shape(envelope.params()) {
        return Err(invalid_request(
            envelope,
            "params",
            "must contain exactly the fields required by process.request_enrichment",
        ));
    }
    envelope
        .decode_params::<RequestProcessEnrichmentRequest>()
        .map_err(|_| {
            invalid_request(
                envelope,
                "params",
                "must contain exactly the fields required by process.request_enrichment",
            )
        })
}

fn has_exact_request_shape(value: &serde_json::Value) -> bool {
    let Some(request) = value.as_object() else {
        return false;
    };
    if request.len() != 2
        || !request.contains_key("visibleProcessInstanceKeys")
        || !request.contains_key("selectedProcessInstanceKey")
    {
        return false;
    }
    let Some(visible) = request
        .get("visibleProcessInstanceKeys")
        .and_then(serde_json::Value::as_array)
    else {
        return false;
    };
    if !visible.iter().all(has_exact_process_instance_key_shape) {
        return false;
    }
    request
        .get("selectedProcessInstanceKey")
        .is_some_and(|selected| {
            selected.is_null() || has_exact_process_instance_key_shape(selected)
        })
}

fn has_exact_process_instance_key_shape(value: &serde_json::Value) -> bool {
    value.as_object().is_some_and(|instance_key| {
        instance_key.len() == 3
            && instance_key.contains_key("bootId")
            && instance_key.contains_key("pid")
            && instance_key.contains_key("nativeStartTime")
    })
}

fn validate_request(
    envelope: &RequestEnvelope,
    request: &RequestProcessEnrichmentRequest,
) -> Result<(), AppError> {
    if request.visible_process_instance_keys.len() > MAX_ENRICHMENT_BATCH_SIZE {
        return Err(invalid_request(
            envelope,
            "visibleProcessInstanceKeys",
            "must contain at most 64 process identities",
        ));
    }

    let mut visible = HashSet::with_capacity(request.visible_process_instance_keys.len());
    for (index, instance_key) in request.visible_process_instance_keys.iter().enumerate() {
        validate_instance_key(
            envelope,
            instance_key,
            &format!("visibleProcessInstanceKeys[{index}]"),
        )?;
        if !visible.insert(instance_key) {
            return Err(invalid_request(
                envelope,
                "visibleProcessInstanceKeys",
                "must contain unique process identities",
            ));
        }
    }
    if let Some(instance_key) = request.selected_process_instance_key.as_ref() {
        validate_instance_key(envelope, instance_key, "selectedProcessInstanceKey")?;
    }
    Ok(())
}

fn validate_instance_key(
    envelope: &RequestEnvelope,
    instance_key: &ProcessInstanceKey,
    field: &str,
) -> Result<(), AppError> {
    lifecycle::validate_process_instance_key(instance_key).map_err(|error| {
        let reason = error
            .details
            .get("reason")
            .map(String::as_str)
            .unwrap_or("must be a complete canonical process identity");
        invalid_request_owned(envelope, field.to_owned(), reason.to_owned())
    })
}

fn invalid_request(
    envelope: &RequestEnvelope,
    field: &'static str,
    reason: &'static str,
) -> AppError {
    invalid_request_owned(envelope, field.to_owned(), reason.to_owned())
}

fn invalid_request_owned(envelope: &RequestEnvelope, field: String, reason: String) -> AppError {
    let mut error = AppError::new(
        ErrorCode::InvalidArgument,
        "process enrichment request does not match the registered method contract",
    );
    error.operation_id = envelope.operation_id().map(str::to_owned);
    error.details.insert("field".into(), field);
    error
        .details
        .insert("method".into(), envelope.method().to_owned());
    error.details.insert("reason".into(), reason);
    error
}
