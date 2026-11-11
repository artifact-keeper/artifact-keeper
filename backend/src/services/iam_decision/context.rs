//! The explicit inputs of one decision besides the snapshot: who asks, with
//! which credential, and the trusted request context.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::services::iam_legacy_projection::{CredentialRef, SubjectRef};

/// Server-derived context of one decision. The caller resolves the client IP
/// through the trusted-proxy policy (or supplies `None` when there is no client
/// request) and samples the clock once; the evaluator never reads either itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestContext {
    pub client_ip: Option<IpAddr>,
    pub now: DateTime<Utc>,
}

impl RequestContext {
    pub fn new(client_ip: Option<IpAddr>, now: DateTime<Utc>) -> RequestContext {
        RequestContext { client_ip, now }
    }
}

/// The principal a decision is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Principal {
    User(Uuid),
    ServiceAccount(Uuid),
    /// An unauthenticated request. Guest access is an outer gate: the evaluator
    /// sees an anonymous principal only when guest access is enabled.
    Anonymous,
}

impl Principal {
    /// The subject bindings and denies name for this principal directly.
    pub fn subject(self) -> SubjectRef {
        match self {
            Principal::User(id) => SubjectRef::User(id),
            Principal::ServiceAccount(id) => SubjectRef::ServiceAccount(id),
            Principal::Anonymous => SubjectRef::Anonymous,
        }
    }

    pub fn id(self) -> Option<Uuid> {
        match self {
            Principal::User(id) | Principal::ServiceAccount(id) => Some(id),
            Principal::Anonymous => None,
        }
    }

    pub fn is_authenticated(self) -> bool {
        !matches!(self, Principal::Anonymous)
    }
}

/// A principal together with the credential it presented. A session carries no
/// ceiling and is passed as `credential: None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caller {
    pub principal: Principal,
    pub credential: Option<CredentialRef>,
}

impl Caller {
    pub fn session(principal: Principal) -> Caller {
        Caller {
            principal,
            credential: None,
        }
    }

    pub fn with_credential(principal: Principal, credential: CredentialRef) -> Caller {
        Caller {
            principal,
            credential: Some(credential),
        }
    }

    pub fn anonymous() -> Caller {
        Caller::session(Principal::Anonymous)
    }
}
