use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    pub schema_version: u32,
    pub enforcement: Enforcement,
    pub people: Vec<Person>,
    pub boundaries: Vec<Boundary>,
    pub overlays: Vec<Overlay>,
    pub cargo_policy: CargoPolicy,
    pub generated: Generated,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enforcement {
    pub mode: String,
    pub project_owner: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Person {
    pub id: String,
    pub kind: String,
    pub role: String,
    pub display: String,
    pub github: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Boundary {
    pub id: String,
    pub title: String,
    pub summary: String,
    pub status: String,
    pub risk: String,
    pub primary: Option<String>,
    #[serde(default)]
    pub reviewers: Vec<String>,
    pub paths: Vec<PathClaim>,
    #[serde(default)]
    pub contracts: Vec<String>,
    #[serde(default)]
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Overlay {
    pub id: String,
    pub title: String,
    pub summary: String,
    pub status: String,
    #[serde(default)]
    pub reviewers: Vec<String>,
    pub requires_independent_review: bool,
    pub paths: Vec<PathClaim>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathClaim {
    pub kind: String,
    pub path: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CargoPolicy {
    pub mode: String,
    pub packages: BTreeMap<String, DependencyKinds>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DependencyKinds {
    #[serde(default)]
    pub normal: Vec<String>,
    #[serde(default)]
    pub dev: Vec<String>,
    #[serde(default)]
    pub build: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Generated {
    pub ownership: String,
    pub codeowners: String,
}
