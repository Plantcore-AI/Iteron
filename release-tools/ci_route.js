"use strict";

function classify({event, files = [], actor = "", draft = false, manual = ""}) {
  const reviewOnly = event === "pull_request_review";
  const pushMain = event === "push";
  const fullManual = event === "workflow_dispatch" && manual === "full";
  const docsManual = event === "workflow_dispatch" && manual === "docs";
  const dependenciesManual =
    event === "workflow_dispatch" && manual === "dependencies";
  const infrastructureManual =
    event === "workflow_dispatch" && manual === "infrastructure";
  const dependabot = actor === "dependabot[bot]" || actor === "app/dependabot";
  const any = (predicate) => files.some(predicate);
  const all = (predicate) => files.length > 0 && files.every(predicate);
  const cargoFile = (path) => path === "Cargo.lock" || path.endsWith("Cargo.toml");
  const docsFile = (path) =>
    path === "README.md" ||
    path === "mkdocs.yml" ||
    path === "requirements-docs.in" ||
    path === "requirements-docs.lock" ||
    path.startsWith("docs/");
  const infrastructureFile = (path) =>
    path.startsWith(".github/") ||
    path.startsWith("release-tools/") ||
    path === "install.sh" ||
    path === "CHANGELOG.md";
  const runtimeFile = (path) =>
    path.startsWith("crates/") ||
    path.startsWith("xtask/") ||
    path.endsWith(".rs") ||
    (path.endsWith("Cargo.toml") && !dependabot);

  const cargoOnly = all(cargoFile);
  const docs = !reviewOnly && (pushMain || fullManual || docsManual || any(docsFile));
  const supply =
    !reviewOnly &&
    (pushMain ||
      fullManual ||
      dependenciesManual ||
      infrastructureManual ||
      any((path) => infrastructureFile(path) || cargoFile(path)));
  const audit =
    !reviewOnly &&
    (pushMain || fullManual || dependenciesManual || any(cargoFile));
  const runtime = any(runtimeFile);
  const dependencyCheck =
    !reviewOnly &&
    (dependenciesManual || (dependabot && cargoOnly) || (draft && runtime));
  const rust =
    !reviewOnly &&
    (pushMain || fullManual || (!draft && runtime && !(dependabot && cargoOnly)));
  const boundary =
    !reviewOnly && !docsManual && !dependenciesManual
      ? true
      : !reviewOnly && (pushMain || fullManual || event.startsWith("pull_request"));
  const evolution =
    rust &&
    (pushMain || fullManual || any((path) => path.startsWith("crates/evolve/")));
  const perf = pushMain || fullManual;
  const releaseBuild = pushMain || fullManual;

  let changeClass = "metadata";
  if (reviewOnly) changeClass = "review";
  else if (pushMain || fullManual) changeClass = "full";
  else if (dependenciesManual || (dependabot && cargoOnly)) changeClass = "dependencies";
  else if (docsManual || all(docsFile)) changeClass = "docs";
  else if (infrastructureManual || all(infrastructureFile)) changeClass = "infrastructure";
  else if (runtime) changeClass = draft ? "runtime-fast" : "runtime-full";
  else if (files.length) changeClass = "mixed";

  return {
    audit,
    boundary,
    change_class: changeClass,
    dependency_check: dependencyCheck,
    docs,
    evolution,
    perf,
    release_build: releaseBuild,
    rust,
    supply,
  };
}

module.exports = {classify};
