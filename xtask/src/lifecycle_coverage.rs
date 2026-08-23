use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use syn::visit::Visit as _;

const MAX_SOURCE_BYTES: usize = 2 * 1024 * 1024;

pub(crate) struct CoverageReport {
    pub(crate) registered: usize,
    pub(crate) active: usize,
    pub(crate) reserved: usize,
}

pub(crate) fn check(root: &Path) -> Result<CoverageReport> {
    let registry_path = root.join("crates/protocol/src/lifecycle/registry.rs");
    let registry = parse_rust(&registry_path)?;
    let registered = string_array(&registry, "EVENTS")?;
    let reserved = string_array(&registry, "RESERVED_EVENTS")?;
    let gate_events = string_array(&registry, "GATE_EVENTS")?
        .into_iter()
        .collect::<BTreeSet<_>>();
    if registered.len() != registered.iter().collect::<BTreeSet<_>>().len() {
        bail!("lifecycle EVENTS contains duplicate identifiers");
    }
    if reserved.len() != reserved.iter().collect::<BTreeSet<_>>().len() {
        bail!("lifecycle RESERVED_EVENTS contains duplicate identifiers");
    }
    let unknown_reserved = reserved
        .iter()
        .filter(|event| !registered.contains(event))
        .cloned()
        .collect::<Vec<_>>();
    if !unknown_reserved.is_empty() {
        bail!("reserved lifecycle identifiers are not registered: {unknown_reserved:?}");
    }
    let unknown_gates = gate_events
        .iter()
        .filter(|event| !registered.contains(event))
        .cloned()
        .collect::<Vec<_>>();
    if !unknown_gates.is_empty() {
        bail!("Gate lifecycle identifiers are not registered: {unknown_gates:?}");
    }

    let mut callables = Vec::new();
    let mut files = Vec::new();
    collect_rust_files(&root.join("crates"), &mut files)?;
    for path in files {
        if excluded_source(root, &path) {
            continue;
        }
        let source = read_source(&path)?;
        let syntax =
            syn::parse_file(&source).with_context(|| format!("cannot parse {}", path.display()))?;
        collect_callables(&syntax, &mut callables);
    }
    let coverage = analyze_callables(&callables);

    let registered_set = registered.iter().cloned().collect::<BTreeSet<_>>();
    let unknown_emitted = coverage
        .called
        .difference(&registered_set)
        .cloned()
        .collect::<Vec<_>>();
    if !unknown_emitted.is_empty() {
        bail!("production lifecycle calls use unregistered identifiers: {unknown_emitted:?}");
    }

    let active = registered
        .iter()
        .filter(|event| !reserved.contains(event))
        .cloned()
        .collect::<BTreeSet<_>>();
    let missing = active
        .iter()
        .filter(|event| !has_executable_route(event, &gate_events, &coverage))
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        bail!("active lifecycle events without an executable Hook route: {missing:?}");
    }
    let produced_reserved = reserved
        .iter()
        .filter(|event| coverage.called.contains(event.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if !produced_reserved.is_empty() {
        bail!(
            "reserved lifecycle events now have a production path; activate and classify them: {produced_reserved:?}"
        );
    }

    Ok(CoverageReport {
        registered: registered.len(),
        active: active.len(),
        reserved: reserved.len(),
    })
}

#[derive(Clone, Debug, Default)]
struct Sources {
    literals: BTreeSet<String>,
    variables: BTreeSet<String>,
}

impl Sources {
    fn extend(&mut self, other: Self) {
        self.literals.extend(other.literals);
        self.variables.extend(other.variables);
    }
}

#[derive(Clone, Debug, Default)]
struct Origins {
    literals: BTreeSet<String>,
    parameters: BTreeSet<usize>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CallableKey {
    name: String,
    arity: usize,
}

impl CallableKey {
    fn new(name: impl Into<String>, arity: usize) -> Self {
        Self {
            name: name.into(),
            arity,
        }
    }
}

#[derive(Clone, Debug)]
struct CallSite {
    callee: CallableKey,
    arguments: Vec<Sources>,
}

#[derive(Clone, Debug)]
struct CallableFacts {
    key: CallableKey,
    parameters: BTreeMap<String, usize>,
    bindings: BTreeMap<String, Sources>,
    calls: Vec<CallSite>,
    raw_emits: Vec<Sources>,
    direct_routes: Vec<Sources>,
}

impl CallableFacts {
    fn new(key: CallableKey, parameters: BTreeMap<String, usize>) -> Self {
        Self {
            key,
            parameters,
            bindings: BTreeMap::new(),
            calls: Vec::new(),
            raw_emits: Vec::new(),
            direct_routes: Vec::new(),
        }
    }

    fn bind(&mut self, pattern: &syn::Pat, sources: Sources) {
        let mut identifiers = Vec::new();
        let mut visitor = PatternIdentifierVisitor {
            identifiers: &mut identifiers,
        };
        visitor.visit_pat(pattern);
        for identifier in identifiers {
            self.bindings
                .entry(identifier)
                .or_default()
                .extend(sources.clone());
        }
    }

    fn resolve(&self, sources: &Sources) -> Origins {
        let mut origins = Origins {
            literals: sources.literals.clone(),
            parameters: BTreeSet::new(),
        };
        let mut visiting = BTreeSet::new();
        for variable in &sources.variables {
            self.resolve_variable(variable, &mut visiting, &mut origins);
        }
        origins
    }

    fn resolve_variable(
        &self,
        variable: &str,
        visiting: &mut BTreeSet<String>,
        origins: &mut Origins,
    ) {
        if let Some(parameter) = self.parameters.get(variable) {
            origins.parameters.insert(*parameter);
        }
        if !visiting.insert(variable.to_owned()) {
            return;
        }
        if let Some(sources) = self.bindings.get(variable) {
            origins.literals.extend(sources.literals.iter().cloned());
            for dependency in &sources.variables {
                self.resolve_variable(dependency, visiting, origins);
            }
        }
        visiting.remove(variable);
    }
}

#[derive(Debug, Default)]
struct SourceCoverage {
    called: BTreeSet<String>,
    async_routed: BTreeSet<String>,
    gate_routed: BTreeSet<String>,
}

fn has_executable_route(
    event: &str,
    gate_events: &BTreeSet<String>,
    coverage: &SourceCoverage,
) -> bool {
    if gate_events.contains(event) {
        coverage.gate_routed.contains(event)
    } else {
        coverage.async_routed.contains(event)
    }
}

/// Fixed synchronous Gate sinks. The values are argument indexes after the method receiver; arity
/// is included so an unrelated overload cannot acquire a route merely by sharing a name.
fn gate_route_sinks() -> BTreeMap<CallableKey, BTreeSet<usize>> {
    [
        ("brokered_lifecycle_gate", 3, 1),
        ("brokered_lifecycle_gate_decision", 3, 1),
        ("brokered_child_lifecycle_gate", 4, 1),
        ("run_lifecycle_gate", 4, 1),
    ]
    .into_iter()
    .map(|(name, arity, event)| (CallableKey::new(name, arity), BTreeSet::from([event])))
    .collect()
}

/// Fixed Observe/Augment sink: the dispatcher's bounded queue primitive. Keeping this disjoint
/// from Gate sinks prevents an async dispatcher call from proving a synchronous veto path that
/// production `LifecycleHookDispatcher::dispatch` deliberately rejects.
fn async_route_sinks() -> BTreeMap<CallableKey, BTreeSet<usize>> {
    [
        // `LifecycleHookDispatcher::dispatch` delegates to this bounded `try_send` helper. The
        // worker's circuit-open notification owns only a weak sender, so it must enter at this
        // same sink without manufacturing a second public dispatcher.
        ("enqueue", 4, 3),
    ]
    .into_iter()
    .map(|(name, arity, event)| (CallableKey::new(name, arity), BTreeSet::from([event])))
    .collect()
}

fn analyze_callables(callables: &[CallableFacts]) -> SourceCoverage {
    let async_routed = analyze_routes(callables, async_route_sinks(), true);
    let gate_routed = analyze_routes(callables, gate_route_sinks(), false);
    let routed = async_routed
        .union(&gate_routed)
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut called = BTreeSet::new();
    // Keep unknown-id and reserved-production detection at least as strict as the old check: raw
    // emitter calls and established lifecycle APIs count even when their Hook route is broken.
    for callable in callables {
        for emit in &callable.raw_emits {
            called.extend(callable.resolve(emit).literals);
        }
        for call in &callable.calls {
            let Some(event_arguments) = legacy_event_arguments(&call.callee) else {
                continue;
            };
            for event_argument in event_arguments {
                if let Some(argument) = call.arguments.get(event_argument) {
                    called.extend(callable.resolve(argument).literals);
                }
            }
        }
    }
    called.extend(routed.iter().cloned());
    SourceCoverage {
        called,
        async_routed,
        gate_routed,
    }
}

fn analyze_routes(
    callables: &[CallableFacts],
    mut routes: BTreeMap<CallableKey, BTreeSet<usize>>,
    include_direct_routes: bool,
) -> BTreeSet<String> {
    let mut routed = BTreeSet::new();
    let mut callers = BTreeMap::<CallableKey, Vec<(usize, usize)>>::new();
    for (callable_index, callable) in callables.iter().enumerate() {
        for (call_index, call) in callable.calls.iter().enumerate() {
            callers
                .entry(call.callee.clone())
                .or_default()
                .push((callable_index, call_index));
        }
    }

    let mut queued = routes.keys().cloned().collect::<BTreeSet<_>>();
    let mut work = queued.iter().cloned().collect::<VecDeque<_>>();

    if include_direct_routes {
        for callable in callables {
            for direct in &callable.direct_routes {
                let origins = callable.resolve(direct);
                routed.extend(origins.literals);
                let routed_parameters = routes.entry(callable.key.clone()).or_default();
                let previous = routed_parameters.len();
                routed_parameters.extend(origins.parameters);
                if routed_parameters.len() != previous && queued.insert(callable.key.clone()) {
                    work.push_back(callable.key.clone());
                }
            }
        }
    }

    // Propagate only when a callee first becomes a route or gains a newly-routed parameter. The
    // former whole-graph fixed-point scan was correct but quadratic in helper-chain depth under a
    // debug xtask build, making the honesty gate itself take minutes on this workspace.
    while let Some(callee) = work.pop_front() {
        queued.remove(&callee);
        let Some(event_arguments) = routes.get(&callee).cloned() else {
            continue;
        };
        let Some(call_sites) = callers.get(&callee) else {
            continue;
        };
        for &(callable_index, call_index) in call_sites {
            let callable = &callables[callable_index];
            let call = &callable.calls[call_index];
            let mut routed_parameters = BTreeSet::new();
            for event_argument in &event_arguments {
                let Some(argument) = call.arguments.get(*event_argument) else {
                    continue;
                };
                let origins = callable.resolve(argument);
                routed.extend(origins.literals);
                routed_parameters.extend(origins.parameters);
            }
            let route = routes.entry(callable.key.clone()).or_default();
            let previous = route.len();
            route.extend(routed_parameters);
            if route.len() != previous && queued.insert(callable.key.clone()) {
                work.push_back(callable.key.clone());
            }
        }
    }

    routed
}

fn legacy_event_arguments(key: &CallableKey) -> Option<BTreeSet<usize>> {
    let event_argument = match key.name.as_str() {
        "emit"
        | "emit_lifecycle"
        | "lifecycle_event"
        | "lifecycle_event_with_correlation"
        | "child_lifecycle_event"
        | "tool_lifecycle_event"
        | "record_lifecycle"
        | "record_workflow_lifecycle"
        | "record_job_lifecycle"
        | "record_workflow_child_lifecycle" => 0,
        "brokered_lifecycle_gate"
        | "brokered_lifecycle_gate_decision"
        | "brokered_child_lifecycle_gate"
        | "run_lifecycle_gate" => 1,
        _ => return None,
    };
    (event_argument < key.arity).then(|| BTreeSet::from([event_argument]))
}

fn collect_callables(file: &syn::File, callables: &mut Vec<CallableFacts>) {
    let mut collector = DefinitionVisitor { callables };
    collector.visit_file(file);
}

struct DefinitionVisitor<'a> {
    callables: &'a mut Vec<CallableFacts>,
}

impl<'ast> syn::visit::Visit<'ast> for DefinitionVisitor<'_> {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        analyze_callable(
            node.sig.ident.to_string(),
            &node.sig.inputs,
            node.block.as_ref(),
            self.callables,
        );
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        analyze_callable(
            node.sig.ident.to_string(),
            &node.sig.inputs,
            &node.block,
            self.callables,
        );
    }
}

fn analyze_callable(
    name: String,
    inputs: &syn::punctuated::Punctuated<syn::FnArg, syn::Token![,]>,
    block: &syn::Block,
    callables: &mut Vec<CallableFacts>,
) {
    let mut parameters = BTreeMap::new();
    let mut arity = 0usize;
    for input in inputs {
        let syn::FnArg::Typed(input) = input else {
            continue;
        };
        let mut identifiers = Vec::new();
        let mut visitor = PatternIdentifierVisitor {
            identifiers: &mut identifiers,
        };
        visitor.visit_pat(input.pat.as_ref());
        for identifier in identifiers {
            parameters.insert(identifier, arity);
        }
        arity = arity.saturating_add(1);
    }
    let mut facts = CallableFacts::new(CallableKey::new(name, arity), parameters);
    let mut nested = Vec::new();
    let mut scanner = CallableVisitor {
        facts: &mut facts,
        nested: &mut nested,
    };
    scanner.visit_block(block);
    callables.push(facts);
    callables.extend(nested);
}

fn analyze_closure(name: String, closure: &syn::ExprClosure, callables: &mut Vec<CallableFacts>) {
    let mut parameters = BTreeMap::new();
    for (index, input) in closure.inputs.iter().enumerate() {
        let mut identifiers = Vec::new();
        let mut visitor = PatternIdentifierVisitor {
            identifiers: &mut identifiers,
        };
        visitor.visit_pat(input);
        for identifier in identifiers {
            parameters.insert(identifier, index);
        }
    }
    let mut facts = CallableFacts::new(CallableKey::new(name, closure.inputs.len()), parameters);
    let mut nested = Vec::new();
    let mut scanner = CallableVisitor {
        facts: &mut facts,
        nested: &mut nested,
    };
    scanner.visit_expr(closure.body.as_ref());
    callables.push(facts);
    callables.extend(nested);
}

struct CallableVisitor<'a> {
    facts: &'a mut CallableFacts,
    nested: &'a mut Vec<CallableFacts>,
}

impl<'ast> syn::visit::Visit<'ast> for CallableVisitor<'_> {
    fn visit_local(&mut self, node: &'ast syn::Local) {
        let Some(initializer) = &node.init else {
            return;
        };
        if let syn::Expr::Closure(closure) = initializer.expr.as_ref()
            && let Some(name) = single_pattern_identifier(&node.pat)
        {
            analyze_closure(name, closure, self.nested);
            return;
        }
        let sources = emitted_event_sources(initializer.expr.as_ref())
            .unwrap_or_else(|| sources_of(initializer.expr.as_ref()));
        self.facts.bind(&node.pat, sources);
        syn::visit::visit_local(self, node);
    }

    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        self.facts.bind(&node.pat, sources_of(node.expr.as_ref()));
        syn::visit::visit_expr_for_loop(self, node);
    }

    fn visit_expr_let(&mut self, node: &'ast syn::ExprLet) {
        self.facts.bind(&node.pat, sources_of(node.expr.as_ref()));
        syn::visit::visit_expr_let(self, node);
    }

    fn visit_expr_assign(&mut self, node: &'ast syn::ExprAssign) {
        if let syn::Expr::Path(path) = node.left.as_ref()
            && let Some(identifier) = single_path_identifier(path)
        {
            self.facts
                .bindings
                .entry(identifier)
                .or_default()
                .extend(sources_of(node.right.as_ref()));
        }
        syn::visit::visit_expr_assign(self, node);
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        let mut emit_bindings = Vec::new();
        let mut visitor = EmitBindingVisitor {
            bindings: &mut emit_bindings,
        };
        visitor.visit_expr(node.cond.as_ref());
        for (event_variable, sources) in emit_bindings {
            if block_dispatches(&node.then_branch, &event_variable) {
                self.facts.direct_routes.push(sources);
            }
        }
        syn::visit::visit_expr_if(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let arguments = node.args.iter().map(sources_of).collect::<Vec<_>>();
        if node.method == "emit"
            && let Some(event) = arguments.first()
        {
            self.facts.raw_emits.push(event.clone());
        }
        if matches!(node.method.to_string().as_str(), "extend" | "push")
            && let syn::Expr::Path(receiver) = node.receiver.as_ref()
            && let Some(identifier) = single_path_identifier(receiver)
            && let Some(values) = arguments.first()
        {
            self.facts
                .bindings
                .entry(identifier)
                .or_default()
                .extend(values.clone());
        }
        self.facts.calls.push(CallSite {
            callee: CallableKey::new(node.method.to_string(), arguments.len()),
            arguments,
        });
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        let Some(name) = called_path_name(node.func.as_ref()) else {
            syn::visit::visit_expr_call(self, node);
            return;
        };
        let arguments = node.args.iter().map(sources_of).collect::<Vec<_>>();
        self.facts.calls.push(CallSite {
            callee: CallableKey::new(name, arguments.len()),
            arguments,
        });
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        collect_macro_calls(node.tokens.clone(), &mut self.facts.calls);
        syn::visit::visit_macro(self, node);
    }
}

struct PatternIdentifierVisitor<'a> {
    identifiers: &'a mut Vec<String>,
}

impl<'ast> syn::visit::Visit<'ast> for PatternIdentifierVisitor<'_> {
    fn visit_pat_ident(&mut self, node: &'ast syn::PatIdent) {
        self.identifiers.push(node.ident.to_string());
        syn::visit::visit_pat_ident(self, node);
    }
}

fn sources_of(expression: &syn::Expr) -> Sources {
    let mut sources = Sources::default();
    collect_expression_sources(expression, &mut sources);
    sources
}

fn emitted_event_sources(expression: &syn::Expr) -> Option<Sources> {
    let syn::Expr::MethodCall(call) = expression else {
        return None;
    };
    (call.method == "emit").then(|| call.args.first().map_or_else(Sources::default, sources_of))
}

/// Extract only value-flow forms that can carry a lifecycle identifier. The definition visitor
/// already reaches every nested call separately, so walking arbitrary call payloads again here is
/// both unnecessary and quadratic on large runtime functions.
fn collect_expression_sources(expression: &syn::Expr, sources: &mut Sources) {
    match expression {
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(value),
            ..
        }) => {
            let value = value.value();
            if looks_like_lifecycle_id(&value) {
                sources.literals.insert(value);
            }
        }
        syn::Expr::Path(path) => {
            if let Some(identifier) = single_path_identifier(path) {
                sources.variables.insert(identifier);
            }
        }
        syn::Expr::Array(array) => {
            for element in &array.elems {
                collect_expression_sources(element, sources);
            }
        }
        syn::Expr::Tuple(tuple) => {
            for element in &tuple.elems {
                collect_expression_sources(element, sources);
            }
        }
        syn::Expr::Reference(reference) => {
            collect_expression_sources(reference.expr.as_ref(), sources)
        }
        syn::Expr::Paren(paren) => collect_expression_sources(paren.expr.as_ref(), sources),
        syn::Expr::Group(group) => collect_expression_sources(group.expr.as_ref(), sources),
        syn::Expr::Cast(cast) => collect_expression_sources(cast.expr.as_ref(), sources),
        syn::Expr::Await(awaited) => collect_expression_sources(awaited.base.as_ref(), sources),
        syn::Expr::Try(tried) => collect_expression_sources(tried.expr.as_ref(), sources),
        syn::Expr::Match(matched) => {
            for arm in &matched.arms {
                collect_expression_sources(arm.body.as_ref(), sources);
            }
        }
        syn::Expr::If(conditional) => {
            collect_block_sources(&conditional.then_branch, sources);
            if let Some((_, alternate)) = &conditional.else_branch {
                collect_expression_sources(alternate.as_ref(), sources);
            }
        }
        syn::Expr::Block(block) => collect_block_sources(&block.block, sources),
        syn::Expr::Macro(expression) => {
            collect_token_literals(expression.mac.tokens.clone(), &mut sources.literals)
        }
        // Constructors commonly wrap a match/if-let source. Arbitrary function and method call
        // payloads are intentionally opaque: their own call site is analyzed independently.
        syn::Expr::Call(call)
            if called_path_name(call.func.as_ref())
                .is_some_and(|name| matches!(name.as_str(), "Some" | "Ok" | "Err")) =>
        {
            for argument in &call.args {
                collect_expression_sources(argument, sources);
            }
        }
        _ => {}
    }
}

fn collect_block_sources(block: &syn::Block, sources: &mut Sources) {
    for statement in &block.stmts {
        match statement {
            syn::Stmt::Local(local) => {
                if let Some(initializer) = &local.init {
                    collect_expression_sources(initializer.expr.as_ref(), sources);
                    if let Some((_, diverge)) = &initializer.diverge {
                        collect_expression_sources(diverge.as_ref(), sources);
                    }
                }
            }
            syn::Stmt::Expr(expression, _) => collect_expression_sources(expression, sources),
            syn::Stmt::Item(_) | syn::Stmt::Macro(_) => {}
        }
    }
}

fn collect_token_literals(tokens: proc_macro2::TokenStream, literals: &mut BTreeSet<String>) {
    for token in tokens {
        match token {
            proc_macro2::TokenTree::Group(group) => {
                collect_token_literals(group.stream(), literals)
            }
            proc_macro2::TokenTree::Literal(literal) => {
                if let Ok(value) = syn::parse_str::<syn::LitStr>(&literal.to_string()) {
                    let value = value.value();
                    if looks_like_lifecycle_id(&value) {
                        literals.insert(value);
                    }
                }
            }
            _ => {}
        }
    }
}

fn collect_macro_calls(tokens: proc_macro2::TokenStream, calls: &mut Vec<CallSite>) {
    let tokens = tokens.into_iter().collect::<Vec<_>>();
    for (index, token) in tokens.iter().enumerate() {
        if let proc_macro2::TokenTree::Group(group) = token {
            collect_macro_calls(group.stream(), calls);
        }
        let proc_macro2::TokenTree::Ident(callee) = token else {
            continue;
        };
        let Some(proc_macro2::TokenTree::Group(arguments)) = tokens.get(index.saturating_add(1))
        else {
            continue;
        };
        if arguments.delimiter() != proc_macro2::Delimiter::Parenthesis {
            continue;
        }
        let arguments = split_macro_arguments(arguments.stream());
        calls.push(CallSite {
            callee: CallableKey::new(callee.to_string(), arguments.len()),
            arguments,
        });
    }
}

fn split_macro_arguments(tokens: proc_macro2::TokenStream) -> Vec<Sources> {
    let tokens = tokens.into_iter().collect::<Vec<_>>();
    if tokens.is_empty() {
        return Vec::new();
    }
    let mut arguments = Vec::new();
    let mut current = proc_macro2::TokenStream::new();
    for token in tokens {
        if matches!(&token, proc_macro2::TokenTree::Punct(punct) if punct.as_char() == ',') {
            if !current.is_empty() {
                arguments.push(sources_from_tokens(current));
            }
            current = proc_macro2::TokenStream::new();
        } else {
            current.extend(std::iter::once(token));
        }
    }
    if !current.is_empty() {
        arguments.push(sources_from_tokens(current));
    }
    arguments
}

fn sources_from_tokens(tokens: proc_macro2::TokenStream) -> Sources {
    let mut sources = Sources::default();
    collect_token_sources(tokens, &mut sources);
    sources
}

fn collect_token_sources(tokens: proc_macro2::TokenStream, sources: &mut Sources) {
    for token in tokens {
        match token {
            proc_macro2::TokenTree::Group(group) => collect_token_sources(group.stream(), sources),
            proc_macro2::TokenTree::Ident(identifier) => {
                sources.variables.insert(identifier.to_string());
            }
            proc_macro2::TokenTree::Literal(literal) => {
                if let Ok(value) = syn::parse_str::<syn::LitStr>(&literal.to_string()) {
                    let value = value.value();
                    if looks_like_lifecycle_id(&value) {
                        sources.literals.insert(value);
                    }
                }
            }
            proc_macro2::TokenTree::Punct(_) => {}
        }
    }
}

struct EmitBindingVisitor<'a> {
    bindings: &'a mut Vec<(String, Sources)>,
}

impl<'ast> syn::visit::Visit<'ast> for EmitBindingVisitor<'_> {
    fn visit_expr_let(&mut self, node: &'ast syn::ExprLet) {
        let syn::Expr::MethodCall(call) = node.expr.as_ref() else {
            syn::visit::visit_expr_let(self, node);
            return;
        };
        if call.method == "emit"
            && let Some(event) = call.args.first()
        {
            let sources = sources_of(event);
            let mut identifiers = Vec::new();
            let mut visitor = PatternIdentifierVisitor {
                identifiers: &mut identifiers,
            };
            visitor.visit_pat(node.pat.as_ref());
            self.bindings.extend(
                identifiers
                    .into_iter()
                    .map(|identifier| (identifier, sources.clone())),
            );
        }
        syn::visit::visit_expr_let(self, node);
    }
}

struct DispatchVisitor<'a> {
    event_variable: &'a str,
    dispatched: bool,
}

impl<'ast> syn::visit::Visit<'ast> for DispatchVisitor<'_> {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == "dispatch"
            && receiver_is_dispatcher(node.receiver.as_ref())
            && node
                .args
                .first()
                .is_some_and(|argument| expression_is_variable(argument, self.event_variable))
        {
            self.dispatched = true;
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Some(name) = called_path_name(node.func.as_ref()) {
            let event_argument = match name.as_str() {
                "dispatch_lifecycle_hook" => 1,
                "enqueue" => 3,
                _ => usize::MAX,
            };
            if node
                .args
                .iter()
                .nth(event_argument)
                .is_some_and(|argument| expression_is_variable(argument, self.event_variable))
            {
                self.dispatched = true;
            }
        }
        syn::visit::visit_expr_call(self, node);
    }
}

fn block_dispatches(block: &syn::Block, event_variable: &str) -> bool {
    let mut visitor = DispatchVisitor {
        event_variable,
        dispatched: false,
    };
    visitor.visit_block(block);
    visitor.dispatched
}

fn receiver_is_dispatcher(expression: &syn::Expr) -> bool {
    match expression {
        syn::Expr::Path(path) => {
            single_path_identifier(path).is_some_and(|identifier| identifier == "dispatcher")
        }
        syn::Expr::Reference(reference) => receiver_is_dispatcher(reference.expr.as_ref()),
        syn::Expr::Paren(paren) => receiver_is_dispatcher(paren.expr.as_ref()),
        _ => false,
    }
}

fn expression_is_variable(expression: &syn::Expr, variable: &str) -> bool {
    matches!(expression, syn::Expr::Path(path) if single_path_identifier(path).as_deref() == Some(variable))
}

fn called_path_name(expression: &syn::Expr) -> Option<String> {
    let syn::Expr::Path(path) = expression else {
        return None;
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

fn single_path_identifier(path: &syn::ExprPath) -> Option<String> {
    (path.qself.is_none() && path.path.segments.len() == 1).then(|| {
        path.path
            .segments
            .first()
            .expect("one segment")
            .ident
            .to_string()
    })
}

fn single_pattern_identifier(pattern: &syn::Pat) -> Option<String> {
    match pattern {
        syn::Pat::Ident(identifier) => Some(identifier.ident.to_string()),
        syn::Pat::Type(typed) => single_pattern_identifier(typed.pat.as_ref()),
        _ => None,
    }
}

fn looks_like_lifecycle_id(value: &str) -> bool {
    const DOMAINS: [&str; 15] = [
        "context.",
        "memory.",
        "submission.",
        "queue.",
        "steer.",
        "cancel.",
        "drain.",
        "control.",
        "tool.",
        "process.",
        "background.",
        "model.",
        "workflow.",
        "session.",
        "verification.",
    ];
    DOMAINS.iter().any(|domain| value.starts_with(domain))
        || value.starts_with("checkpoint.")
        || value.starts_with("replay.")
        || value.starts_with("hook.")
        || value.starts_with("exporter.")
}

fn collect_rust_files(directory: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(directory).with_context(|| {
        format!(
            "cannot inspect lifecycle source directory {}",
            directory.display()
        )
    })? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_rust_files(&path, files)?;
        } else if file_type.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
    Ok(())
}

fn excluded_source(root: &Path, path: &Path) -> bool {
    let relative = path.strip_prefix(root).unwrap_or(path);
    let rendered = relative.to_string_lossy();
    rendered == "crates/protocol/src/lifecycle/registry.rs"
        || rendered.starts_with("crates/obs/src/otel/")
        || rendered.contains("/tests/")
        || rendered.ends_with("/tests.rs")
        || rendered.ends_with("_tests.rs")
}

fn parse_rust(path: &Path) -> Result<syn::File> {
    let source = read_source(path)?;
    syn::parse_file(&source).with_context(|| format!("cannot parse {}", path.display()))
}

fn read_source(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    if bytes.len() > MAX_SOURCE_BYTES {
        bail!("lifecycle source {} exceeds 2 MiB", path.display());
    }
    String::from_utf8(bytes)
        .with_context(|| format!("lifecycle source {} is not UTF-8", path.display()))
}

fn string_array(file: &syn::File, name: &str) -> Result<Vec<String>> {
    let item = file.items.iter().find_map(|item| match item {
        syn::Item::Const(item) if item.ident == name => Some(item),
        _ => None,
    });
    let Some(item) = item else {
        bail!("lifecycle registry does not declare {name}");
    };
    let syn::Expr::Array(array) = item.expr.as_ref() else {
        bail!("lifecycle registry {name} is not a literal array");
    };
    array
        .elems
        .iter()
        .map(|expression| match expression {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(value),
                ..
            }) => Ok(value.value()),
            _ => bail!("lifecycle registry {name} contains a non-string expression"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_coverage(source: &str) -> SourceCoverage {
        let syntax = syn::parse_file(source).expect("fixture parses");
        let mut callables = Vec::new();
        collect_callables(&syntax, &mut callables);
        analyze_callables(&callables)
    }

    #[test]
    fn raw_emit_is_called_but_not_hook_routed() {
        let coverage = source_coverage(
            r#"
            fn owner(emitter: &Emitter) {
                let _ = emitter.emit(
                    "model.accepted",
                    correlation(),
                    payload(),
                );
            }
            "#,
        );

        assert!(coverage.called.contains("model.accepted"));
        assert!(!coverage.async_routed.contains("model.accepted"));
        assert!(!coverage.gate_routed.contains("model.accepted"));
    }

    #[test]
    fn emit_then_dispatch_and_proven_wrapper_calls_are_hook_routed() {
        let coverage = source_coverage(
            r#"
            impl Agent {
                fn lifecycle_route(&self, event_id: &str, payload: Payload) {
                    if let Ok(event) = self.emitter.emit(
                        event_id,
                        self.correlation(),
                        payload,
                    ) {
                        dispatcher.dispatch(event);
                    }
                }

                fn owner(&self) {
                    self.lifecycle_route("model.first_token", payload());
                }
            }

            fn direct(emitter: &Emitter, dispatcher: &LifecycleHookDispatcher) {
                if let Ok(event) = emitter.emit(
                    "model.first_byte",
                    correlation(),
                    payload(),
                ) {
                    dispatcher.dispatch(event);
                }
            }
            "#,
        );

        assert!(coverage.async_routed.contains("model.first_byte"));
        assert!(coverage.async_routed.contains("model.first_token"));
        assert!(coverage.gate_routed.is_empty());
    }

    #[test]
    fn routed_closure_propagates_literal_calls() {
        let coverage = source_coverage(
            r#"
            fn stream(emitter: &Emitter, dispatcher: &LifecycleHookDispatcher) {
                let emit_model_lifecycle = |event_id: &str, payload: Payload| {
                    if let Ok(event) = emitter.emit(event_id, correlation(), payload) {
                        dispatcher.dispatch(event);
                    }
                };
                emit_model_lifecycle("model.rate_limit_observed", payload());
            }
            "#,
        );

        assert!(coverage.async_routed.contains("model.rate_limit_observed"));
    }

    #[test]
    fn async_dispatch_cannot_prove_a_synchronous_gate_route() {
        let coverage = source_coverage(
            r#"
            fn wrong_for_gate(emitter: &Emitter, dispatcher: &LifecycleHookDispatcher) {
                if let Ok(event) = emitter.emit(
                    "submission.created",
                    correlation(),
                    payload(),
                ) {
                    dispatcher.dispatch(event);
                }
            }
            "#,
        );
        let gates = BTreeSet::from(["submission.created".to_owned()]);

        assert!(coverage.async_routed.contains("submission.created"));
        assert!(!coverage.gate_routed.contains("submission.created"));
        assert!(!has_executable_route(
            "submission.created",
            &gates,
            &coverage
        ));
    }

    #[test]
    fn canonical_gate_call_proves_the_gate_route() {
        let coverage = source_coverage(
            r#"
            async fn owner(execution: HookExecution<'_>, submission: SubmissionId) {
                run_lifecycle_gate(
                    execution,
                    "submission.created",
                    submission,
                    None,
                ).await;
            }
            "#,
        );
        let gates = BTreeSet::from(["submission.created".to_owned()]);

        assert!(coverage.gate_routed.contains("submission.created"));
        assert!(has_executable_route(
            "submission.created",
            &gates,
            &coverage
        ));
    }
}
