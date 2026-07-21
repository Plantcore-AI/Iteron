use anyhow::{Context, Result, bail};

#[derive(Clone, Copy)]
pub(super) enum ExpectedKind {
    Enum,
    Struct,
    Function,
}

enum ExpectedVisibility {
    Public,
    Crate,
    Super,
    Private,
}

pub(super) struct ExpectedItem {
    pub(super) kind: ExpectedKind,
    visibility: ExpectedVisibility,
    pub(super) name: String,
}

impl ExpectedItem {
    pub(super) fn from_signature(signature: &str) -> Result<Self> {
        let (visibility, item) = if let Some(item) = signature.strip_prefix("pub(crate) ") {
            (ExpectedVisibility::Crate, item)
        } else if let Some(item) = signature.strip_prefix("pub(super) ") {
            (ExpectedVisibility::Super, item)
        } else if let Some(item) = signature.strip_prefix("pub ") {
            (ExpectedVisibility::Public, item)
        } else {
            (ExpectedVisibility::Private, signature)
        };
        let (kind, declaration) = if let Some(item) = item.strip_prefix("enum ") {
            (ExpectedKind::Enum, item)
        } else if let Some(item) = item.strip_prefix("struct ") {
            (ExpectedKind::Struct, item)
        } else if let Some(item) = item.strip_prefix("fn ") {
            (ExpectedKind::Function, item)
        } else {
            bail!("unsupported schema item signature '{signature}'");
        };
        let name = declaration
            .split(|character: char| {
                character == '<'
                    || character == '{'
                    || character == '('
                    || character.is_ascii_whitespace()
            })
            .next()
            .unwrap_or_default();
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            bail!("schema item signature has an invalid identifier");
        }
        Ok(Self {
            kind,
            visibility,
            name: name.to_owned(),
        })
    }

    fn matches(&self, item: &syn::Item) -> bool {
        match (self.kind, item) {
            (ExpectedKind::Enum, syn::Item::Enum(item)) => {
                item.ident == self.name && self.visibility.matches(&item.vis)
            }
            (ExpectedKind::Struct, syn::Item::Struct(item)) => {
                item.ident == self.name
                    && matches!(item.fields, syn::Fields::Named(_))
                    && self.visibility.matches(&item.vis)
            }
            (ExpectedKind::Function, syn::Item::Fn(item)) => {
                item.sig.ident == self.name && self.visibility.matches(&item.vis)
            }
            _ => false,
        }
    }
}

impl ExpectedVisibility {
    fn matches(&self, visibility: &syn::Visibility) -> bool {
        match (self, visibility) {
            (Self::Public, syn::Visibility::Public(_))
            | (Self::Private, syn::Visibility::Inherited) => true,
            (Self::Crate, syn::Visibility::Restricted(restricted)) => {
                restricted.path.is_ident("crate")
            }
            (Self::Super, syn::Visibility::Restricted(restricted)) => {
                restricted.path.is_ident("super")
            }
            _ => false,
        }
    }
}

pub(super) fn unique_expected_item<'a>(
    file: &'a syn::File,
    expected: &ExpectedItem,
    signature: &str,
) -> Result<&'a syn::Item> {
    let mut items = file.items.iter().filter(|item| expected.matches(item));
    let item = items
        .next()
        .with_context(|| format!("schema source lacks explicit item '{signature}'"))?;
    if items.next().is_some() {
        bail!("schema source repeats explicit item '{signature}'");
    }
    Ok(item)
}
