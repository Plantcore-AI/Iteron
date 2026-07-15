"""Build-only normalization for canonical repository-root documentation links.

MkDocs deliberately refuses to publish files outside ``docs_dir``. A small set
of existing, tracked project documents links to canonical generated files at the
repository root. Keep the source link correct on GitHub while rendering the same
target as an absolute repository URL in the Pages build.
"""

from __future__ import annotations

from mkdocs.structure.pages import Page


_ROOT_LINKS = {
    "../OWNERSHIP.md": "https://github.com/Plantcore-AI/core/blob/main/OWNERSHIP.md",
}


def on_page_markdown(markdown: str, *, page: Page, **_: object) -> str:
    """Rewrite only exact Markdown destinations that cannot live in docs_dir."""

    if page.file.src_uri != "maintainer-onboarding.md":
        return markdown
    for source, target in _ROOT_LINKS.items():
        markdown = markdown.replace(f"]({source})", f"]({target})")
    return markdown
