"""OAuth proxy extensions and configuration helpers."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any

from fastmcp.server.auth.oauth_proxy import OAuthProxy
from fastmcp.server.auth.redirect_validation import validate_redirect_uri
from mcp.server.auth.provider import OAuthClientInformationFull

logger = logging.getLogger("mcp-atlassian.server.oauth_proxy")


def _normalize_list(values: Iterable[str] | None) -> list[str] | None:
    if values is None:
        return None
    return [value.strip() for value in values if value and value.strip()]


def parse_env_list(raw: str | None) -> list[str] | None:
    if raw is None:
        return None
    if not raw.strip():
        return []
    normalized = raw.replace(",", " ")
    return [item.strip() for item in normalized.split() if item.strip()]


class HardenedOAuthProxy(OAuthProxy):
    """OAuthProxy with stricter DCR controls for grants and scopes."""

    def __init__(
        self,
        *,
        allowed_grant_types: list[str] | None = None,
        forced_scopes: list[str] | None = None,
        strip_resource_from_upstream: bool = False,
        allowed_client_redirect_uris: list[str] | None = None,
        **kwargs: object,
    ) -> None:
        super().__init__(
            allowed_client_redirect_uris=allowed_client_redirect_uris, **kwargs
        )
        self._allowed_grant_types = _normalize_list(allowed_grant_types)
        self._forced_scopes = _normalize_list(forced_scopes)
        self._strip_resource_from_upstream = strip_resource_from_upstream
        self._allowed_redirect_uris = allowed_client_redirect_uris

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        # Reject clients whose redirect URIs don't match allowed patterns.
        # FastMCP's base register_client accepts any URI and only validates
        # later with a fallback that bypasses the restriction.
        if self._allowed_redirect_uris is not None and client_info.redirect_uris:
            for uri in client_info.redirect_uris:
                if not validate_redirect_uri(
                    redirect_uri=uri,
                    allowed_patterns=self._allowed_redirect_uris,
                ):
                    logger.warning(
                        "DCR rejected: redirect_uri %s not in allowed patterns %s",
                        uri,
                        self._allowed_redirect_uris,
                    )
                    raise ValueError(
                        f"redirect_uri {uri} is not allowed by server policy"
                    )

        updates: dict[str, object] = {"response_types": ["code"]}

        if self._allowed_grant_types is not None:
            requested = list(client_info.grant_types or [])
            filtered = [gt for gt in requested if gt in self._allowed_grant_types]
            if requested and set(requested) - set(filtered):
                logger.warning(
                    "DCR requested unsupported grant types %s; enforcing %s",
                    sorted(set(requested) - set(filtered)),
                    self._allowed_grant_types,
                )
            if not filtered:
                filtered = list(self._allowed_grant_types)
            updates["grant_types"] = filtered

        if self._forced_scopes is not None:
            forced_scope = " ".join(self._forced_scopes).strip()
            updates["scope"] = forced_scope or None
            if client_info.scope and client_info.scope != forced_scope:
                logger.warning(
                    "DCR requested scope '%s'; enforcing '%s'",
                    client_info.scope,
                    forced_scope,
                )

        client_info = client_info.model_copy(update=updates)
        await super().register_client(client_info)

    def _build_upstream_authorize_url(
        self, txn_id: str, transaction: dict[str, Any]
    ) -> str:
        """Build upstream authorize URL with Atlassian-specific adjustments.

        Two fixes applied here:

        1. **Strip resource**: Atlassian Cloud does not support RFC 8707
           resource indicators. When an MCP client sends a ``resource``
           parameter, FastMCP forwards it upstream. Atlassian binds it into
           the auth code JWT, then rejects the token exchange with
           ``invalid_target: Incorrect resource parameters``.

        2. **Force scopes**: FastMCP uses the MCP client's requested scopes
           for the upstream authorize URL (``transaction["scopes"]``). MCP
           clients like Claude may only request a subset of scopes, missing
           ones required by Atlassian APIs (e.g. ``read:me``,
           ``read:jira-user``). We replace the transaction scopes with the
           full set configured via ``forced_scopes`` so the upstream token
           always carries every scope the server needs.
        """
        transaction = dict(transaction)

        if self._strip_resource_from_upstream:
            removed = transaction.pop("resource", None)
            if removed:
                logger.debug(
                    "Stripped resource=%s from upstream authorize request",
                    removed,
                )

        if self._forced_scopes:
            original = transaction.get("scopes", [])
            transaction["scopes"] = list(self._forced_scopes)
            if set(original) != set(self._forced_scopes):
                logger.debug(
                    "Replaced upstream scopes %s with forced scopes %s",
                    original,
                    self._forced_scopes,
                )

        return super()._build_upstream_authorize_url(txn_id, transaction)


__all__ = ["HardenedOAuthProxy", "parse_env_list"]
