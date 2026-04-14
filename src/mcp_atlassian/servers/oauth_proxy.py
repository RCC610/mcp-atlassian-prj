"""OAuth proxy extensions and configuration helpers."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any

from fastmcp.server.auth.oauth_proxy import OAuthProxy
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
        **kwargs: object,
    ) -> None:
        super().__init__(**kwargs)
        self._allowed_grant_types = _normalize_list(allowed_grant_types)
        self._forced_scopes = _normalize_list(forced_scopes)
        self._strip_resource_from_upstream = strip_resource_from_upstream

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
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
        """Build upstream authorize URL, stripping resource for Atlassian Cloud.

        Atlassian Cloud does not support RFC 8707 resource indicators. When
        an MCP client (e.g. Claude) sends a ``resource`` parameter, FastMCP
        forwards it to the upstream ``/authorize`` endpoint. Atlassian binds
        it into the auth code JWT, then rejects the token exchange with
        ``invalid_target: Incorrect resource parameters``.

        Stripping the parameter before the upstream redirect prevents this
        while the proxy still tracks it internally for its own validation.
        """
        if self._strip_resource_from_upstream:
            transaction = dict(transaction)
            removed = transaction.pop("resource", None)
            if removed:
                logger.debug(
                    "Stripped resource=%s from upstream authorize request",
                    removed,
                )
        return super()._build_upstream_authorize_url(txn_id, transaction)


__all__ = ["HardenedOAuthProxy", "parse_env_list"]
