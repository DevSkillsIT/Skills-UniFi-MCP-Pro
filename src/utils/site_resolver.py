"""
Site resolver with fuzzy matching for multi-site support.

Provides semantic search to resolve friendly site names to UniFi site slugs.
Fase 1: Site Resolver + unifi_list_sites (CRÍTICA)
"""

import asyncio
import logging
import re
import sys
from typing import Any, Dict, List, Optional

try:
    from rapidfuzz import fuzz
    RAPIDFUZZ_AVAILABLE = True
except ImportError:
    RAPIDFUZZ_AVAILABLE = False
    import difflib

from src.exceptions import (
    SiteNotFoundError,
    SiteForbiddenError,
    InvalidSiteParameterError,
)

logger = logging.getLogger("unifi-network-mcp")


# Cache for sites (TTL handled externally)
_sites_cache: Optional[List[Dict[str, Any]]] = None
_sites_lock = asyncio.Lock()


async def get_all_sites() -> List[Dict[str, Any]]:
    """Sites the whitelist allows, in the UniFi field convention.

    Reads the registry the connection builds at login rather than calling the
    API: `/api/self/sites` is a controller-level path, and handing it to
    `ApiRequest` prefixes it with `/api/s/<site>`, which the controller rejects
    as `api.err.InvalidObject`.

    The three fields mean three different things and all three are matchable:
        _id   the controller's ObjectId for the site
        name  the slug that appears in API paths (what `site=` ultimately needs)
        desc  the human-readable display name

    They used to be collapsed -- `_id` held the slug and `name` held the display
    name -- so the `_id` that `list_sites` reported could not be passed back as
    `site`, and the two views of the same site disagreed.

    Returns:
        List of site dicts with keys: _id, name, desc

    Raises:
        Exception: if the registry cannot be read
    """
    from src.runtime import connection_manager

    try:
        registry = getattr(connection_manager, "_sites_by_slug", None) or {}
        if registry:
            return [
                {"_id": entry.get("_id", ""), "name": entry.get("name", ""), "desc": entry.get("desc", "")}
                for entry in registry.values()
            ]

        # Before the registry exists, fall back to the display-name mapping.
        mappings = connection_manager._site_name_to_id
        if not mappings:
            logger.warning("Site registry is empty; no site is available")
            return []
        return [{"_id": slug, "name": slug, "desc": display} for display, slug in mappings.items()]
    except Exception as e:
        logger.error(f"Error reading the site registry: {e}")
        raise


async def map_allowed_sites_to_ids(
    allowed_sites: Optional[List[str]],
) -> Optional[List[str]]:
    """
    Map configured allowed sites (names or IDs) to controller site IDs.

    Args:
        allowed_sites: List of allowed site identifiers (display names or IDs). None => all allowed.

    Returns:
        List of site IDs (slugs) or None if all sites are allowed.
    """
    if allowed_sites is None:
        return None

    sites = await get_all_sites()
    if not sites:
        return []

    mapped: List[str] = []
    for allowed in allowed_sites:
        # Use direct site matching with fuzzy/prefix strategies
        allowed_norm = allowed.strip().lower()
        for site in sites:
            display = (site.get("desc") or site.get("name") or "").lower()
            desc = (site.get("desc") or "").lower()
            site_id = (site.get("_id") or "").lower()

            if allowed_norm in {display, desc, site_id}:
                mapped.append(site.get("name", "") or site.get("_id", ""))
                break
        else:
            logger.warning(
                f"Allowed site '{allowed}' not found in controller sites; skipping."
            )

    # Deduplicate while preserving order
    seen = set()
    deduped = []
    for sid in mapped:
        if sid and sid not in seen:
            seen.add(sid)
            deduped.append(sid)

    return deduped


def validate_site_parameter(site: str) -> str:
    """
    Validate and normalize site parameter.

    Rules:
    - Only alphanumeric, hyphens, and underscores allowed
    - Maximum 100 characters
    - Must not be empty
    - Whitespace trimmed
    - Case preserved

    Case is deliberately preserved. The whitelist in `_load_site_mappings` is
    compared case-sensitively against the controller's display names, so
    lower-casing "Grupo_Acme-Matriz" here would stop it matching.
    Resolution itself is case-insensitive, so nothing is lost by keeping it.

    Args:
        site: Site parameter from user input

    Returns:
        Trimmed site parameter, original casing intact

    Raises:
        InvalidSiteParameterError: If validation fails
    """
    if not site:
        raise InvalidSiteParameterError(
            site,
            reason="Site parameter must not be empty"
        )

    # Trim whitespace
    site = site.strip()

    if not site:
        raise InvalidSiteParameterError(
            site,
            reason="Site parameter must not be empty after trimming"
        )

    # Check length
    if len(site) > 100:
        raise InvalidSiteParameterError(
            site,
            reason="Site parameter exceeds maximum length of 100 characters"
        )

    # Check for invalid characters
    if not re.match(r"^[a-zA-Z0-9_-]+$", site):
        raise InvalidSiteParameterError(
            site,
            reason="Special characters not allowed. Use only letters, numbers, hyphens, and underscores"
        )

    # Preserve original casing for UniFi API (case-sensitive)
    return site.strip()


async def resolve_site_identifier(site_input: str) -> Dict[str, str]:
    """
    Resolve friendly site name to site slug and ID.

    Args:
        site_input: Site identifier (name, description, or slug)
        system_manager: System manager instance for site access validation
        
    Returns:
        Dict with site context (slug, id, display_name)
        
    Raises:
        SiteNotFoundError: If site cannot be resolved
        InvalidSiteParameterError: If site parameter is invalid
    """
    # Validate input first
    validated_input = validate_site_parameter(site_input)
    site_lower = validated_input.lower()

    # Fetch sites from controller
    sites = await get_all_sites()

    if not sites:
        raise SiteNotFoundError(site_input, suggestions=[])

    # Strategy 1: exact match on any of the three identifiers
    for site in sites:
        if site_lower in {
            site.get("name", "").lower(),
            site.get("_id", "").lower(),
            site.get("desc", "").lower(),
        }:
            return _site_context(site)

    # Strategy 2: Prefix match (case-insensitive)
    prefix_matches = [
        s for s in sites
        if s.get("name", "").lower().startswith(site_lower)
        or s.get("desc", "").lower().startswith(site_lower)
    ]
    if len(prefix_matches) == 1:
        return _site_context(prefix_matches[0])

    # Strategy 3: Fuzzy matching (threshold 80%)
    matches = []
    for site in sites:
        site_name = site.get("name", "")
        site_desc = site.get("desc", "")

        # Compare with name and description
        name_score = _fuzzy_score(site_lower, site_name.lower())
        desc_score = _fuzzy_score(site_lower, site_desc.lower()) if site_desc else 0

        best_score = max(name_score, desc_score)
        matches.append((site, best_score))

    if matches:
        best_match = max(matches, key=lambda x: x[1])
        # With token_set_ratio, 60% is a good threshold for substrings
        # e.g., "acme" matching "grupo acme" = 100%, "acme" in "grupoacme" = 61%
        if best_match[1] >= 60:
            return _site_context(best_match[0])

    # Nothing in the allowed set matched. Before reporting "not found", ask the
    # controller registry whether the site exists at all: a site that exists but
    # is outside the whitelist is a permission problem, not a missing site, and
    # reporting it as missing sends the reader to audit the controller instead
    # of the whitelist.
    if _exists_outside_whitelist(validated_input):
        raise SiteForbiddenError(
            site_input,
            allowed_sites=[s.get("desc", "") or s.get("name", "") for s in sites if s.get("name")],
        )

    available_sites = [s.get("desc", "") or s.get("name", "") or s.get("_id", "") for s in sites[:5]]
    raise SiteNotFoundError(site_input, suggestions=available_sites)


def _exists_outside_whitelist(site: str) -> bool:
    """Whether the controller knows this site even though the whitelist hides it.

    Reads `src.runtime` only if it is already imported, via `sys.modules`,
    instead of importing it. Importing the runtime from here would pull in the
    whole configuration stack as a side effect of an error path -- which is both
    a surprising dependency for a pure resolver and enough to break any caller
    that has the configuration layer stubbed.

    When the runtime is not loaded there is nothing to consult, so the answer is
    "unknown", and the caller reports the site as not found: the conservative
    reading, since claiming a site exists when that cannot be checked would be
    worse than under-reporting.
    """
    runtime = sys.modules.get("src.runtime")
    connection = getattr(runtime, "connection_manager", None) if runtime else None
    checker = getattr(connection, "site_exists_on_controller", None) if connection else None
    if checker is None:
        return False
    try:
        return bool(checker(site))
    except Exception:
        return False


def _site_context(site: Dict[str, Any]) -> Dict[str, str]:
    """Build the (slug, id, display_name) triple tools carry around.

    `slug` is the API path segment, which is the `name` field -- not `_id`.
    """
    return {
        "slug": site.get("name", "") or site.get("_id", ""),
        "id": site.get("_id", "") or site.get("name", ""),
        "display_name": site.get("desc", "") or site.get("name", ""),
    }


def _fuzzy_score(s1: str, s2: str) -> int:
    """
    Calculate fuzzy string matching score.

    Uses rapidfuzz token_set_ratio if available (better for substrings),
    falls back to difflib.

    Args:
        s1: First string
        s2: Second string

    Returns:
        Score 0-100
    """
    if RAPIDFUZZ_AVAILABLE:
        # token_set_ratio is better for substring matching
        # e.g., "acme" in "Grupo Acme" scores higher
        return int(fuzz.token_set_ratio(s1, s2))
    else:
        # Fallback to difflib - simple ratio
        ratio = difflib.SequenceMatcher(None, s1, s2).ratio()
        return int(ratio * 100)


async def validate_site_access(
    site_slug: str,
    allowed_sites: Optional[List[str]]
) -> None:
    """
    Validate that site is in the allowed list.

    Args:
        site_slug: Site slug/name from resolver (e.g., "grupoacme")
        allowed_sites: List of allowed site slugs (None = ALL sites allowed)

    Raises:
        SiteForbiddenError: If site is not in allowed list
    """
    if allowed_sites is None:
        # ALL-SITES mode - no restrictions
        return

    # Normalize comparison
    site_normalized = site_slug.lower().strip()

    # Check if in whitelist
    allowed_normalized = [s.lower().strip() for s in allowed_sites]
    if site_normalized not in allowed_normalized:
        raise SiteForbiddenError(
            site_slug,
            allowed_sites=allowed_sites
        )


class SiteResolverCache:
    """
    Cache for site resolution results.

    Prevents hammering the controller for the same site list.
    """

    def __init__(self, ttl_seconds: int = 300):
        """
        Initialize cache.

        Args:
            ttl_seconds: Cache TTL in seconds (default: 5 minutes)
        """
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, tuple] = {}  # key -> (value, timestamp)
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache if not expired."""
        async with self._lock:
            if key not in self._cache:
                return None

            value, timestamp = self._cache[key]
            # Check if expired (TTL)
            import time
            if time.time() - timestamp > self.ttl_seconds:
                del self._cache[key]
                return None

            return value

    async def set(self, key: str, value: Any) -> None:
        """Set value in cache."""
        async with self._lock:
            import time
            self._cache[key] = (value, time.time())

    async def clear(self, key: Optional[str] = None) -> None:
        """Clear cache (all or specific key)."""
        async with self._lock:
            if key:
                self._cache.pop(key, None)
            else:
                self._cache.clear()
