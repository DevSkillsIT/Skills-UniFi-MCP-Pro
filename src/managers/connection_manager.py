import asyncio
import logging
import os
import time
import time as _time
from typing import Any, Dict, Optional

import aiohttp
from aiounifi.controller import Controller
from aiounifi.errors import LoginRequired, RequestError, ResponseError
from aiounifi.models.api import ApiRequest, ApiRequestV2
from aiounifi.models.configuration import Configuration

from src.bootstrap import ALLOWED_SITES  # Site whitelist (None = ALL)

logger = logging.getLogger("unifi-network-mcp")


async def detect_unifi_os_pre_login(
    session: aiohttp.ClientSession,
    base_url: str,
    timeout: int = 5,
) -> Optional[bool]:
    """
    Detect UniFi OS BEFORE authentication using unauthenticated probes.

    This detection determines which auth endpoint to use:
    - UniFi OS: /api/auth/login
    - Standalone: /api/login

    Strategy:
    1. GET base URL - UniFi OS returns 200 with HTML, standalone redirects or errors
    2. Check for UniFi OS specific headers/behavior

    Args:
        session: Active aiohttp.ClientSession
        base_url: Base URL of controller (e.g., 'https://192.168.1.1:443')
        timeout: Detection timeout in seconds (default: 5)

    Returns:
        True: UniFi OS detected (use /api/auth/login)
        False: Standalone controller (use /api/login)
        None: Detection inconclusive
    """
    client_timeout = aiohttp.ClientTimeout(total=timeout)

    try:
        # Probe 1: GET base URL without following redirects
        # UniFi OS typically returns 200 OK with the web UI
        # Standalone controllers often redirect to /manage or return different status
        async with session.get(base_url, timeout=client_timeout, ssl=False, allow_redirects=False) as response:
            logger.debug(f"Pre-login probe {base_url}: status={response.status}")

            if response.status == 200:
                # UniFi OS returns 200 at base URL
                logger.debug("Pre-login detection: UniFi OS (200 at base URL)")
                return True
            elif response.status in (301, 302, 303, 307, 308):
                # Redirect typically indicates standalone controller
                location = response.headers.get("Location", "")
                logger.debug(f"Pre-login detection: redirect to {location}")
                # Could be standalone redirecting to /manage
                return False

    except asyncio.TimeoutError:
        logger.debug("Pre-login detection: timeout")
    except aiohttp.ClientError as e:
        logger.debug(f"Pre-login detection failed: {e}")
    except Exception as e:
        logger.debug(f"Pre-login detection unexpected error: {e}")

    return None


async def detect_with_retry(
    session: aiohttp.ClientSession,
    base_url: str,
    max_retries: int = 3,
    timeout: int = 5,
    pre_login: bool = False,
) -> Optional[bool]:
    """
    Detect UniFi OS with exponential backoff retry.

    Args:
        session: Active aiohttp.ClientSession
        base_url: Base URL of controller
        max_retries: Maximum retry attempts (default: 3)
        timeout: Detection timeout per attempt in seconds (default: 5)
        pre_login: If True, use unauthenticated detection for auth endpoint selection.
                   If False, use authenticated detection for API path verification.

    Returns:
        True: UniFi OS detected
        False: Standard controller detected
        None: Detection failed after all retries

    Implementation:
        - Retries up to max_retries times
        - Uses exponential backoff: 1s, 2s, 4s, ...
        - Logs retry attempts at debug level
        - Returns None if all attempts fail
    """
    detect_func = detect_unifi_os_pre_login if pre_login else detect_unifi_os_proactively

    for attempt in range(max_retries):
        try:
            result = await detect_func(session, base_url, timeout)
            if result is not None:
                return result
        except Exception as e:
            if attempt < max_retries - 1:
                delay = 2**attempt  # Exponential backoff: 1s, 2s, 4s
                logger.debug(f"Detection attempt {attempt + 1}/{max_retries} failed: {e}. Retrying in {delay}s...")
                await asyncio.sleep(delay)
            else:
                logger.warning(f"Detection failed after {max_retries} attempts: {e}")

    return None


async def _probe_endpoint(
    session: aiohttp.ClientSession,
    url: str,
    timeout: aiohttp.ClientTimeout,
    endpoint_name: str,
) -> bool:
    """
    Probe a single UniFi endpoint to check if it responds successfully.

    Args:
        session: Active aiohttp.ClientSession for making requests
        url: Full URL to probe
        timeout: Request timeout configuration
        endpoint_name: Human-readable name for logging (e.g., "UniFi OS", "standard")

    Returns:
        True if endpoint responds with 200 and valid JSON containing "data" key
        False otherwise
    """
    try:
        logger.debug(f"Probing {endpoint_name} endpoint: {url}")

        async with session.get(url, timeout=timeout, ssl=False) as response:
            if response.status == 200:
                try:
                    data = await response.json()
                    if "data" in data:
                        logger.debug(f"{endpoint_name} endpoint responded successfully")
                        return True
                except Exception as e:
                    logger.debug(f"{endpoint_name} endpoint returned 200 but invalid JSON: {e}")
    except asyncio.TimeoutError:
        logger.debug(f"{endpoint_name} endpoint probe timed out")
    except aiohttp.ClientError as e:
        logger.debug(f"{endpoint_name} endpoint probe failed: {e}")
    except Exception as e:
        logger.debug(f"Unexpected error probing {endpoint_name} endpoint: {e}")

    return False


async def detect_unifi_os_proactively(
    session: aiohttp.ClientSession, base_url: str, timeout: int = 5
) -> Optional[bool]:
    """
    Detect if controller is UniFi OS by testing endpoint variants.

    Probes both UniFi OS (/proxy/network/api/self/sites) and standard
    (/api/self/sites) endpoints to empirically determine path requirement.

    Args:
        session: Active aiohttp.ClientSession for making requests
        base_url: Base URL of controller (e.g., 'https://192.168.1.1:443')
        timeout: Detection timeout in seconds (default: 5)

    Returns:
        True: UniFi OS detected (requires /proxy/network prefix)
        False: Standard controller detected (uses /api paths)
        None: Detection failed, fall back to aiounifi's check_unifi_os()

    Implementation Notes:
        - Tries UniFi OS endpoint first (newer controllers)
        - Falls back to standard endpoint if UniFi OS fails
        - Returns None if both fail (timeout, network error, etc.)
        - Per FR-012: If both succeed, prefers direct (returns False)
    """
    client_timeout = aiohttp.ClientTimeout(total=timeout)

    # Probe both endpoints
    unifi_os_url = f"{base_url}/proxy/network/api/self/sites"
    standard_url = f"{base_url}/api/self/sites"

    unifi_os_result = await _probe_endpoint(session, unifi_os_url, client_timeout, "UniFi OS")
    standard_result = await _probe_endpoint(session, standard_url, client_timeout, "standard")

    # Determine result based on probe outcomes
    if unifi_os_result and standard_result:
        # FR-012: Both succeed, prefer direct (standard)
        logger.info("Both endpoints succeeded - preferring standard (direct) paths")
        return False
    elif unifi_os_result:
        logger.info("Detected UniFi OS controller (proxy paths required)")
        return True
    elif standard_result:
        logger.info("Detected standard controller (direct paths)")
        return False
    else:
        logger.warning("Auto-detection failed - both endpoints unsuccessful")
        return None


class ConnectionManager:
    """Manages the connection and session with the Unifi Network Controller."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 443,
        site: str = "default",
        verify_ssl: bool = False,
        cache_timeout: int = 30,
        max_retries: int = 3,
        retry_delay: int = 5,
    ):
        """Initialize the Connection Manager."""
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.site = site
        self.verify_ssl = verify_ssl
        self.cache_timeout = cache_timeout
        self._max_retries = max_retries
        self._retry_delay = retry_delay
        self.controller: Optional[Controller] = None
        self._aiohttp_session: Optional[aiohttp.ClientSession] = None
        self._initialized = False
        self._connect_lock = asyncio.Lock()
        self._cache: Dict[str, Any] = {}
        self._last_cache_update: Dict[str, float] = {}

        # Path detection state
        self._unifi_os_override: Optional[bool] = None
        """
        Override for is_unifi_os flag:
        - None: Use aiounifi's detection (no override)
        - True: Force UniFi OS paths (/proxy/network)
        - False: Force standard paths (/api)
        """

        # Site NAME → ID mapping cache (CRÍTICO: UniFi API usa ID, não nome)
        self._site_name_to_id: Dict[str, str] = {}
        """
        Mapeamento de site NAME → site ID.
        Exemplo: {"SK_PMW_SkillsIT-Escritorio": "i06j58bm"}
        Carregado via _load_site_mappings() após autenticação.
        """

    @property
    def url_base(self) -> str:
        proto = "https"
        return f"{proto}://{self.host}:{self.port}"

    async def initialize(self) -> bool:
        """Initialize the controller connection (correct for attached aiounifi version)."""
        if self._initialized and self.controller and self._aiohttp_session and not self._aiohttp_session.closed:
            return True

        async with self._connect_lock:
            if self._initialized and self.controller and self._aiohttp_session and not self._aiohttp_session.closed:
                return True

            logger.info(f"Attempting to connect to Unifi controller at {self.host}...")
            for attempt in range(self._max_retries):
                session_created = False
                try:
                    if self.controller:
                        self.controller = None
                    if self._aiohttp_session and not self._aiohttp_session.closed:
                        await self._aiohttp_session.close()
                        self._aiohttp_session = None

                    connector = aiohttp.TCPConnector(ssl=False if not self.verify_ssl else None)
                    self._aiohttp_session = aiohttp.ClientSession(
                        connector=connector, cookie_jar=aiohttp.CookieJar(unsafe=True)
                    )
                    session_created = True

                    # Controller type detection/override configuration
                    # Two-phase detection:
                    # 1. Pre-login: Determines auth endpoint (/api/auth/login vs /api/login)
                    # 2. Post-login: Verifies API path prefix (/proxy/network/api vs /api)
                    # See: https://github.com/sirkirby/unifi-network-mcp/issues/33
                    from src.bootstrap import UNIFI_CONTROLLER_TYPE

                    if UNIFI_CONTROLLER_TYPE == "proxy":
                        self._unifi_os_override = True
                        logger.info("Controller type forced to UniFi OS (proxy) via config")
                    elif UNIFI_CONTROLLER_TYPE == "direct":
                        self._unifi_os_override = False
                        logger.info("Controller type forced to standard (direct) via config")
                    elif UNIFI_CONTROLLER_TYPE == "auto":
                        # Phase 1: Pre-login detection (unauthenticated)
                        # Determines which auth endpoint to use
                        if self._unifi_os_override is None:
                            detected = await detect_with_retry(
                                self._aiohttp_session,
                                self.url_base,
                                max_retries=3,
                                timeout=5,
                                pre_login=True,  # Use unauthenticated detection
                            )
                            if detected is not None:
                                self._unifi_os_override = detected
                                mode = "UniFi OS (proxy)" if detected else "standard (direct)"
                                logger.info(f"Pre-login auto-detected controller type: {mode}")
                            else:
                                # Pre-login detection inconclusive - aiounifi will try its own detection
                                # Show helpful message for troubleshooting
                                logger.warning(
                                    "Pre-login detection inconclusive, deferring to aiounifi. "
                                    "If login fails, try setting UNIFI_CONTROLLER_TYPE=proxy for UniFi OS devices."
                                )
                        else:
                            logger.debug(f"Using cached detection result: {self._unifi_os_override}")

                    config = Configuration(
                        session=self._aiohttp_session,
                        host=self.host,
                        username=self.username,
                        password=self.password,
                        port=self.port,
                        site=self.site,
                    )

                    self.controller = Controller(config=config)

                    # Apply pre-login detection result BEFORE login to ensure correct auth endpoint
                    # aiounifi uses /api/auth/login for UniFi OS, /api/login for standalone
                    if self._unifi_os_override is not None:
                        self.controller.connectivity.is_unifi_os = self._unifi_os_override
                        logger.debug(f"Pre-login is_unifi_os set to: {self._unifi_os_override}")

                    await self.controller.login()

                    # Phase 2: Post-login verification (authenticated)
                    # Verify API path prefix works correctly after successful login
                    if UNIFI_CONTROLLER_TYPE == "auto" and self._unifi_os_override is not None:
                        post_login_detected = await detect_with_retry(
                            self._aiohttp_session,
                            self.url_base,
                            max_retries=2,
                            timeout=5,
                            pre_login=False,  # Use authenticated detection
                        )
                        if post_login_detected is not None and post_login_detected != self._unifi_os_override:
                            # Post-login detection differs - update override
                            logger.warning(
                                f"Post-login detection differs from pre-login: "
                                f"pre={self._unifi_os_override}, post={post_login_detected}. "
                                f"Using post-login result."
                            )
                            self._unifi_os_override = post_login_detected
                        elif post_login_detected is not None:
                            logger.debug("Post-login detection confirmed pre-login result")

                    self._initialized = True
                    logger.info(f"Successfully connected to Unifi controller at {self.host} for site '{self.site}'")
                    self._invalidate_cache()

                    # CRÍTICO: Carregar mapeamento NAME → ID após autenticação
                    await self._load_site_mappings()

                    return True

                except (
                    LoginRequired,
                    RequestError,
                    ResponseError,
                    asyncio.TimeoutError,
                    aiohttp.ClientError,
                ) as e:
                    logger.warning(f"Connection attempt {attempt + 1} failed: {e}")
                    if session_created and self._aiohttp_session and not self._aiohttp_session.closed:
                        await self._aiohttp_session.close()
                        self._aiohttp_session = None
                    self.controller = None
                    if attempt < self._max_retries - 1:
                        await asyncio.sleep(self._retry_delay)
                    else:
                        logger.error(f"Failed to initialize Unifi controller after {self._max_retries} attempts: {e}")
                        self._initialized = False
                        return False
                except Exception as e:
                    logger.error(
                        f"Unexpected error during controller initialization: {e}",
                        exc_info=True,
                    )
                    if session_created and self._aiohttp_session and not self._aiohttp_session.closed:
                        await self._aiohttp_session.close()
                        self._aiohttp_session = None
                    self._initialized = False
                    self.controller = None
                    return False
            return False

    async def _load_site_mappings(self) -> None:
        """
        Carrega mapeamento de site NAME → ID do controller.

        CRÍTICO: UniFi API usa site ID (campo 'name') nas URLs, não o display name (campo 'desc').
        Exemplo:
        - Site ID: 'i06j58bm' (usado em /api/s/i06j58bm/...)
        - Display Name: 'SK_PMW_SkillsIT-Escritorio' (nome legível)

        Este método:
        1. Busca todos os sites do controller (/api/self/sites)
        2. Filtra pela whitelist (ALLOWED_SITES) quando configurada
        3. Constrói mapeamento: {display_name: site_id}
        4. SEGURANÇA: Não expõe sites fora da whitelist
        """
        try:
            # Obter whitelist configurada (None = ALL)
            allowed_sites = ALLOWED_SITES

            # Endpoint para listar todos os sites
            api_path = "/api/self/sites"
            url = f"{self.url_base}{api_path}"

            logger.debug(f"Buscando lista de sites em: {url}")

            # Fazer request HTTP direto (antes de self.controller.site estar configurado)
            async with self._aiohttp_session.get(url) as response:
                if response.status != 200:
                    logger.error(f"Falha ao buscar sites: HTTP {response.status}")
                    return

                data = await response.json()

                if not isinstance(data, dict) or "data" not in data:
                    logger.error(f"Resposta inválida do controller: {data}")
                    return

                sites = data["data"]
                logger.debug(f"Controller retornou {len(sites)} sites")

                # Construir mapeamento NAME → ID (apenas sites na whitelist se houver)
                mapping_count = 0
                for site in sites:
                    site_id = site.get("name")  # Campo 'name' = ID do site
                    display_name = site.get("desc")  # Campo 'desc' = nome legível

                    if not site_id or not display_name:
                        logger.warning(f"Site sem ID ou nome: {site}")
                        continue

                    # SEGURANÇA: Apenas mapear sites na whitelist quando houver
                    if allowed_sites is not None and display_name not in allowed_sites:
                        logger.debug(f"Site '{display_name}' ignorado (não está na whitelist)")
                        continue

                    self._site_name_to_id[display_name] = site_id
                    mapping_count += 1
                    logger.info(f"Mapeado: '{display_name}' → '{site_id}'")

                logger.info(f"Mapeamento NAME→ID carregado: {mapping_count} sites permitidos" if allowed_sites else f"Mapeamento NAME→ID carregado: {mapping_count} sites (ALL-SITES)")

                if mapping_count == 0 and allowed_sites is not None:
                    logger.warning(
                        f"ATENÇÃO: Nenhum site da whitelist encontrado no controller! "
                        f"Whitelist: {allowed_sites}"
                    )

        except Exception as e:
            logger.error(f"Erro ao carregar mapeamento de sites: {e}", exc_info=True)

    async def ensure_connected(self) -> bool:
        """Ensure the controller is connected, attempting to reconnect if necessary."""

        if not self._initialized or not self.controller or not self._aiohttp_session or self._aiohttp_session.closed:
            logger.warning("Controller not initialized or session lost/closed, attempting to reconnect...")
            return await self.initialize()

        try:
            internal_session = self.controller.connectivity.config.session
            if internal_session.closed:
                logger.warning(
                    "Controller session found closed (via connectivity.config.session), attempting to reconnect..."
                )
                return await self.initialize()
        except AttributeError:
            logger.debug("connectivity.config.session attribute not found – skipping additional session check.")

        return True

    async def cleanup(self):
        """Clean up resources and close connections."""
        if self._aiohttp_session and not self._aiohttp_session.closed:
            await self._aiohttp_session.close()
            logger.info("aiohttp session closed.")
        self._initialized = False
        self.controller = None
        self._aiohttp_session = None
        self._cache = {}
        self._last_cache_update = {}
        logger.info("Unifi connection manager resources cleared.")

    async def request(self, api_request: ApiRequest | ApiRequestV2, return_raw: bool = False) -> Any:
        """Make a request to the controller API, handling raw responses."""
        if not await self.ensure_connected() or not self.controller:
            raise ConnectionError("Unifi Controller is not connected.")

        # Apply override if we have better detection (FR-003: use cached detection)
        original_is_unifi_os = None
        if self._unifi_os_override is not None:
            original_is_unifi_os = self.controller.connectivity.is_unifi_os
            if original_is_unifi_os != self._unifi_os_override:
                logger.debug(
                    f"Overriding is_unifi_os from {original_is_unifi_os} to {self._unifi_os_override} for this request"
                )
                self.controller.connectivity.is_unifi_os = self._unifi_os_override

        request_method = self.controller.connectivity._request if return_raw else self.controller.request

        try:
            # Diagnostics: capture timing and payloads without leaking secrets
            start_ts = _time.perf_counter()
            response = await request_method(api_request)
            duration_ms = (_time.perf_counter() - start_ts) * 1000.0
            try:
                from src.utils.diagnostics import (
                    diagnostics_enabled,
                    log_api_request,
                )  # lazy import to avoid cycles

                if diagnostics_enabled():
                    payload = getattr(api_request, "json", None) or getattr(api_request, "data", None)
                    log_api_request(
                        api_request.method,
                        api_request.path,
                        payload,
                        response,
                        duration_ms,
                        True,
                    )
            except Exception:
                pass
            return response if return_raw else response.get("data")

        except LoginRequired:
            logger.warning("Login required detected during request, attempting re-login...")
            if await self.initialize():
                if not self.controller:
                    raise ConnectionError("Re-login failed, controller not available.")
                logger.info("Re-login successful, retrying original request...")
                try:
                    start_ts = _time.perf_counter()
                    retry_response = await request_method(api_request)
                    duration_ms = (_time.perf_counter() - start_ts) * 1000.0
                    try:
                        from src.utils.diagnostics import (
                            diagnostics_enabled,
                            log_api_request,
                        )

                        if diagnostics_enabled():
                            payload = getattr(api_request, "json", None) or getattr(api_request, "data", None)
                            log_api_request(
                                api_request.method,
                                api_request.path,
                                payload,
                                retry_response,
                                duration_ms,
                                True,
                            )
                    except Exception:
                        pass
                    return retry_response if return_raw else retry_response.get("data")
                except Exception as retry_e:
                    logger.error(
                        f"API request failed even after re-login: {api_request.method.upper()} {api_request.path} - {retry_e}"
                    )
                    raise retry_e from None
            else:
                raise ConnectionError("Re-login failed, cannot proceed with request.")
        except (RequestError, ResponseError, aiohttp.ClientError) as e:
            logger.error(f"API request error: {api_request.method.upper()} {api_request.path} - {e}")
            try:
                from src.utils.diagnostics import diagnostics_enabled, log_api_request

                if diagnostics_enabled():
                    payload = getattr(api_request, "json", None) or getattr(api_request, "data", None)
                    log_api_request(
                        api_request.method,
                        api_request.path,
                        payload,
                        {"error": str(e)},
                        0.0,
                        False,
                    )
            except Exception:
                pass
            raise
        except Exception as e:
            logger.error(
                f"Unexpected error during API request: {api_request.method.upper()} {api_request.path} - {e}",
                exc_info=True,
            )
            try:
                from src.utils.diagnostics import diagnostics_enabled, log_api_request

                if diagnostics_enabled():
                    payload = getattr(api_request, "json", None) or getattr(api_request, "data", None)
                    log_api_request(
                        api_request.method,
                        api_request.path,
                        payload,
                        {"error": str(e)},
                        0.0,
                        False,
                    )
            except Exception:
                pass
            raise
        finally:
            # Always restore original value (FR-003: maintain session state)
            if original_is_unifi_os is not None:
                self.controller.connectivity.is_unifi_os = original_is_unifi_os

    # --- Cache Management ---

    def _update_cache(self, key: str, data: Any, timeout: Optional[int] = None):
        """Update the cache with new data."""
        self._cache[key] = data
        self._last_cache_update[key] = time.time()
        logger.debug(f"Cache updated for key '{key}' with timeout {timeout or self.cache_timeout}s")

    def _is_cache_valid(self, key: str, timeout: Optional[int] = None) -> bool:
        """Check if the cache for a given key is still valid."""
        if key not in self._cache or key not in self._last_cache_update:
            return False

        effective_timeout = timeout if timeout is not None else self.cache_timeout
        current_time = time.time()
        last_update = self._last_cache_update[key]

        is_valid = (current_time - last_update) < effective_timeout
        logger.debug(
            f"Cache check for key '{key}': {'Valid' if is_valid else 'Expired'} (Timeout: {effective_timeout}s)"
        )
        return is_valid

    def get_cached(self, key: str, timeout: Optional[int] = None) -> Optional[Any]:
        """Get data from cache if valid."""
        if self._is_cache_valid(key, timeout):
            logger.debug(f"Cache hit for key '{key}'")
            return self._cache[key]
        logger.debug(f"Cache miss for key '{key}'")
        return None

    def _invalidate_cache(self, prefix: Optional[str] = None):
        """Invalidate cache entries, optionally by prefix."""
        if prefix:
            keys_to_remove = [k for k in self._cache if k.startswith(prefix)]
            for key in keys_to_remove:
                del self._cache[key]
                if key in self._last_cache_update:
                    del self._last_cache_update[key]
            logger.debug(f"Invalidated cache for keys starting with '{prefix}'")
        else:
            self._cache = {}
            self._last_cache_update = {}
            logger.debug("Invalidated entire cache")

    async def set_site(self, site: str):
        """
        Atualiza o site alvo e invalida cache relevante.

        CRÍTICO: Este método agora aceita display name e resolve para site ID automaticamente.

        Args:
            site: Display name do site (ex: 'SK_PMW_SkillsIT-Escritorio')
                  ou site ID direto (ex: 'i06j58bm')

        Fluxo:
        1. Verifica se 'site' é um display name no mapeamento
        2. Se sim, resolve para site ID
        3. Se não, assume que já é site ID
        4. Aplica o site ID no controller

        Note: Este método tenta troca dinâmica. Estabilidade completa pode requerer
        re-inicialização do connection manager ou restart do servidor.
        """
        if not self.controller or not hasattr(self.controller.connectivity, "config"):
            logger.warning("Cannot set site dynamically, controller or config not available.")
            return

        # CRÍTICO: Resolver display name → site ID
        site_id = site  # Default: assumir que já é ID

        if site in self._site_name_to_id:
            # É um display name - resolver para ID
            site_id = self._site_name_to_id[site]
            logger.info(f"Resolvido display name '{site}' → site ID '{site_id}'")
        else:
            # Não está no mapeamento - pode ser ID direto ou site inválido
            logger.debug(f"Site '{site}' não encontrado no mapeamento NAME→ID, assumindo que é site ID direto")

        # Aplicar site ID no controller
        self.controller.connectivity.config.site = site_id
        self.site = site_id
        self._invalidate_cache()
        logger.info(f"Site alvo alterado para ID '{site_id}'. Cache invalidado. Re-login pode ocorrer no próximo request.")
