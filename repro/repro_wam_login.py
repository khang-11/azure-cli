"""
Reproduces the exact error from GitHub issue #32931 — the failure happens
during `az login` itself, not during a subsequent `get-access-token` call.

The call stack from the issue:
  az login
    → find_using_common_tenant()
      → identity.get_user_credential(username)   # specific-tenant PCA created
      → find_using_specific_tenant(tenant, cred)
        → client.subscriptions.list()            # triggers acquire_token
          → acquire_token_silent_with_error()    # WAM returns None (AccountNotFound)
            → check_result(None)
              → AuthenticationError: "Can't find token from MSAL cache"
              # caught by find_using_common_tenant → logged as warning, tenant skipped

On macOS, even with WAM patched, this repro requires also evicting the cached
ARM access tokens from the MSAL cache — otherwise MSAL returns them directly
from the in-process cache without calling acquire_token_silent_with_error.
On real Windows with WAM, the broker intercepts even cache hits, so the broker's
AccountNotFound fires unconditionally.

Usage:
    # Make sure you are logged in:
    #   az login
    #
    # Run WITHOUT fix (on dev branch) — all tenants fail, 0 subscriptions found:
    #   git checkout dev
    #   ~/.venv/azure-cli/bin/python repro/repro_wam_login.py
    #
    # Run WITH fix — all tenants succeed:
    #   git checkout fix/msal-organizations-authority-token-fallback
    #   ~/.venv/azure-cli/bin/python repro/repro_wam_login.py
"""

import sys
import os
import logging

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'azure-cli-core'))

import msal

_original_pca_init = msal.PublicClientApplication.__init__
_original_acquire_silent = msal.PublicClientApplication.acquire_token_silent_with_error


def _patched_init(self, client_id, authority=None, **kwargs):
    _original_pca_init(self, client_id, authority=authority, **kwargs)
    self._patched_authority_str = authority or ''


def _patched_acquire_silent(self, scopes, account, **kwargs):
    authority_str = getattr(self, '_patched_authority_str', '')
    tenant_segment = authority_str.rstrip('/').split('/')[-1]
    is_specific_tenant = (
        tenant_segment
        and tenant_segment not in ('organizations', 'common', 'consumers')
        and '-' in tenant_segment
    )
    if is_specific_tenant:
        print(
            "[PATCH] WAM broker AccountNotFound for authority: %s -> None" % authority_str
        )
        return None
    return _original_acquire_silent(self, scopes, account, **kwargs)


msal.PublicClientApplication.__init__ = _patched_init
msal.PublicClientApplication.acquire_token_silent_with_error = _patched_acquire_silent

print("=" * 70)
print("MSAL patched: specific-tenant PCA silent acquisition will return None")
print("=" * 70)
print()

from azure.cli.core import get_default_cli
from azure.cli.core._profile import Profile, SubscriptionFinder, _create_identity_instance
from azure.cli.core.auth.identity import Identity

cli = get_default_cli()
profile = Profile(cli_ctx=cli)

account = profile.get_subscription()
username = account['user']['name']
authority = cli.cloud.endpoints.active_directory

print("Logged in as : %s" % username)
print("Authority    : %s" % authority)
print()

# On Windows with WAM, the broker intercepts all token requests — including cache
# hits — so even a cached ARM access token triggers AccountNotFound.
# On macOS, MSAL returns cached access tokens directly without calling
# acquire_token_silent_with_error, bypassing our patch.
# To simulate Windows WAM behaviour on macOS, evict the ARM access tokens for
# specific-tenant realms from the in-process MSAL cache so that
# acquire_token_silent_with_error must be called (and our patch fires).
print("Evicting specific-tenant ARM access tokens from MSAL cache")
print("(simulates Windows WAM intercepting all token requests)...")
identity = _create_identity_instance(cli, authority)
cache = Identity._msal_token_cache
if cache:
    snapshot = cache.serialize()
    import json
    data = json.loads(snapshot)
    arm_scope_prefix = 'https://management.core.windows.net/'
    evicted = 0
    for key in list(data.get('AccessToken', {}).keys()):
        entry = data['AccessToken'][key]
        realm = entry.get('realm', '')
        target = entry.get('target', '')
        # Remove ARM access tokens cached under specific tenant realms
        if (arm_scope_prefix in target
                and realm not in ('organizations', 'common', 'consumers')
                and '-' in realm):
            del data['AccessToken'][key]
            evicted += 1
    cache.deserialize(json.dumps(data))
    print("  Evicted %d ARM access token(s) from specific-tenant realms." % evicted)
else:
    print("  (No MSAL token cache loaded yet — will load on first use)")
print()

print("Simulating find_using_common_tenant() as called by `az login`...")
print("(Without fix: each tenant fails with 'Can't find token from MSAL cache')")
print("(With fix:    each tenant retries via organizations authority and succeeds)")
print()

# Capture per-tenant failure warnings from find_using_common_tenant
warnings_emitted = []

_original_warning = logging.Logger.warning
def _capturing_warning(self, msg, *args, **kwargs):
    formatted = msg % args if args else msg
    if "Authentication failed" in formatted or "Can't find token" in formatted:
        warnings_emitted.append(formatted)
        print("[WARNING] %s" % formatted)
    return _original_warning(self, msg, *args, **kwargs)
logging.Logger.warning = _capturing_warning

organizations_credential = identity.get_user_credential(username)
subscription_finder = SubscriptionFinder(cli)

try:
    subscriptions = subscription_finder.find_using_common_tenant(username, organizations_credential)
except Exception as ex:
    print("[CRASH] Unexpected exception: %s: %s" % (type(ex).__name__, ex))
    sys.exit(1)
finally:
    logging.Logger.warning = _original_warning

print()
print("=" * 70)
tenants_tried = len(subscription_finder.tenants)
if warnings_emitted:
    print("[BUG REPRODUCED] %d of %d tenant(s) failed: 'Can't find token from MSAL cache'" % (
        len(warnings_emitted), tenants_tried + len(warnings_emitted)))
    print("  Subscriptions found: %d (should be more without the bug)" % len(subscriptions))
    print()
    print("  On real Windows, ALL tenants fail this way and the user sees:")
    print("    'If you need to access subscriptions in the following tenants,")
    print("     please use `az login --tenant TENANT_ID`.'")
    print()
    print("  Switch to fix/msal-organizations-authority-token-fallback and re-run.")
else:
    print("[FIX VERIFIED] All %d tenant(s) succeeded via organizations-authority retry." % tenants_tried)
    print("  Found %d subscription(s)." % len(subscriptions))
print("=" * 70)
