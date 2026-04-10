"""
Reproduces GitHub issue #32931 on macOS by monkey-patching MSAL to simulate
the Windows WAM broker returning None (AccountNotFound) for a specific-tenant PCA.

On Windows with WAM, when you run `az login` (no --tenant), the account is
registered under the 'organizations' realm. A new PCA scoped to a specific
tenant (which is what _create_credential and find_using_common_tenant create)
cannot find the account via the broker and returns None from
acquire_token_silent_with_error.

Usage:
    # Make sure you are logged in first:
    #   az login
    #
    # Run WITHOUT the fix (on dev branch) to see the error:
    #   git checkout dev
    #   ~/.venv/azure-cli/bin/python repro/repro_wam.py
    #
    # Run WITH the fix to see it succeed:
    #   git checkout fix/msal-organizations-authority-token-fallback
    #   ~/.venv/azure-cli/bin/python repro/repro_wam.py
"""

import sys
import os

# Ensure we use the in-repo azure-cli-core, not any installed version
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
        and '-' in tenant_segment  # tenant GUIDs contain hyphens
    )
    if is_specific_tenant:
        print(
            "[PATCH] Simulating WAM broker AccountNotFound for authority: %s\n"
            "[PATCH] acquire_token_silent_with_error -> None" % authority_str
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
from azure.cli.core._profile import Profile

cli = get_default_cli()
profile = Profile(cli_ctx=cli)

# Use a non-ARM resource so there is no cached access token for it
resource = 'https://ossrdbms-aad.database.windows.net'
scopes = [resource + '/.default']

account = profile.get_subscription()
print("Subscription : %s" % account['id'])
print("Tenant       : %s" % account['tenantId'])
print("Resource     : %s" % resource)
print()

cred = profile._create_credential(account)
print("PCA authority: %s" % cred._msal_app.authority.authorization_endpoint)
print()

try:
    result = cred.acquire_token(scopes)
    print("[SUCCESS] Got access token (fix is working)")
    print("  token_source : %s" % result.get('token_source'))
    print("  expires_in   : %ss" % result.get('expires_in'))
    try:
        import base64, json as _json
        payload = result['access_token'].split('.')[1]
        payload += '=' * (-len(payload) % 4)
        aud = _json.loads(base64.b64decode(payload)).get('aud')
        print("  aud          : %s" % aud)
    except Exception:
        pass
except Exception as ex:
    print("[FAILURE] %s: %s" % (type(ex).__name__, ex))
    print()
    print("This is the bug from GitHub #32931.")
    print("Switch to fix/msal-organizations-authority-token-fallback and re-run to see the fix.")
