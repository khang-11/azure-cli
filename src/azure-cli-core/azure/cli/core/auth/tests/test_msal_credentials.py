# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

# pylint: disable=protected-access

import sys
import types
import unittest
from unittest import mock

# Stub out azure.cli.telemetry before any azure.cli.core imports so that
# the telemetry module (which requires the azure-cli-telemetry package) doesn't
# need to be installed when running unit tests in isolation.
_telemetry_stub = types.ModuleType('azure.cli.telemetry')
_telemetry_stub.DEFAULT_INSTRUMENTATION_KEY = 'stub-key'
_telemetry_stub.start = lambda *a, **kw: None
_telemetry_stub.flush = lambda *a, **kw: None
sys.modules.setdefault('azure.cli.telemetry', _telemetry_stub)


MOCK_ACCESS_TOKEN = 'mock_access_token'
MOCK_SCOPES = ['https://contoso.kusto.windows.net/.default']

# MSAL account as returned by PublicClientApplication.get_accounts()
# home_account_id format: "<object-id>.<home-tenant-id>"
MOCK_ACCOUNT_TENANT = {
    'home_account_id': 'oid-00000001.tenant-00000001',
    'environment': 'login.microsoftonline.com',
    'realm': 'tenant-00000001',
    'local_account_id': 'oid-00000001',
    'username': 'user@example.com',
    'authority_type': 'MSSTS',
}

MOCK_ACCOUNT_ORGANIZATIONS = {
    **MOCK_ACCOUNT_TENANT,
    'realm': 'organizations',
}

MOCK_TOKEN_RESULT = {
    'access_token': MOCK_ACCESS_TOKEN,
    'token_type': 'Bearer',
    'expires_in': 3600,
    'token_source': 'cache',
}


class TestUserCredential(unittest.TestCase):
    """Tests for UserCredential.acquire_token, focusing on the organizations-authority retry logic.

    The bug (GitHub #32931): When `az login` is run without --tenant, MSAL uses the 'organizations'
    authority and caches the refresh token under that realm. But _create_credential (and
    find_using_common_tenant) always create a PCA with the *specific tenant* authority
    (from account[_TENANT_ID]). When that specific-tenant PCA calls acquire_token_silent_with_error
    for a non-ARM resource (e.g. Kusto, ADO) it returns None because the token is stored under
    'organizations', not the specific tenant realm.

    The fix: when a specific-tenant PCA returns None, retry with an 'organizations' PCA that shares
    the same token cache — which CAN find the cached refresh token.
    """

    def _make_authority_mock(self, tenant='tenant-00000001'):
        """Build a mock MSAL authority object."""
        authority = mock.MagicMock()
        authority.tenant = tenant
        # MSAL authorization_endpoint format:
        # https://login.microsoftonline.com/<tenant>/oauth2/v2.0/authorize
        authority.authorization_endpoint = (
            'https://login.microsoftonline.com/{}/oauth2/v2.0/authorize'.format(tenant)
        )
        authority.is_adfs = False
        return authority

    def _make_msal_app_mock(self, tenant='tenant-00000001', silent_result=None, accounts=None):
        """Build a mock PublicClientApplication."""
        app = mock.MagicMock()
        app.client_id = 'azure-cli-client-id'
        app.authority = self._make_authority_mock(tenant)
        app.token_cache = mock.MagicMock()
        app.get_accounts.return_value = accounts if accounts is not None else [MOCK_ACCOUNT_TENANT]
        app.acquire_token_silent_with_error.return_value = silent_result
        return app

    @mock.patch('azure.cli.core.auth.msal_credentials.PublicClientApplication')
    def test_acquire_token_specific_tenant_succeeds_no_retry(self, mock_pca_cls):
        """When the specific-tenant PCA succeeds on first try, no retry is needed."""
        from azure.cli.core.auth.msal_credentials import UserCredential

        main_app = self._make_msal_app_mock(tenant='tenant-00000001', silent_result=MOCK_TOKEN_RESULT)
        mock_pca_cls.return_value = main_app

        cred = UserCredential.__new__(UserCredential)
        cred._msal_app = main_app
        cred._account = MOCK_ACCOUNT_TENANT

        result = cred.acquire_token(MOCK_SCOPES)

        self.assertEqual(result, MOCK_TOKEN_RESULT)
        # acquire_token_silent_with_error should be called exactly once (no retry)
        main_app.acquire_token_silent_with_error.assert_called_once_with(
            MOCK_SCOPES, MOCK_ACCOUNT_TENANT, claims_challenge=None)
        # No second PublicClientApplication should be created for the retry
        mock_pca_cls.assert_not_called()

    @mock.patch('azure.cli.core.auth.msal_credentials.PublicClientApplication')
    def test_acquire_token_specific_tenant_retries_with_organizations(self, mock_pca_cls):
        """When the specific-tenant PCA returns None (token cached under 'organizations' realm),
        the fix retries using an 'organizations' authority PCA that shares the same token cache."""
        from azure.cli.core.auth.msal_credentials import UserCredential

        # First (specific-tenant) app returns None — simulating WAM broker AccountNotFound
        main_app = self._make_msal_app_mock(tenant='tenant-00000001', silent_result=None)

        # Second (organizations) app returns a valid token
        organizations_app = self._make_msal_app_mock(
            tenant='organizations',
            silent_result=MOCK_TOKEN_RESULT,
            accounts=[MOCK_ACCOUNT_ORGANIZATIONS],
        )
        mock_pca_cls.return_value = organizations_app

        cred = UserCredential.__new__(UserCredential)
        cred._msal_app = main_app
        cred._account = MOCK_ACCOUNT_TENANT

        result = cred.acquire_token(MOCK_SCOPES)

        self.assertEqual(result, MOCK_TOKEN_RESULT)

        # The retry PublicClientApplication must be constructed with the 'organizations' authority
        mock_pca_cls.assert_called_once_with(
            main_app.client_id,
            authority='https://login.microsoftonline.com/organizations',
            token_cache=main_app.token_cache,
        )
        # The retry must use the organizations-scoped account
        organizations_app.acquire_token_silent_with_error.assert_called_once_with(
            MOCK_SCOPES, MOCK_ACCOUNT_ORGANIZATIONS, claims_challenge=None)

    @mock.patch('azure.cli.core.auth.msal_credentials.PublicClientApplication')
    def test_acquire_token_both_miss_raises(self, mock_pca_cls):
        """When both the specific-tenant and the organizations silent acquisitions return None,
        AuthenticationError is raised."""
        from azure.cli.core.auth.msal_credentials import UserCredential
        from azure.cli.core.azclierror import AuthenticationError

        main_app = self._make_msal_app_mock(tenant='tenant-00000001', silent_result=None)
        organizations_app = self._make_msal_app_mock(
            tenant='organizations',
            silent_result=None,
            accounts=[MOCK_ACCOUNT_ORGANIZATIONS],
        )
        mock_pca_cls.return_value = organizations_app

        cred = UserCredential.__new__(UserCredential)
        cred._msal_app = main_app
        cred._account = MOCK_ACCOUNT_TENANT

        with self.assertRaises(AuthenticationError):
            cred.acquire_token(MOCK_SCOPES)

    @mock.patch('azure.cli.core.auth.msal_credentials.PublicClientApplication')
    def test_acquire_token_organizations_authority_no_retry(self, mock_pca_cls):
        """When the PCA already uses the 'organizations' authority, no retry loop is triggered
        even if the silent acquisition returns None."""
        from azure.cli.core.auth.msal_credentials import UserCredential
        from azure.cli.core.azclierror import AuthenticationError

        # PCA already scoped to 'organizations' — the retry condition is NOT met
        main_app = self._make_msal_app_mock(tenant='organizations', silent_result=None)
        main_app.get_accounts.return_value = [MOCK_ACCOUNT_ORGANIZATIONS]

        cred = UserCredential.__new__(UserCredential)
        cred._msal_app = main_app
        cred._account = MOCK_ACCOUNT_ORGANIZATIONS

        with self.assertRaises(AuthenticationError):
            cred.acquire_token(MOCK_SCOPES)

        # No secondary PublicClientApplication should be created — the retry is skipped
        mock_pca_cls.assert_not_called()

    @mock.patch('azure.cli.core.auth.msal_credentials.PublicClientApplication')
    def test_acquire_token_no_organizations_account_no_retry(self, mock_pca_cls):
        """If the organizations PCA finds no matching account in the cache, no retry call is made."""
        from azure.cli.core.auth.msal_credentials import UserCredential
        from azure.cli.core.azclierror import AuthenticationError

        main_app = self._make_msal_app_mock(tenant='tenant-00000001', silent_result=None)

        # organizations PCA has no accounts (e.g. user never logged in with organizations authority)
        organizations_app = self._make_msal_app_mock(
            tenant='organizations',
            silent_result=None,
            accounts=[],  # empty — no account found under organizations realm
        )
        mock_pca_cls.return_value = organizations_app

        cred = UserCredential.__new__(UserCredential)
        cred._msal_app = main_app
        cred._account = MOCK_ACCOUNT_TENANT

        with self.assertRaises(AuthenticationError):
            cred.acquire_token(MOCK_SCOPES)

        # organizations PCA was created (the retry was attempted)
        mock_pca_cls.assert_called_once()
        # But acquire_token_silent_with_error was NOT called because no account was found
        organizations_app.acquire_token_silent_with_error.assert_not_called()


if __name__ == '__main__':
    unittest.main()
