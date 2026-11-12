"""Ensure the correct error responses are returned for all defined error types.
"""
import json
from unittest import mock

from oauthlib.common import urlencode
from oauthlib.oauth2 import (
    BackendApplicationServer, LegacyApplicationServer, MobileApplicationServer,
    RequestValidator, WebApplicationServer,
)
from oauthlib.oauth2.rfc6749 import errors

from tests.unittest import TestCase


class ErrorResponseTest(TestCase):

    def set_client(self, request):
        request.client = mock.MagicMock()
        request.client.client_id = 'mocked'
        return True

    def setUp(self):
        self.validator = mock.MagicMock(spec=RequestValidator)
        self.validator.get_default_redirect_uri.return_value = None
        self.validator.get_code_challenge.return_value = None
        self.web = WebApplicationServer(self.validator)
        self.mobile = MobileApplicationServer(self.validator)
        self.legacy = LegacyApplicationServer(self.validator)
        self.backend = BackendApplicationServer(self.validator)

    def test_invalid_redirect_uri(self):
        uri = 'https://example.com/authorize?response_type={0}&client_id=foo&redirect_uri=wrong'

        # Authorization code grant
        self.assertRaises(errors.InvalidRedirectURIError,
                self.web.validate_authorization_request, uri.format('code'))
        self.assertRaises(errors.InvalidRedirectURIError,
                self.web.create_authorization_response, uri.format('code'), scopes=['foo'])

        # Implicit grant
        self.assertRaises(errors.InvalidRedirectURIError,
                self.mobile.validate_authorization_request, uri.format('token'))
        self.assertRaises(errors.InvalidRedirectURIError,
                self.mobile.create_authorization_response, uri.format('token'), scopes=['foo'])

    def test_invalid_default_redirect_uri(self):
        uri = 'https://example.com/authorize?response_type={0}&client_id=foo'
        self.validator.get_default_redirect_uri.return_value = "wrong"

        # Authorization code grant
        self.assertRaises(errors.InvalidRedirectURIError,
                self.web.validate_authorization_request, uri.format('code'))
        self.assertRaises(errors.InvalidRedirectURIError,
                self.web.create_authorization_response, uri.format('code'), scopes=['foo'])

        # Implicit grant
        self.assertRaises(errors.InvalidRedirectURIError,
                self.mobile.validate_authorization_request, uri.format('token'))
        self.assertRaises(errors.InvalidRedirectURIError,
                self.mobile.create_authorization_response, uri.format('token'), scopes=['foo'])

    def test_missing_redirect_uri(self):
        uri = 'https://example.com/authorize?response_type={0}&client_id=foo'

        # Authorization code grant
        self.assertRaises(errors.MissingRedirectURIError,
                self.web.validate_authorization_request, uri.format('code'))
        self.assertRaises(errors.MissingRedirectURIError,
                self.web.create_authorization_response, uri.format('code'), scopes=['foo'])

        # Implicit grant
        self.assertRaises(errors.MissingRedirectURIError,
                self.mobile.validate_authorization_request, uri.format('token'))
        self.assertRaises(errors.MissingRedirectURIError,
                self.mobile.create_authorization_response, uri.format('token'), scopes=['foo'])

    def test_mismatching_redirect_uri(self):
        uri = 'https://example.com/authorize?response_type={0}&client_id=foo&redirect_uri=https%3A%2F%2Fi.b%2Fback'

        # Authorization code grant
        self.validator.validate_redirect_uri.return_value = False
        self.assertRaises(errors.MismatchingRedirectURIError,
                self.web.validate_authorization_request, uri.format('code'))
        self.assertRaises(errors.MismatchingRedirectURIError,
                self.web.create_authorization_response, uri.format('code'), scopes=['foo'])

        # Implicit grant
        self.assertRaises(errors.MismatchingRedirectURIError,
                self.mobile.validate_authorization_request, uri.format('token'))
        self.assertRaises(errors.MismatchingRedirectURIError,
                self.mobile.create_authorization_response, uri.format('token'), scopes=['foo'])

    def test_missing_client_id(self):
        uri = 'https://example.com/authorize?response_type={0}&redirect_uri=https%3A%2F%2Fi.b%2Fback'

        # Authorization code grant
        self.validator.validate_redirect_uri.return_value = False
        self.assertRaises(errors.MissingClientIdError,
                self.web.validate_authorization_request, uri.format('code'))
        self.assertRaises(errors.MissingClientIdError,
                self.web.create_authorization_response, uri.format('code'), scopes=['foo'])

        # Implicit grant
        self.assertRaises(errors.MissingClientIdError,
                self.mobile.validate_authorization_request, uri.format('token'))
        self.assertRaises(errors.MissingClientIdError,
                self.mobile.create_authorization_response, uri.format('token'), scopes=['foo'])

    def test_invalid_client_id(self):
        uri = 'https://example.com/authorize?response_type={0}&client_id=foo&redirect_uri=https%3A%2F%2Fi.b%2Fback'

        # Authorization code grant
        self.validator.validate_client_id.return_value = False
        self.assertRaises(errors.InvalidClientIdError,
                self.web.validate_authorization_request, uri.format('code'))
        self.assertRaises(errors.InvalidClientIdError,
                self.web.create_authorization_response, uri.format('code'), scopes=['foo'])

        # Implicit grant
        self.assertRaises(errors.InvalidClientIdError,
                self.mobile.validate_authorization_request, uri.format('token'))
        self.assertRaises(errors.InvalidClientIdError,
                self.mobile.create_authorization_response, uri.format('token'), scopes=['foo'])

    def test_empty_parameter(self):
        uri = 'https://example.com/authorize?client_id=foo&redirect_uri=https%3A%2F%2Fi.b%2Fback&response_type=code&'

        # Authorization code grant
        self.assertRaises(errors.InvalidRequestFatalError,
                self.web.validate_authorization_request, uri)

        # Implicit grant
        self.assertRaises(errors.InvalidRequestFatalError,
                self.mobile.validate_authorization_request, uri)

    def test_invalid_request(self):
        self.validator.get_default_redirect_uri.return_value = 'https://i.b/cb'
        token_uri = 'https://i.b/token'

        invalid_bodies = [
            # duplicate params
            'grant_type=authorization_code&client_id=nope&client_id=nope&code=foo'
        ]
        for body in invalid_bodies:
            _, body, _ = self.web.create_token_response(token_uri,
                    body=body)
            self.assertEqual('invalid_request', json.loads(body)['error'])

        # Password credentials grant
        invalid_bodies = [
            # duplicate params
            'grant_type=password&username=foo&username=bar&password=baz'
            # missing username
            'grant_type=password&password=baz'
            # missing password
            'grant_type=password&username=foo'
        ]
        self.validator.authenticate_client.side_effect = self.set_client
        for body in invalid_bodies:
            _, body, _ = self.legacy.create_token_response(token_uri,
                    body=body)
            self.assertEqual('invalid_request', json.loads(body)['error'])

        # Client credentials grant
        invalid_bodies = [
            # duplicate params
            'grant_type=client_credentials&scope=foo&scope=bar'
        ]
        for body in invalid_bodies:
            _, body, _ = self.backend.create_token_response(token_uri,
                    body=body)
            self.assertEqual('invalid_request', json.loads(body)['error'])

    def test_invalid_request_duplicate_params(self):
        self.validator.get_default_redirect_uri.return_value = 'https://i.b/cb'
        uri = 'https://i.b/auth?client_id=foo&client_id=bar&response_type={0}'
        description = 'Duplicate client_id parameter.'

        # Authorization code
        self.assertRaisesRegex(errors.InvalidRequestFatalError,
                              description,
                              self.web.validate_authorization_request,
                              uri.format('code'))
        self.assertRaisesRegex(errors.InvalidRequestFatalError,
                              description,
                              self.web.create_authorization_response,
                              uri.format('code'), scopes=['foo'])

        # Implicit grant
        self.assertRaisesRegex(errors.InvalidRequestFatalError,
                              description,
                              self.mobile.validate_authorization_request,
                              uri.format('token'))
        self.assertRaisesRegex(errors.InvalidRequestFatalError,
                              description,
                              self.mobile.create_authorization_response,
                              uri.format('token'), scopes=['foo'])

    def test_invalid_request_duplicate_response_mode(self):
        self.validator.get_default_redirect_uri.return_value = 'https://i.b/cb'
        uri = 'https://i.b/auth?client_id=foo&response_mode=query&response_mode=fragment&response_type={0}'
        description = 'Duplicate response_mode parameter.'

        # Authorization code
        self.assertRaisesRegex(errors.InvalidRequestFatalError,
                              description,
                              self.web.create_authorization_response,
                              uri.format('code'), scopes=['foo'])

        # Implicit grant
        self.assertRaisesRegex(errors.InvalidRequestFatalError,
                              description,
                              self.mobile.create_authorization_response,
                              uri.format('token'), scopes=['foo'])

    def test_unsupported_response_mode(self):
        self.validator.get_default_redirect_uri.return_value = 'https://i.b/cb'
        uri = 'https://i.b/auth?client_id=foo&response_mode=form_post&response_type={0}'

        # Authorization code
        self.assertRaises(errors.UnsupportedResponseModeError,
                          self.web.validate_authorization_request, uri.format('code'))
        self.assertRaises(errors.UnsupportedResponseModeError,
                          self.web.create_authorization_response, uri.format('code'), scopes=['foo'])

        # Implicit grant
        self.assertRaises(errors.UnsupportedResponseModeError,
                          self.mobile.validate_authorization_request, uri.format('token'))
        self.assertRaises(errors.UnsupportedResponseModeError,
                          self.mobile.create_authorization_response, uri.format('token'), scopes=['foo'])

    def test_invalid_request_missing_response_type(self):

        self.validator.get_default_redirect_uri.return_value = 'https://i.b/cb'

        uri = 'https://i.b/auth?client_id=foo'

        # Authorization code
        self.assertRaises(errors.MissingResponseTypeError,
                          self.web.validate_authorization_request,
                          uri.format('code'))
        h, _, s = self.web.create_authorization_response(uri, scopes=['foo'])
        self.assertEqual(s, 302)
        self.assertIn('Location', h)
        self.assertIn('error=invalid_request', h['Location'])

        # Implicit grant
        self.assertRaises(errors.MissingResponseTypeError,
                          self.mobile.validate_authorization_request,
                          uri.format('token'))
        h, _, s = self.mobile.create_authorization_response(uri, scopes=['foo'])
        self.assertEqual(s, 302)
        self.assertIn('Location', h)
        self.assertIn('error=invalid_request', h['Location'])

    def test_unauthorized_client(self):
        self.validator.get_default_redirect_uri.return_value = 'https://i.b/cb'
        self.validator.validate_grant_type.return_value = False
        self.validator.validate_response_type.return_value = False
        self.validator.authenticate_client.side_effect = self.set_client
        token_uri = 'https://i.b/token'

        # Authorization code grant
        self.assertRaises(errors.UnauthorizedClientError,
                self.web.validate_authorization_request,
                'https://i.b/auth?response_type=code&client_id=foo')
        _, body, _ = self.web.create_token_response(token_uri,
                body='grant_type=authorization_code&code=foo')
        self.assertEqual('unauthorized_client', json.loads(body)['error'])

        # Implicit grant, errors default to the fragment response mode
        with self.assertRaises(errors.UnauthorizedClientError) as cm:
            self.mobile.validate_authorization_request(
                'https://i.b/auth?response_type=token&client_id=foo')
        uri = cm.exception.in_uri(cm.exception.redirect_uri)
        self.assertIn('#error=unauthorized_client', uri)
        self.assertNotIn('?error=', uri)

        # Password credentials grant
        _, body, _ = self.legacy.create_token_response(token_uri,
                body='grant_type=password&username=foo&password=bar')
        self.assertEqual('unauthorized_client', json.loads(body)['error'])

        # Client credentials grant
        _, body, _ = self.backend.create_token_response(token_uri,
                body='grant_type=client_credentials')
        self.assertEqual('unauthorized_client', json.loads(body)['error'])

    def test_access_denied(self):
        self.validator.authenticate_client.side_effect = self.set_client
        self.validator.get_default_redirect_uri.return_value = 'https://i.b/cb'
        self.validator.confirm_redirect_uri.return_value = False
        token_uri = 'https://i.b/token'
        # Authorization code grant
        _, body, _ = self.web.create_token_response(token_uri,
                body='grant_type=authorization_code&code=foo')
        self.assertEqual('invalid_request', json.loads(body)['error'])

    def test_access_denied_no_default_redirecturi(self):
        self.validator.authenticate_client.side_effect = self.set_client
        self.validator.get_default_redirect_uri.return_value = None
        token_uri = 'https://i.b/token'
        # Authorization code grant
        _, body, _ = self.web.create_token_response(token_uri,
                body='grant_type=authorization_code&code=foo')
        self.assertEqual('invalid_request', json.loads(body)['error'])

    def test_unsupported_response_type(self):
        self.validator.get_default_redirect_uri.return_value = 'https://i.b/cb'

        # Authorization code grant
        self.assertRaises(errors.UnsupportedResponseTypeError,
                self.web.validate_authorization_request,
                'https://i.b/auth?response_type=foo&client_id=foo')

        # Implicit grant
        self.assertRaises(errors.UnsupportedResponseTypeError,
                self.mobile.validate_authorization_request,
                'https://i.b/auth?response_type=foo&client_id=foo')

    def test_invalid_scope(self):
        self.validator.get_default_redirect_uri.return_value = 'https://i.b/cb'
        self.validator.validate_scopes.return_value = False
        self.validator.authenticate_client.side_effect = self.set_client

        # Authorization code grant
        self.assertRaises(errors.InvalidScopeError,
                self.web.validate_authorization_request,
                'https://i.b/auth?response_type=code&client_id=foo')

        # Implicit grant
        self.assertRaises(errors.InvalidScopeError,
                self.mobile.validate_authorization_request,
                'https://i.b/auth?response_type=token&client_id=foo')

        # Password credentials grant
        _, body, _ = self.legacy.create_token_response(
                'https://i.b/token',
                body='grant_type=password&username=foo&password=bar')
        self.assertEqual('invalid_scope', json.loads(body)['error'])

        # Client credentials grant
        _, body, _ = self.backend.create_token_response(
                'https://i.b/token',
                body='grant_type=client_credentials')
        self.assertEqual('invalid_scope', json.loads(body)['error'])

    def test_server_error(self):
        def raise_error(*args, **kwargs):
            raise ValueError()

        self.validator.validate_client_id.side_effect = raise_error
        self.validator.authenticate_client.side_effect = raise_error
        self.validator.get_default_redirect_uri.return_value = 'https://i.b/cb'

        # Authorization code grant
        self.web.catch_errors = True
        _, _, s = self.web.create_authorization_response(
                'https://i.b/auth?client_id=foo&response_type=code',
                scopes=['foo'])
        self.assertEqual(s, 500)
        _, _, s = self.web.create_token_response(
                'https://i.b/token',
                body='grant_type=authorization_code&code=foo',
                scopes=['foo'])
        self.assertEqual(s, 500)

        # Implicit grant
        self.mobile.catch_errors = True
        _, _, s = self.mobile.create_authorization_response(
                'https://i.b/auth?client_id=foo&response_type=token',
                scopes=['foo'])
        self.assertEqual(s, 500)

        # Password credentials grant
        self.legacy.catch_errors = True
        _, _, s = self.legacy.create_token_response(
                'https://i.b/token',
                body='grant_type=password&username=foo&password=foo')
        self.assertEqual(s, 500)

        # Client credentials grant
        self.backend.catch_errors = True
        _, _, s = self.backend.create_token_response(
                'https://i.b/token',
                body='grant_type=client_credentials')
        self.assertEqual(s, 500)

    def test_temporarily_unavailable(self):
        # Authorization code grant
        self.web.available = False
        _, _, s = self.web.create_authorization_response(
                'https://i.b/auth?client_id=foo&response_type=code',
                scopes=['foo'])
        self.assertEqual(s, 503)
        _, _, s = self.web.create_token_response(
                'https://i.b/token',
                body='grant_type=authorization_code&code=foo',
                scopes=['foo'])
        self.assertEqual(s, 503)

        # Implicit grant
        self.mobile.available = False
        _, _, s = self.mobile.create_authorization_response(
                'https://i.b/auth?client_id=foo&response_type=token',
                scopes=['foo'])
        self.assertEqual(s, 503)

        # Password credentials grant
        self.legacy.available = False
        _, _, s = self.legacy.create_token_response(
                'https://i.b/token',
                body='grant_type=password&username=foo&password=foo')
        self.assertEqual(s, 503)

        # Client credentials grant
        self.backend.available = False
        _, _, s = self.backend.create_token_response(
                'https://i.b/token',
                body='grant_type=client_credentials')
        self.assertEqual(s, 503)

    def test_invalid_client(self):
        self.validator.authenticate_client.return_value = False
        self.validator.authenticate_client_id.return_value = False

        # Authorization code grant
        _, body, _ = self.web.create_token_response('https://i.b/token',
                body='grant_type=authorization_code&code=foo')
        self.assertEqual('invalid_client', json.loads(body)['error'])

        # Password credentials grant
        _, body, _ = self.legacy.create_token_response('https://i.b/token',
                body='grant_type=password&username=foo&password=bar')
        self.assertEqual('invalid_client', json.loads(body)['error'])

        # Client credentials grant
        _, body, _ = self.backend.create_token_response('https://i.b/token',
                body='grant_type=client_credentials')
        self.assertEqual('invalid_client', json.loads(body)['error'])

    def test_invalid_grant(self):
        self.validator.authenticate_client.side_effect = self.set_client

        # Authorization code grant
        self.validator.validate_code.return_value = False
        _, body, _ = self.web.create_token_response('https://i.b/token',
                body='grant_type=authorization_code&code=foo')
        self.assertEqual('invalid_grant', json.loads(body)['error'])

        # Password credentials grant
        self.validator.validate_user.return_value = False
        _, body, _ = self.legacy.create_token_response('https://i.b/token',
                body='grant_type=password&username=foo&password=bar')
        self.assertEqual('invalid_grant', json.loads(body)['error'])

    def test_unsupported_grant_type(self):
        self.validator.authenticate_client.side_effect = self.set_client

        # Authorization code grant
        _, body, _ = self.web.create_token_response('https://i.b/token',
                body='grant_type=bar&code=foo')
        self.assertEqual('unsupported_grant_type', json.loads(body)['error'])

        # Password credentials grant
        _, body, _ = self.legacy.create_token_response('https://i.b/token',
                body='grant_type=bar&username=foo&password=bar')
        self.assertEqual('unsupported_grant_type', json.loads(body)['error'])

        # Client credentials grant
        _, body, _ = self.backend.create_token_response('https://i.b/token',
                body='grant_type=bar')
        self.assertEqual('unsupported_grant_type', json.loads(body)['error'])

    def test_invalid_request_method(self):
        test_methods = ['GET', 'pUt', 'dEleTe', 'paTcH']
        test_methods = test_methods + [x.lower() for x in test_methods] + [x.upper() for x in test_methods]
        for method in test_methods:
            self.validator.authenticate_client.side_effect = self.set_client

            uri = "http://i/b/token/"
            try:
                _, _body, _s = self.web.create_token_response(uri,
                        body='grant_type=access_token&code=123', http_method=method)
                self.fail('This should have failed with InvalidRequestError')
            except errors.InvalidRequestError as ire:
                self.assertIn('Unsupported request method', ire.description)

            try:
                _, _body, _s = self.legacy.create_token_response(uri,
                        body='grant_type=access_token&code=123', http_method=method)
                self.fail('This should have failed with InvalidRequestError')
            except errors.InvalidRequestError as ire:
                self.assertIn('Unsupported request method', ire.description)

            try:
                _, _body, _s = self.backend.create_token_response(uri,
                        body='grant_type=access_token&code=123', http_method=method)
                self.fail('This should have failed with InvalidRequestError')
            except errors.InvalidRequestError as ire:
                self.assertIn('Unsupported request method', ire.description)

    def test_invalid_content_type(self):
        """
        Test that requests with invalid content-type raise UnsupportedContentTypeError
        """
        self.validator.authenticate_client.side_effect = self.set_client

        uri = "http://i/b/token/"
        expected_content_type = "application/x-www-form-urlencoded"
        invalid_headers = {
            'Content-Type': 'application/json'
        }

        try:
            _h, _b, _s = self.web.create_token_response(uri,
                    body='grant_type=access_token&code=123', headers=invalid_headers)
            self.fail('This should have failed with UnsupportedContentTypeError')
        except errors.UnsupportedContentTypeError as ire:
            self.assertIn(expected_content_type, ire.description)

        try:
            _h, _b, _s = self.legacy.create_token_response(uri,
                    body='grant_type=access_token&code=123', headers=invalid_headers)
            self.fail('This should have failed with UnsupportedContentTypeError')
        except errors.UnsupportedContentTypeError as ire:
            self.assertIn(expected_content_type, ire.description)

        try:
            _h, _b, _s = self.backend.create_token_response(uri,
                    body='grant_type=access_token&code=123', headers=invalid_headers)
            self.fail('This should have failed with UnsupportedContentTypeError')
        except errors.UnsupportedContentTypeError as ire:
            self.assertIn(expected_content_type, ire.description)

    def test_invalid_post_request(self):
        self.validator.authenticate_client.side_effect = self.set_client
        for param in ['token', 'secret', 'code', 'foo']:
            uri = 'https://i/b/token?' + urlencode([(param, 'secret')])
            try:
                _, _body, _s = self.web.create_token_response(uri,
                        body='grant_type=access_token&code=123')
                self.fail('This should have failed with InvalidRequestError')
            except errors.InvalidRequestError as ire:
                self.assertIn('URL query parameters are not allowed', ire.description)

            try:
                _, _body, _s = self.legacy.create_token_response(uri,
                        body='grant_type=access_token&code=123')
                self.fail('This should have failed with InvalidRequestError')
            except errors.InvalidRequestError as ire:
                self.assertIn('URL query parameters are not allowed', ire.description)

            try:
                _, _body, _s = self.backend.create_token_response(uri,
                        body='grant_type=access_token&code=123')
                self.fail('This should have failed with InvalidRequestError')
            except errors.InvalidRequestError as ire:
                self.assertIn('URL query parameters are not allowed', ire.description)


class MalformedInputTest(TestCase):
    """Behavior baseline for malformed request parameters.

    Pins the error contract for malformed input at the three gateway
    entries (authorization endpoint, token endpoint, protected resource
    validation): equally malformed inputs must converge on controlled
    invalid_request responses instead of internal errors, regardless of
    whether they arrive in the query string or the request body.

    Malformation forms covered: bad percent-encoding, dangling
    parameters, unencoded special characters and overlong parameters.
    """

    def set_client(self, request):
        request.client = mock.MagicMock()
        request.client.client_id = 'mocked'
        return True

    def setUp(self):
        self.validator = mock.MagicMock(spec=RequestValidator)
        self.validator.get_default_redirect_uri.return_value = 'https://i.b/cb'
        self.validator.get_code_challenge.return_value = None
        self.web = WebApplicationServer(self.validator)
        self.mobile = MobileApplicationServer(self.validator)
        self.legacy = LegacyApplicationServer(self.validator)
        self.backend = BackendApplicationServer(self.validator)

    # Query strings that are not valid x-www-form-urlencoded.
    malformed_queries = [
        '%ZZ',        # bad percent-encoding
        'foo bar',    # unencoded special characters
    ]

    def assert_fatal_invalid_request(self, func, *args, **kwargs):
        with self.assertRaises(errors.InvalidRequestFatalError) as cm:
            func(*args, **kwargs)
        self.assertEqual('invalid_request', cm.exception.error)
        self.assertIn('Unable to parse query string', cm.exception.description)

    def assert_invalid_request(self, func, *args, **kwargs):
        with self.assertRaises(errors.InvalidRequestError) as cm:
            func(*args, **kwargs)
        self.assertEqual('invalid_request', cm.exception.error)
        self.assertIn('Unable to parse query string', cm.exception.description)

    def test_authorization_endpoint_malformed_query(self):
        # Bad encoding and unencoded special characters in the query string
        # are rejected with a fatal invalid_request, never an internal error.
        for bad in self.malformed_queries:
            uri = 'https://i.b/auth?client_id=%s&response_type={0}' % bad
            for server, response_type in ((self.web, 'code'), (self.mobile, 'token')):
                self.assert_fatal_invalid_request(
                        server.validate_authorization_request, uri.format(response_type))
                self.assert_fatal_invalid_request(
                        server.create_authorization_response,
                        uri.format(response_type), scopes=['foo'])

    def test_authorization_endpoint_dangling_query_param(self):
        # Existing rejection semantics for dangling parameters are unchanged.
        uri = 'https://i.b/auth?client_id&response_type={0}'
        for server, response_type in ((self.web, 'code'), (self.mobile, 'token')):
            self.assert_fatal_invalid_request(
                    server.validate_authorization_request, uri.format(response_type))
            self.assert_fatal_invalid_request(
                    server.create_authorization_response,
                    uri.format(response_type), scopes=['foo'])

    def test_authorization_endpoint_overlong_param(self):
        # Overlong parameters are not malformed: they flow through normal
        # validation without any internal error.
        uri = 'https://i.b/auth?client_id=%s&response_type={0}' % ('a' * 100000)
        for server, response_type in ((self.web, 'code'), (self.mobile, 'token')):
            self.assertTrue(server.validate_authorization_request(
                uri.format(response_type)))

    def test_token_endpoint_malformed_query(self):
        for bad in self.malformed_queries:
            uri = 'https://i.b/token?client_id=%s' % bad
            for server in (self.web, self.legacy, self.backend):
                self.assert_invalid_request(
                        server.create_token_response, uri,
                        body='grant_type=client_credentials')

    def test_token_endpoint_malformed_query_not_a_server_error(self):
        # With catch_errors enabled a malformed query string must still
        # surface as invalid_request, never as a 500 server_error.
        self.web.catch_errors = True
        for bad in self.malformed_queries:
            self.assert_invalid_request(
                    self.web.create_token_response,
                    'https://i.b/token?client_id=%s' % bad,
                    body='grant_type=client_credentials')

    def test_token_endpoint_malformed_body_form_recognition(self):
        # Form recognition contract: a body that is not valid
        # x-www-form-urlencoded is treated as raw body data, so the request
        # fails later with a controlled 400, never a 500.
        malformed_bodies = [
            'grant_type=%ZZ',     # bad percent-encoding
            'grant_type=auth code',  # unencoded special characters
            'grant_type',         # dangling parameter
        ]
        self.validator.authenticate_client.side_effect = self.set_client
        for body in malformed_bodies:
            for server in (self.web, self.legacy, self.backend):
                _, body_json, status = server.create_token_response(
                        'https://i.b/token', body=body)
                self.assertEqual(400, status)
                error = json.loads(body_json)['error']
                self.assertNotIn(error, ('server_error',))

    def test_token_endpoint_overlong_body_param(self):
        # Overlong parameters are not malformed: they reach the validator
        # intact and the response stays controlled (here invalid_scope).
        self.validator.authenticate_client.side_effect = self.set_client
        self.validator.validate_scopes.return_value = False
        overlong_scope = 'a' * 100000
        _, body_json, status = self.backend.create_token_response(
                'https://i.b/token',
                body='grant_type=client_credentials&scope=' + overlong_scope)
        self.assertEqual(400, status)
        self.assertEqual('invalid_scope', json.loads(body_json)['error'])
        self.assertEqual([overlong_scope],
                self.validator.validate_scopes.call_args[0][1])

    def test_resource_endpoint_malformed_query(self):
        for bad in self.malformed_queries:
            uri = 'https://i.b/resource?access_token=%s' % bad
            for server in (self.web, self.legacy, self.backend):
                self.assert_invalid_request(server.verify_request, uri)

    def test_resource_endpoint_malformed_query_not_a_server_error(self):
        self.web.catch_errors = True
        for bad in self.malformed_queries:
            self.assert_invalid_request(
                    self.web.verify_request,
                    'https://i.b/resource?access_token=%s' % bad)

    def test_resource_endpoint_dangling_and_overlong_query_param(self):
        # Dangling and overlong query parameters are not rejected at parse
        # time; they reach the token validator as before.
        self.validator.validate_bearer_token.return_value = False
        for uri in ('https://i.b/resource?access_token',
                    'https://i.b/resource?access_token=' + 'a' * 100000):
            valid, _request = self.web.verify_request(uri)
            self.assertFalse(valid)
            self.assertTrue(self.validator.validate_bearer_token.called)
