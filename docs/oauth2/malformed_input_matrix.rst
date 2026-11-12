.. _malformed_input_matrix:

Malformed Input Behavior Matrix
===============================

The OAuth 2.0 gateway entries share a single error contract for malformed
request parameters: equally malformed inputs converge on controlled
``invalid_request`` responses instead of internal errors, regardless of
whether they arrive in the URI query string or the request body.

The contract is pinned by the ``MalformedInputTest`` suite in
``tests/oauth2/rfc6749/endpoints/test_error_responses.py`` and the
query-string flag tests in ``tests/test_common.py`` (``RequestTest``).

Malformation forms
------------------

=================== ==========================================================
Form                Example
=================== ==========================================================
Bad encoding        ``client_id=%ZZ`` (invalid percent-encoding)
Unencoded specials  ``client_id=foo bar`` (raw characters outside the
                    x-www-form-urlencoded alphabet)
Dangling parameter  ``client_id`` (no ``=`` separator)
Overlong parameter  ``client_id=aaaa...`` (100k characters)
=================== ==========================================================

Behavior matrix
---------------

Authorization endpoint (``create_authorization_response`` /
``validate_authorization_request``):

=================== ============================ ============================
Input               Response                     Notes
=================== ============================ ============================
query: bad encoding ``InvalidRequestFatalError`` fatal ``invalid_request``
query: unencoded    ``InvalidRequestFatalError`` (``error=invalid_request``,
specials                                       not redirected: client and
query: dangling                                redirect URI are unknowable)
parameter
query: overlong     normal validation flow       reaches the validator intact
body: any form      per grant-type validation    body of an authorization
                                                 request is not form-parsed
                                                 into OAuth parameters
=================== ============================ ============================

Token endpoint (``create_token_response``):

=================== ============================ ============================
Input               Response                     Notes
=================== ============================ ============================
query: bad encoding ``InvalidRequestError``      ``invalid_request``; any
query: unencoded                                 query on a POST is rejected
specials                                       anyway
query: dangling     ``InvalidRequestError``      "URL query parameters are
parameter                                        not allowed"
query: overlong     ``InvalidRequestError``      same rejection as above
body: bad encoding  400 JSON, controlled error   body is not valid
body: unencoded     (e.g.                        x-www-form-urlencoded, so it
specials            ``unsupported_grant_type``)  is treated as raw data and
body: dangling                                 OAuth parameters stay empty
parameter                                       (form-recognition contract)
body: overlong      normal validation flow       reaches the validator intact
=================== ============================ ============================

Protected resource validation (``verify_request``):

=================== ============================ ============================
Input               Response                     Notes
=================== ============================ ============================
query: bad encoding ``InvalidRequestError``      ``invalid_request``
query: unencoded    ``InvalidRequestError``      ``invalid_request``
specials
query: dangling     passed to token validator    unchanged legacy behavior
parameter
query: overlong     passed to token validator    reaches the validator intact
=================== ============================ ============================

Invariants
----------

* No malformed input at any of the three entries surfaces as an internal
  error (uncaught exception, or ``server_error``/HTTP 500 when
  ``catch_errors`` is enabled).
* ``oauthlib.common.Request`` never raises out of its constructor for a
  malformed query string; it drops the unparseable query parameters and
  sets ``request.malformed_query_string`` so the endpoints can reject the
  request with the controlled errors above.
* Dangling-parameter rejection semantics predate this contract and are
  unchanged: the authorization endpoint rejects them with
  ``InvalidRequestFatalError`` ("Unable to parse query string") via strict
  query parsing, and the token endpoint rejects any query component on
  POST requests.
* The form-recognition contract is unchanged: a request body that is not
  valid x-www-form-urlencoded is treated as raw body data
  (``request.decoded_body is None``), not as an error in itself.
* Normal (well-formed) requests are unaffected.
