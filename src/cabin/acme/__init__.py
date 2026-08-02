"""cabin's own ACME v2 server (RFC 8555).

Written from RFC 8555 (+ RFC 7515/7517/7518/7638 for the JOSE layer and
RFC 7807 for the error documents) and the ``josepy``/``cryptography`` APIs.
django-ca and acme2certifier are GPLv3 and were consulted for observable
*behavior* only -- no code from either is reproduced or translated here.

Layering, outermost first:

* :mod:`cabin.acme.api` -- the router: the directory, the nonce endpoint,
  and the assembly (including the catch-all that makes "ACME is off" a 404
  everywhere). :mod:`~cabin.acme.api_account` and
  :mod:`~cabin.acme.api_order` hold the resource routes.
* :mod:`cabin.acme.http` -- what those routes share: URL building, the
  ``acme_enabled`` gate, the Replay-Nonce/Link middleware, the problem-
  document handler, and row-to-protocol-object serialization.
* :mod:`cabin.acme.service` -- accounts, orders, authorizations, challenges
  and the identifier policy; knows about the database, not about HTTP.
* :mod:`cabin.acme.jws` -- request authentication.
* :mod:`cabin.acme.nonces` -- replay protection.
* :mod:`cabin.acme.models` / :mod:`cabin.acme.errors` -- the storage shapes
  and the problem documents, imported by everything above.
"""
