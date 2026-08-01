"""CA hierarchy: root+intermediate creation/import and DB-backed storage.

``cabin.ca.x509`` is pure pyca/cryptography code (no FastAPI/DB imports);
``cabin.ca.service`` orchestrates it against the database and secrets layer.
"""
