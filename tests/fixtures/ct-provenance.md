The `ct-github-leaf.der` and `ct-github-issuer.der` fixtures are the public leaf
and issuer certificates served by github.com on 2026-10-22. The leaf contains
SCTs from Google Argon2026h2 and Sectigo Tiger2026h2. Tests use a fixed date and
the bundled Google log-key snapshot; they do not contact GitHub or a CT provider.
No private keys are included. The fixtures test signature verification, not a
claim about GitHub's content or its current certificate.
