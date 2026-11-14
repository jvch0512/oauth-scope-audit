test:
	python3 -m unittest discover -s tests -v

sample:
	mkdir -p docs site
	python3 -m oauth_scope_audit examples/grants.json --today 2026-11-14 > docs/sample-output.txt; true
	python3 -m oauth_scope_audit examples/grants.json --today 2026-11-14 --tsv > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "oauth-scope-audit" "Audits third-party OAuth app grants (Microsoft 365, Google Workspace exports) for risky scopes, unverified publishers and stale access. Python." "Synthetic app grants, evaluated at 2026-11-14."
