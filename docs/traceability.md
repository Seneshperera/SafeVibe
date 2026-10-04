# Traceability (SRS requirement -> code -> test)

| Requirement | Code | Test |
|---|---|---|
| FR-01-001/002/005 | input_manager/manager.py | tests/test_input_manager.py |
| FR-01-004 | input_manager/manager.py | test_conversation_order_preserved |
| FR-02-001/002 | analyzers/message.py, rules/rules_v1.yaml | tests/test_analyzers.py |
| FR-03-001/002 | analyzers/url.py | tests/test_analyzers.py |
| FR-07-001/003/005/006 | risk/engine.py | tests/test_risk_engine.py, test_api.py |
| FR-09-003 | api/routes.py, services/store.py | test_delete_flow |
| FR-03-005 / IR-COM-005 | URL analyzer is string-only, never fetches | (by design) |
| FR-06, FR-04, FR-05, FR-08 full | TODO | TODO |
