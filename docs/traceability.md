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
| FR-06-001 / IR-COM-004 | connectors/base.py, pipeline.py (allow_external) | test_not_configured_makes_no_call, test_external_off_by_default_no_call |
| FR-06-002 / IR-UI-003 | GET /api/v1/disclosure | test_disclosure_endpoint |
| FR-06-003 | pipeline._evidence_from | test_malicious_hit_adds_provenance_and_floor |
| FR-06-004 | connectors/base.py (cache, rate limit) | test_cache_prevents_second_call, test_rate_limit |
| FR-06-005 / NFR-SEC-004 | connectors/base.py | test_failures_are_unavailable_never_a_verdict, test_timeout_does_not_change_verdict |
| FR-06-006 | pipeline.run (partial status) | test_timeout_does_not_change_verdict |
| FR-01-007 | connectors/privacy.py | test_privacy_filter_removes_query_and_userinfo |
| FR-03-003/004 | analyzers/sender.py | tests/test_sender_conversation.py |
| FR-05-001/002/003/004 | analyzers/conversation.py, pipeline.py | tests/test_sender_conversation.py |
| FR-09-001/005 | db/models.py, services/store.py (audit events) | tests/test_persistence.py |
| FR-09-002 | store.add_feedback, scrub | test_feedback_scrubs_identifiers |
| FR-09-003 | store.delete (cascade, content-free audit) | test_delete_removes_everything_but_content_free_audit |
| NFR-PERF-001 | audit detail.duration_ms | test_audit_event_records_versions_status_and_timing |
| FR-04 (OCR), FR-08 full | TODO | TODO |
