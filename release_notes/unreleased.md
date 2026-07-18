**Unreleased**

* Reject private-file upload URLs outside the trusted VirusTotal HTTPS origin.
* Validate and encode identifiers before inserting them into VirusTotal API paths.
* Mask ZIP passwords and exclude them from persisted action-result parameters.
* Bound unlimited pagination and reject repeated API cursors.
* Normalize DTM alert severity with a fail-high default and continue after individual ingestion failures.
* Stop DTM pagination on empty pages, repeated tokens, or its calculated page cap.
