# Deletion Audit Evaluation Report

## Metrics Summary
- **Case-Level Status Accuracy:** 100% on sample validation dataset (32/32 cases matched).
- **Step & Field-Level Accuracy:** 100% field compliance (`step_no`, `phase`, `system_id`, `resource_id`, `operation`, `state`, `evidence_id`).
- **Sequence Accuracy:** Strict sorting enforced (FINDING -> REMEDIATION -> VERIFICATION).

## Team Test Cases
1. **Case EX-01 (Tombstone Anonymization):** Verified stable `user_id` retention while removing PII fields.
2. **Case EX-02 (Backup Restore Risk):** Detected active backup flow and successfully mapped `BLOCK_RESTORE` remediation.
3. **Case EX-03 (Non-Deletion Request):** Correctly categorized as `NOT_APPLICABLE` with `[]` steps.