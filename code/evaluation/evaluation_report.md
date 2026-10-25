# Evaluation Report

## 1. Evaluation Scope

The current baseline was evaluated using the 32 public sample deletion requests.

Predictions were generated using the participant-facing evidence dataset. The public sample output was used to compare the predictions after generation.

Command used:

```bash
python code/main.py --requests dataset/sample_deletion_requests.csv --output /tmp/sample_predictions.csv
```

## 2. Public-Sample Results

| Metric | Result |
|---|---:|
| Status accuracy | 29/32 = 90.625% |
| Exact `steps_json` match | 2/32 = 6.25% |
| Step-level accuracy | Not measured |
| Field-level accuracy | Not measured |
| Full 518-case evaluation | Not reported |

## 3. Observed Status Mismatches

The following cases had different predicted and expected status labels:

- `case_10`: predicted `COMPLETE`; expected `INCOMPLETE`.
- `case_16`: predicted `COMPLETE`; expected `INCOMPLETE`.
- `case_26`: predicted `INCOMPLETE`; expected `COMPLETE`.

These mismatches show that the status-classification logic still needs improvement.

## 4. Proposed Custom Test Cases

The following are proposed test specifications. They are not claims that the current implementation has passed these tests.

### Test Case A: Unauthorized Request

**Condition:** Available evidence establishes that the requester is not the data subject or an authorized representative.

**Expected behavior:**
- Return `NOT_APPLICABLE`.
- Set `steps_json` to an empty array: `[]`.
- Do not propose destructive remediation for an inapplicable request.

### Test Case B: Data Recreation Risk

**Condition:** Evidence shows that an active restore, import, or data-flow process can recreate personal data after deletion.

**Expected behavior:**
- Return `INCOMPLETE` while the relevant risk remains unresolved.
- Cite participant-facing evidence supporting the finding.
- Include appropriate proposed remediation.
- Leave `evidence_id` empty for proposed future actions that have not yet occurred.

### Test Case C: Retained Security Record

**Condition:** Policy requires a security or audit record to be retained, while direct identifiers must be redacted.

**Expected behavior:**
- Do not delete a record that policy requires to be retained.
- Verify required redaction or tombstone behavior using available evidence.
- Return `COMPLETE` only when all applicable deletion and retention requirements are satisfied.

## 5. Improvement Priorities

### 5.1 Status Classification

Investigate the three observed status mismatches and improve the logic for deciding whether deletion is complete.

### 5.2 Evidence and Resource IDs

Use evidence-supported identifiers. Avoid inventing resource IDs or evidence references when the available data does not support them.

### 5.3 Identity Resolution

Improve the handling of historical identities and ensure evidence is associated with the correct subject.

### 5.4 Timestamp Handling

Do not use evidence created after a request's `audit_at` timestamp to prove the state at the audit time.

### 5.5 Verification Coverage

Verify every applicable system and resource before marking a request `COMPLETE`.

### 5.6 Structural Evaluation

Implement reproducible step-level and field-level scoring to identify exact JSON mismatches.

## 6. Conclusion

The public sample status accuracy is 90.625%, while the exact `steps_json` match rate is 6.25%.

The low exact-match rate indicates that resource selection, evidence references, operation choices, verification coverage, and step ordering require further refinement.

These results are limited to the public sample and should not be interpreted as a guarantee of performance on the full dataset or hidden tests.
