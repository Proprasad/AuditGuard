# AuditGuard Phase 4 — Human Worksheet Scoring Guidelines

## 1. Purpose & Independence Protocol
Two human annotators independently score the **same 60 blinded investigation worksheets** (`WS-CAL-001` through `WS-CAL-060`) to calibrate and validate the cross-family LLM judge.

- **Annotator 1 file:** `eval/human_labels/worksheets_to_score_annotator_1.csv`
- **Annotator 2 file:** `eval/human_labels/worksheets_to_score_annotator_2.csv`
- **Blinded worksheet packet:** `eval/human_labels/worksheets_packet_blinded.jsonl`
- **Full anchor rubric:** `eval/judge_rubric.md`

### Strict Blindness & Independence Rules
1. **Work independently.** Do not view the other annotator's CSV, discuss individual `WS-CAL-*` items before submitting initial scores, or inspect `eval/calibration_manifest/`.
2. **Blinded presentation.** Each `WS-CAL-*` item intentionally hides originating agent mode, LLM model, split (`dev` vs `held_out`), gold label, and outcome correctness. Presentation order is randomized independently in each CSV.
3. **Pilot pass recommended.** Score your first 10 items independently, check rubric-wording questions on general principles only (never held-out specifics), and complete all 60 rows.

---

## 2. CSV Schema & Allowed Values

Every row in your assigned CSV has the columns:

`worksheet_id,annotator,G1,G2,G3,G4,G5,G6,G7,comments`

| Column | Type / Allowed Values | Meaning |
|---|---|---|
| `worksheet_id` | `WS-CAL-001` .. `WS-CAL-060` | Pre-populated anonymized ID (do not edit or duplicate). |
| `annotator` | Non-empty string (e.g. `annotator_1`) | Your annotator identifier. |
| `G1` | Integer `1`, `2`, `3`, `4`, or `5` | **Grounding:** material claims cite valid supporting `TXN-*/PATH-*/KYC-*/REGISTRY-*/CALC-*` IDs. |
| `G2` | `pass` or `fail` | **Numeric fidelity:** all INR amounts and `%` match tool outputs within ₹0.01. |
| `G3` | Integer `1`, `2`, `3`, `4`, or `5` | **Balance:** strongest competing hypothesis (`benign` vs `suspicious`) substantively weighed. |
| `G4` | Integer `1`, `2`, `3`, `4`, or `5` | **Appropriate uncertainty:** missing evidence stated explicitly; confidence calibrated to gaps. |
| `G5` | Integer `1`, `2`, `3`, `4`, or `5` | **Citation relevance:** cited `REG-*/SOP-*` clauses exist and govern the claims/disposition. |
| `G6` | `pass` or `fail` | **Tone/compliance:** zero criminal-guilt declarations and zero tipping-off language. |
| `G7` | Integer `1`, `2`, `3`, `4`, or `5` | **Actionability:** clear, concrete next step for the human compliance reviewer. |
| `comments` | Optional free text | Brief note explaining any low score (`<= 2` or `fail`) or ambiguity. |

---

## 3. Validation Rules Enforced by `eval/calibration.py`
- Leave unscored rows completely blank until you score all 7 criteria (`G1`–`G7`) for that row; partially filled rows fail validation (`MISSING_CRITERIA`).
- Never enter `0`, decimals, or out-of-range integers (`1..5` only for `G1, G3, G4, G5, G7`; `pass` or `fail` only for `G2, G6`).
- Run status check at any time:
  ```bash
  python -m eval.calibration --labels eval/human_labels --out runs/cal/
  ```
