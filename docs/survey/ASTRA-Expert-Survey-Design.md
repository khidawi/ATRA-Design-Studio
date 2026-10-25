# ASTRA expert survey: design, codebook and analysis plan

The form is built by `create_astra_expert_form.gs` (Google Apps Script). This note explains the design, how answers appear in the CSV, and how to analyse them.

## 1. Structure (about 15 minutes; 20 with the optional usability part)

| Section | Content | Items | Type |
|---|---|---|---|
| Consent | Information, voluntary, anonymity, data use, ethics reference | C1 (2 boxes) | Required checkboxes |
| A. About you | Sector, role, experience, expertise, standards familiarity, agent experience, organisation size, region | P1 to P9 | Categorical, one 4-item grid |
| B. Evaluation | Usefulness, relevance, understandability, credibility, intention to use; module ratings; recommendation | PU1-4, RL1-4, EU1-4, CR1-4, IN1-3, M1-7, B7 | 5-point Likert grids, 0-10 scale |
| C. Hands-on experience (branch) | Only for people who used the studio: System Usability Scale and four studio items | U0, SUS1-10, UX1-4 | Likert grids |
| D. Priorities and adoption | Top-3 capabilities, top-3 barriers, deployment preference, pilot interest | D1-D4 | Checkbox (max 3), categorical |
| E. Comments | Strengths, limitations, gaps, misuse risks, one change, other | Q1-Q6, F1, F2 | Free text |

**Why these constructs.** Usefulness, understandability and intention to use follow the Technology Acceptance Model (Davis, 1989), the standard way to evaluate a new tool. Relevance and credibility address whether a *framework* is fit for purpose and rigorous, which TAM does not cover. The System Usability Scale (Brooke, 1996) gives a benchmarkable usability score (average around 68), but only from people who actually used the studio, hence the branch.

**Bias controls.** EU4 and CR4 are worded negatively so that straight-lining shows up and a "concern" is captured explicitly; reverse-score them before analysis. Section B has no neutral-leading wording. Critical feedback is invited in the introduction and in Q2, Q4 and Q5, which are required so strengths are not the only thing recorded.

## 2. Settings that matter for the research

- **Anonymous by default:** email is not collected and no Google sign-in is needed, so response rates are higher and consent is simpler. F2 is optional and only for follow-up.
- **No edits after submission;** one response per person is not enforced (that would force sign-in). Ask participants to answer once, and check for duplicate timestamps with identical answers.
- **Responses go to a Google Sheet** (created by the script). Download as CSV with *File > Download > Comma-separated values*. Keep the original sheet untouched and analyse a copy.
- **Ethics:** replace the placeholders in the consent text (approval reference, researcher, data controller). Confirm with your ethics committee that anonymous expert surveys of this kind are covered, and that Google as a processor is acceptable for your institution.

## 3. How the CSV looks and how to code it

Google puts each question title in the column header, and each row of a grid in its own column as `Title [row text]`. Because every title and row starts with a code, columns are easy to rename (for example `PU1`, `SUS3`). Grids, scales and single choices export as text that begins with the number, so recode with the leading digit.

| Variable group | Export looks like | Recode |
|---|---|---|
| P1-P4, P7-P9, D3, D4, F1 | the chosen option as text | factor; order P3, P4, P8 as ordinal |
| P5, D1, D2 | one cell, answers separated by commas | split into 0/1 indicator columns (one per option) |
| P6, PU, RL, EU, CR, IN, SUS, UX | `1 Strongly disagree` ... `5 Strongly agree` | take the leading digit as 1-5 |
| EU4, CR4 | same | reverse: `6 - x`, call them EU4r, CR4r |
| SUS2,4,6,8,10 | same | negative items; SUS score below |
| M1-M7 | `1 Not useful` ... `5 Very useful`, `Cannot judge` | digit 1-5; `Cannot judge` becomes missing and is counted separately |
| B7 | 0 to 10 | numeric |
| Q1-Q6 | free text | qualitative coding |

**Constructs (mean of the items, after reverse scoring):** Usefulness = PU1-4; Relevance = RL1-4; Understandability = EU1-4r; Credibility = CR1-4r; Intention = IN1-3.

**SUS score:** for odd items use `x - 1`; for even items use `5 - x`; sum the ten and multiply by 2.5, giving 0 to 100. Report it only for the people who answered Section C.

## 4. Analysis plan for about 30 responses

30 is enough for solid descriptive and exploratory work, not for strong inference. Plan accordingly and say so in the paper.

1. **Describe the sample:** counts and percentages for P1-P9. If one sector dominates, say so.
2. **Descriptives per construct and item:** median and interquartile range (Likert data are ordinal), with mean and standard deviation alongside for comparison with other work. Show a diverging stacked bar chart per item. Report the share agreeing (4 or 5).
3. **Reliability:** Cronbach's alpha per construct. With 4 items and n of 30 it is unstable; report it with that caveat, and give item-total correlations.
4. **Group comparisons:** academia against industry (and against government or consultancy if numbers allow) with the Mann-Whitney U test and an effect size (rank-biserial or Cliff's delta). Keep to a few planned comparisons and state them in advance; correct for multiple tests (Holm), and do not over-read p values with groups of 10 to 15.
5. **Relationships:** Spearman correlations between constructs, mainly Usefulness and Understandability with Intention, in the TAM spirit. Treat as exploratory.
6. **Module ratings (M1-M7):** rank by median; report how many answered "cannot judge" per module, since that is also a finding.
7. **Priorities and barriers (D1, D2):** frequency of each option by sector; they show where the framework should go next (for example real-time blocking if it ranks high).
8. **Open text (Q1-Q6):** reflexive thematic analysis. Two coders independently code a sample, agree a codebook, then code all answers; report agreement (Cohen's kappa) on the shared sample. Use themes such as *strengths*, *limits of scope*, *complexity*, *trust and false assurance*, *adoption barriers*, *missing features*, and tie them to the quantitative results.
9. **Report honestly:** convenience sample after a presentation (people may be polite); ceiling effects are likely; self-report only. A short threats-to-validity paragraph is expected.

A minimal Python starting point:

```python
import pandas as pd, numpy as np
df = pd.read_csv("ASTRA expert survey (Responses).csv")
lik = lambda s: pd.to_numeric(s.astype(str).str.extract(r"^(\d+)")[0])
pu = [c for c in df.columns if c.startswith("B1.")]            # grid columns are "B1. ... [PU1 ...]"
df["Usefulness"] = df[pu].apply(lik).mean(axis=1)
print(df.groupby("P1. Which sector best describes where you mainly work?")["Usefulness"].agg(["count", "median"]))
```

## 5. Distribution

1. Run the script, test the form yourself once on a phone and a laptop, export the test row to CSV, then delete the test response (Responses tab, delete).
2. Share the *published* link (the one the script prints first), not the edit link.
3. Send the link right after the presentation, with a reminder 3 to 4 days later and a close date. Typical expert-survey response rates are 30 to 50 per cent, so reaching 30 answers from about 30 invitees will take follow-up; consider inviting more.
4. Close the form (Responses tab > Accepting responses off) before analysis and freeze a CSV copy.

## 6. Limits of this instrument

- It evaluates the *concept and the platform as presented*, not a controlled experiment; claims about effectiveness need field evidence.
- The SUS is meaningful only for people who really used the studio; with few hands-on users, report it descriptively.
- Neither the instrument nor its scales have been validated; if you reuse it more widely, add a small pilot with 3 to 5 people first and fix any wording that confuses them.
