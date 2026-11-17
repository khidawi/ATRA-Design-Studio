# Checklist for the independent assessor

You have an **auditor** account: read-only, plus the audit log. You cannot sign, approve or change anything, and you should not be able to. If you can, tell the project team: that is a finding.

You will work from two places: the platform (read-only) and the export folder (`deploy/pilot_export.py` writes it; every file in it is listed in `MANIFEST.json` with its SHA-256).

## 1. Is the export the real thing?

- [ ] Recompute the SHA-256 of each file and compare with `MANIFEST.json`.
- [ ] `contract.json` verifies with the public key (`astra_signing.py verify` instructions in the export's `README.txt`): hash, signature, validity window. Try changing one character of `contract.json` and confirm that it then fails.
- [ ] The platform's own verify endpoint agrees (`GET /api/astra/contracts/{id}/verify`), and the pack verifies (`GET /api/packs/{key}/verify`: its hash chain and the contracts it cites).
- [ ] The audit log chain verifies (`GET /api/audit/verify`).

## 2. Does each claim stand on a record?

For each row of `OBLIGATION-MAPPING.md`:

- [ ] Open the record the dossier names. Does it say what the claim says?
- [ ] For a **constraint**: is it in the signed contract (`contract.json`, `constraints`)? Is the clause the contract maps it to the one that matters for the obligation, and is it the *right* clause?
- [ ] For a **Probe** result: open the run (`probe_run.json`). Which scenarios passed, which were not applicable and why? Does a pass for those scenarios mean something for this obligation?
- [ ] For **monitored**: does the number of events for the class in the last 30 days look like real traffic? Ask for the raw event list for a day and compare with the agent's own logs.
- [ ] For an **assessment**: who recorded it, who accepted the baseline, are they different people, and was the verdict APPROVED for the version that was signed?

## 3. What is the pack silent about?

- [ ] Read `gaps` and `unmapped_rows`. Is anything you know about the agent missing from them?
- [ ] Open every finding raised during the pilot (`findings.json`). Is each judged, and by whom? Is any finding hidden by being acknowledged without a reason?
- [ ] Look at the Security view and the regulation watch. Anything flagged there that the pack does not mention?
- [ ] Check the limits the pack states. Is there a limit you think it should state and does not?

## 4. Try to break one claim

Pick the claim you trust least.

- [ ] Ask the project team to cause the divergence the claim says is caught (a tool call outside the contract, for example) and watch the finding and the verdict appear. Or ask for the Probe scenario that stands for it and replay it.
- [ ] Ask what would make the claim false and whether the platform would notice.

## 5. Your conclusion

Write it yourself, in your own words, in `OBLIGATION-MAPPING.md`. The project team does not edit it. Record: which claims stood, which did not, what is missing, and whether you would accept this evidence for the named obligation.

If you reject the evidence, say why. That is as useful as accepting it.
