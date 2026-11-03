------------------------------ MODULE AstraV25 ------------------------------
(* Finite-abstraction encoding of the transition system of ASTRA research specification v2.5, section 3.5.2.
   Two candidate versions, two hard-control evidence records, one effectiveness evidence record, one incident,
   one data-retention record. MUT selects a planted defect; MUT = "none" is the specification as written. *)
EXTENDS Naturals

CONSTANTS CM,        \* last clock value
          VE, VE2,   \* validity end of the hard-control evidence and of the effectiveness evidence
          AP_LEN,    \* validity length of an approval
          DR, DC,    \* response bound for an incident and for a continuing-compliance obligation
          AUTH,      \* TRUE if an authorised responder exists
          NV, NE,    \* number of candidate versions and of hard-control evidence records in the finite abstraction
          POLCH,     \* TRUE to include the action ChangePolicy
          RET, INCI, \* TRUE to include the retirement actions, respectively the incident actions
          MUT

VARIABLES clock, st, prod, apPol, apUntil, pol, pend, rvw, rvwPol, rvwFp, rvwB, rv, evs, ee, cred,
          oblOpen, oblT, oblBreach, inc, t0, art, hold, basis, del, lock

vars == <<clock, st, prod, apPol, apUntil, pol, pend, rvw, rvwPol, rvwFp, rvwB, rv, evs, ee, cred,
          oblOpen, oblT, oblBreach, inc, t0, art, hold, basis, del, lock>>

V  == 1..NV
EV == 1..NE
RI == {<<0,0,0>>, <<0,1,0>>, <<0,1,1>>, <<1,1,1>>}     \* (lower bound above tolerance, upper bound above tolerance, evidenced value)
M(x) == MUT = x

(* ---------- derived predicates ---------- *)
\* Satisfies(e,c,q): current, not expired by the clock, not revoked (section 3.3)
SatI(i) == evs[i] = "CUR" /\ (M("oldSatisfies") \/ clock < VE)
HardPass == \E i \in EV : SatI(i)
Evid == ee = "CUR" /\ (M("oldSatisfies") \/ clock < VE2)
RiskL == IF Evid THEN rv[3] ELSE rv[1]
RiskU == IF Evid THEN rv[3] ELSE rv[2]
RiskSt == IF RiskL = 1 THEN "BLOCK" ELSE IF RiskU = 0 THEN "PASS" ELSE "REVIEW"
Gate == IF lock \/ ~HardPass \/ RiskSt = "BLOCK" THEN "BLOCKED" ELSE IF RiskSt = "REVIEW" THEN "REVIEW" ELSE "APPROVED"
Rank(g) == IF g = "APPROVED" THEN 0 ELSE IF g = "REVIEW" THEN 1 ELSE 2
Fp == <<rv, Evid>>
\* a review is valid only with its basis recorded: rationale, decision authority, evidence considered, expiry or review trigger
ValidReview(v) == rvw[v] /\ rvwPol[v] = pol /\ rvwFp[v] = Fp /\ (rvwB[v] \/ M("reviewNoBasis"))
Releasable(v) == Gate = "APPROVED" \/ ((Gate = "REVIEW" \/ M("reviewOverrides")) /\ ValidReview(v))
ValidApproval(v) == apPol[v] # 0 /\ apPol[v] = pol /\ clock <= apUntil[v]
ContinuingPass(v) == ValidApproval(v) /\ Releasable(v)
Fail == prod # 0 /\ ~ContinuingPass(prod)

(* urgent actions: time may not pass while one of them is enabled *)
ExpireEn(i) == evs[i] = "CUR" /\ clock >= VE
ExpireEEn == ee = "CUR" /\ clock >= VE2
FlagEn == ~M("noObligation") /\ Fail /\ ~oblOpen
CloseEn == oblOpen /\ ~Fail
ObBreachEn == oblOpen /\ ~oblBreach /\ clock > oblT + DC /\ ~AUTH
TimeoutEn == inc = "OPEN" /\ clock > t0 + DR
Urgent == (\E i \in EV : ExpireEn(i)) \/ ExpireEEn \/ FlagEn \/ CloseEn \/ ObBreachEn \/ TimeoutEn

Init == /\ clock = 0 /\ st = [v \in V |-> "NONE"] /\ prod = 0
        /\ apPol = [v \in V |-> 0] /\ apUntil = [v \in V |-> 0] /\ pol = 1 /\ pend = [v \in V |-> FALSE]
        /\ rvw = [v \in V |-> FALSE] /\ rvwPol = [v \in V |-> 0] /\ rvwFp = [v \in V |-> <<<<0,0,0>>, FALSE>>] /\ rvwB = [v \in V |-> FALSE]
        /\ rv = <<0,0,0>> /\ evs = [i \in EV |-> "NONE"] /\ ee = "NONE" /\ cred = [v \in V |-> FALSE]
        /\ oblOpen = FALSE /\ oblT = 0 /\ oblBreach = FALSE /\ inc = "NONE" /\ t0 = 0
        /\ art = FALSE /\ hold = FALSE /\ basis = FALSE /\ del = FALSE /\ lock = FALSE

Other(x) == UNCHANGED x

Submit(v) == /\ st[v] = "NONE" /\ st' = [st EXCEPT ![v] = "SUBM"]
             /\ UNCHANGED <<clock, prod, apPol, apUntil, pol, pend, rvw, rvwPol, rvwFp, rvwB, rv, evs, ee, cred, oblOpen, oblT, oblBreach, inc, t0, art, hold, basis, del, lock>>

Upload(i) == /\ evs[i] = "NONE" /\ evs' = [evs EXCEPT ![i] = "UPL"]
             /\ UNCHANGED <<clock, st, prod, apPol, apUntil, pol, pend, rvw, rvwPol, rvwFp, rvwB, rv, ee, cred, oblOpen, oblT, oblBreach, inc, t0, art, hold, basis, del, lock>>

Attest(i) == /\ evs[i] = "UPL" /\ clock < VE /\ evs' = [evs EXCEPT ![i] = "CUR"]
             /\ UNCHANGED <<clock, st, prod, apPol, apUntil, pol, pend, rvw, rvwPol, rvwFp, rvwB, rv, ee, cred, oblOpen, oblT, oblBreach, inc, t0, art, hold, basis, del, lock>>

AttestEff == /\ ee = "NONE" /\ clock < VE2 /\ ee' = "CUR"
             /\ UNCHANGED <<clock, st, prod, apPol, apUntil, pol, pend, rvw, rvwPol, rvwFp, rvwB, rv, evs, cred, oblOpen, oblT, oblBreach, inc, t0, art, hold, basis, del, lock>>

Expire(i) == /\ ExpireEn(i) /\ evs' = [evs EXCEPT ![i] = "EXP"]
             /\ UNCHANGED <<clock, st, prod, apPol, apUntil, pol, pend, rvw, rvwPol, rvwFp, rvwB, rv, ee, cred, oblOpen, oblT, oblBreach, inc, t0, art, hold, basis, del, lock>>

ExpireEff == /\ ExpireEEn /\ ee' = "EXP" /\ lock' = (lock \/ (RiskSt = "BLOCK" /\ ~M("noRatchet")))
             /\ UNCHANGED <<clock, st, prod, apPol, apUntil, pol, pend, rvw, rvwPol, rvwFp, rvwB, rv, evs, cred, oblOpen, oblT, oblBreach, inc, t0, art, hold, basis, del>>

\* RevokeEvidence(e): an authorised revoker; the status is final; dependent statuses are recomputed because they are derived
RevokeEv(i) == /\ evs[i] \in {"UPL", "CUR", "EXP"} /\ evs' = [evs EXCEPT ![i] = "REV"]
               /\ UNCHANGED <<clock, st, prod, apPol, apUntil, pol, pend, rvw, rvwPol, rvwFp, rvwB, rv, ee, cred, oblOpen, oblT, oblBreach, inc, t0, art, hold, basis, del, lock>>

RevokeEff == /\ ee \in {"CUR", "EXP"} /\ ee' = "REV" /\ lock' = (lock \/ (RiskSt = "BLOCK" /\ ~M("noRatchet")))
             /\ UNCHANGED <<clock, st, prod, apPol, apUntil, pol, pend, rvw, rvwPol, rvwFp, rvwB, rv, evs, cred, oblOpen, oblT, oblBreach, inc, t0, art, hold, basis, del>>

\* the mutation "reinstate" lets a revoked record become current again
Reinstate(i) == /\ M("reinstate") /\ evs[i] = "REV" /\ evs' = [evs EXCEPT ![i] = "CUR"]
                /\ UNCHANGED <<clock, st, prod, apPol, apUntil, pol, pend, rvw, rvwPol, rvwFp, rvwB, rv, ee, cred, oblOpen, oblT, oblBreach, inc, t0, art, hold, basis, del, lock>>

Review(v, b) == /\ st[v] \in {"SUBM", "APPR", "DEPL", "SUSP", "SUPR"}
             /\ (Gate = "REVIEW" \/ (M("reviewOverrides") /\ Gate = "BLOCKED"))
             /\ rvw' = [rvw EXCEPT ![v] = TRUE] /\ rvwPol' = [rvwPol EXCEPT ![v] = pol] /\ rvwFp' = [rvwFp EXCEPT ![v] = Fp] /\ rvwB' = [rvwB EXCEPT ![v] = b]
             /\ UNCHANGED <<clock, st, prod, apPol, apUntil, pol, pend, rv, evs, ee, cred, oblOpen, oblT, oblBreach, inc, t0, art, hold, basis, del, lock>>

Approve(v) == /\ st[v] = "SUBM" /\ (Releasable(v) \/ M("noRelApprove"))
              /\ apPol' = [apPol EXCEPT ![v] = pol] /\ apUntil' = [apUntil EXCEPT ![v] = clock + AP_LEN]
              /\ st' = [st EXCEPT ![v] = "APPR"] /\ pend' = [pend EXCEPT ![v] = FALSE]
              /\ UNCHANGED <<clock, prod, pol, rvw, rvwPol, rvwFp, rvwB, rv, evs, ee, cred, oblOpen, oblT, oblBreach, inc, t0, art, hold, basis, del, lock>>

\* Deploy, Rollback and Resume share one effect: the previous production version becomes SUPERSEDED
Enter(v) == /\ prod' = v
            /\ st' = [w \in V |-> IF w = v THEN "DEPL" ELSE IF w = prod /\ ~M("noSupersede") THEN "SUPR" ELSE st[w]]
            /\ cred' = [w \in V |-> IF w = v THEN TRUE ELSE IF w = prod THEN FALSE ELSE cred[w]]

Deploy(v) == /\ st[v] = "APPR" /\ ValidApproval(v) /\ (Releasable(v) \/ M("noRelDeploy")) /\ Enter(v)
             /\ UNCHANGED <<clock, apPol, apUntil, pol, pend, rvw, rvwPol, rvwFp, rvwB, rv, evs, ee, oblOpen, oblT, oblBreach, inc, t0, art, hold, basis, del, lock>>

Rollback(v) == /\ st[v] = "SUPR" /\ ValidApproval(v) /\ Releasable(v) /\ Enter(v)
               /\ UNCHANGED <<clock, apPol, apUntil, pol, pend, rvw, rvwPol, rvwFp, rvwB, rv, evs, ee, oblOpen, oblT, oblBreach, inc, t0, art, hold, basis, del, lock>>

Resume(v) == /\ AUTH /\ st[v] = "SUSP" /\ ValidApproval(v) /\ Releasable(v) /\ Enter(v)
             /\ UNCHANGED <<clock, apPol, apUntil, pol, pend, rvw, rvwPol, rvwFp, rvwB, rv, evs, ee, oblOpen, oblT, oblBreach, inc, t0, art, hold, basis, del, lock>>

Suspend(v) == /\ AUTH /\ st[v] = "DEPL" /\ prod = v
              /\ st' = [st EXCEPT ![v] = "SUSP"] /\ prod' = 0 /\ cred' = [cred EXCEPT ![v] = FALSE] /\ oblOpen' = FALSE /\ oblBreach' = FALSE
              /\ UNCHANGED <<clock, apPol, apUntil, pol, pend, rvw, rvwPol, rvwFp, rvwB, rv, evs, ee, oblT, inc, t0, art, hold, basis, del, lock>>

Update(v) == /\ prod # v /\ st[v] \in {"SUBM", "APPR", "SUPR", "SUSP"}
             /\ pend' = [pend EXCEPT ![v] = TRUE]
             /\ st' = [st EXCEPT ![v] = IF M("updateKeepsStatus") THEN st[v] ELSE "SUBM"]
             /\ apPol' = [apPol EXCEPT ![v] = IF M("updateKeepsStatus") THEN apPol[v] ELSE 0]
             /\ rvw' = [rvw EXCEPT ![v] = FALSE]
             /\ UNCHANGED <<clock, prod, apUntil, pol, rvwPol, rvwFp, rvwB, rv, evs, ee, cred, oblOpen, oblT, oblBreach, inc, t0, art, hold, basis, del, lock>>

Decommission(v) == /\ st[v] \in {"SUBM", "APPR", "DEPL", "SUPR", "SUSP"}
                   /\ st' = [st EXCEPT ![v] = "DECOM"] /\ prod' = (IF prod = v THEN 0 ELSE prod)
                   /\ cred' = [cred EXCEPT ![v] = IF M("keepCredentials") THEN cred[v] ELSE FALSE]
                   /\ UNCHANGED <<clock, apPol, apUntil, pol, pend, rvw, rvwPol, rvwFp, rvwB, rv, evs, ee, oblOpen, oblT, oblBreach, inc, t0, art, hold, basis, del, lock>>

RetireVerify(v) == /\ st[v] = "DECOM" /\ art /\ (del \/ (hold /\ (basis \/ M("retireNoBasis"))))
                   /\ st' = [st EXCEPT ![v] = "RETIRED"]
                   /\ UNCHANGED <<clock, prod, apPol, apUntil, pol, pend, rvw, rvwPol, rvwFp, rvwB, rv, evs, ee, cred, oblOpen, oblT, oblBreach, inc, t0, art, hold, basis, del, lock>>

DisposeArtefacts == /\ RET /\ ~art /\ art' = TRUE
                    /\ UNCHANGED <<clock, st, prod, apPol, apUntil, pol, pend, rvw, rvwPol, rvwFp, rvwB, rv, evs, ee, cred, oblOpen, oblT, oblBreach, inc, t0, hold, basis, del, lock>>
PlaceHold == /\ RET /\ ~hold /\ ~del /\ hold' = TRUE
             /\ UNCHANGED <<clock, st, prod, apPol, apUntil, pol, pend, rvw, rvwPol, rvwFp, rvwB, rv, evs, ee, cred, oblOpen, oblT, oblBreach, inc, t0, art, basis, del, lock>>
RecordBasis == /\ RET /\ hold /\ ~basis /\ basis' = TRUE
               /\ UNCHANGED <<clock, st, prod, apPol, apUntil, pol, pend, rvw, rvwPol, rvwFp, rvwB, rv, evs, ee, cred, oblOpen, oblT, oblBreach, inc, t0, art, hold, del, lock>>
\* releasing a hold withdraws the retention basis and the retirement claim that rested on it
ReleaseHold == /\ RET /\ hold /\ hold' = FALSE /\ basis' = FALSE
               /\ st' = [w \in V |-> IF st[w] = "RETIRED" /\ ~del /\ ~M("keepRetired") THEN "DECOM" ELSE st[w]]
               /\ UNCHANGED <<clock, prod, apPol, apUntil, pol, pend, rvw, rvwPol, rvwFp, rvwB, rv, evs, ee, cred, oblOpen, oblT, oblBreach, inc, t0, art, del, lock>>
Delete == /\ RET /\ ~hold /\ ~del /\ del' = TRUE
          /\ UNCHANGED <<clock, st, prod, apPol, apUntil, pol, pend, rvw, rvwPol, rvwFp, rvwB, rv, evs, ee, cred, oblOpen, oblT, oblBreach, inc, t0, art, hold, basis, lock>>

\* Reestimate: a new estimate version recorded by an independent reviewer; releases the ratchet set by loss of effectiveness evidence
Reestimate == /\ AUTH /\ lock /\ lock' = FALSE
              /\ UNCHANGED <<clock, st, prod, apPol, apUntil, pol, pend, rvw, rvwPol, rvwFp, rvwB, rv, evs, ee, cred, oblOpen, oblT, oblBreach, inc, t0, art, hold, basis, del>>

ChangePolicy == /\ POLCH /\ pol = 1 /\ pol' = 2
                /\ UNCHANGED <<clock, st, prod, apPol, apUntil, pend, rvw, rvwPol, rvwFp, rvwB, rv, evs, ee, cred, oblOpen, oblT, oblBreach, inc, t0, art, hold, basis, del, lock>>

Observe(r) == /\ r \in RI /\ r # rv /\ rv' = r
              /\ UNCHANGED <<clock, st, prod, apPol, apUntil, pol, pend, rvw, rvwPol, rvwFp, rvwB, evs, ee, cred, oblOpen, oblT, oblBreach, inc, t0, art, hold, basis, del, lock>>

Flag == /\ FlagEn /\ oblOpen' = TRUE /\ oblT' = clock
        /\ UNCHANGED <<clock, st, prod, apPol, apUntil, pol, pend, rvw, rvwPol, rvwFp, rvwB, rv, evs, ee, cred, oblBreach, inc, t0, art, hold, basis, del, lock>>
CloseObl == /\ CloseEn /\ oblOpen' = FALSE /\ oblBreach' = FALSE
            /\ UNCHANGED <<clock, st, prod, apPol, apUntil, pol, pend, rvw, rvwPol, rvwFp, rvwB, rv, evs, ee, cred, oblT, inc, t0, art, hold, basis, del, lock>>
ObBreach == /\ ObBreachEn /\ oblBreach' = TRUE
            /\ UNCHANGED <<clock, st, prod, apPol, apUntil, pol, pend, rvw, rvwPol, rvwFp, rvwB, rv, evs, ee, cred, oblOpen, oblT, inc, t0, art, hold, basis, del, lock>>

Alert == /\ INCI /\ inc = "NONE" /\ inc' = "OPEN" /\ t0' = clock
         /\ UNCHANGED <<clock, st, prod, apPol, apUntil, pol, pend, rvw, rvwPol, rvwFp, rvwB, rv, evs, ee, cred, oblOpen, oblT, oblBreach, art, hold, basis, del, lock>>
Respond == /\ AUTH /\ inc = "OPEN" /\ inc' = "CLOSED"
           /\ UNCHANGED <<clock, st, prod, apPol, apUntil, pol, pend, rvw, rvwPol, rvwFp, rvwB, rv, evs, ee, cred, oblOpen, oblT, oblBreach, t0, art, hold, basis, del, lock>>
Timeout == /\ TimeoutEn /\ inc' = "BREACH"
           /\ UNCHANGED <<clock, st, prod, apPol, apUntil, pol, pend, rvw, rvwPol, rvwFp, rvwB, rv, evs, ee, cred, oblOpen, oblT, oblBreach, t0, art, hold, basis, del, lock>>

Tick == /\ clock < CM /\ ~(Urgent \/ (M("strictTick") /\ \E i \in EV : evs[i] = "CUR" /\ clock + 1 >= VE)
                          \/ (inc = "OPEN" /\ clock + 1 > t0 + DR /\ (AUTH \/ M("deadlineTick")))
                          \/ (oblOpen /\ clock + 1 > oblT + DC /\ AUTH))
        /\ clock' = clock + 1
        /\ UNCHANGED <<st, prod, apPol, apUntil, pol, pend, rvw, rvwPol, rvwFp, rvwB, rv, evs, ee, cred, oblOpen, oblT, oblBreach, inc, t0, art, hold, basis, del, lock>>

Done == clock = CM /\ UNCHANGED vars

Next == \/ \E v \in V : Submit(v) \/ (\E b \in BOOLEAN : Review(v, b)) \/ Approve(v) \/ Deploy(v) \/ Rollback(v) \/ Resume(v) \/ Suspend(v)
                         \/ Update(v) \/ Decommission(v) \/ RetireVerify(v)
        \/ \E i \in EV : Upload(i) \/ Attest(i) \/ Expire(i) \/ RevokeEv(i) \/ Reinstate(i)
        \/ AttestEff \/ ExpireEff \/ RevokeEff \/ DisposeArtefacts \/ PlaceHold \/ RecordBasis \/ ReleaseHold \/ Delete
        \/ Reestimate \/ ChangePolicy \/ (\E r \in RI : Observe(r)) \/ Flag \/ CloseObl \/ ObBreach \/ Alert \/ Respond \/ Timeout \/ Tick \/ Done

Spec == Init /\ [][Next]_vars /\ SF_vars(Tick) /\ WF_vars(\E i \in EV : Expire(i)) /\ WF_vars(ExpireEff) /\ WF_vars(Flag) /\ WF_vars(CloseObl)
        /\ WF_vars(ObBreach) /\ WF_vars(Respond) /\ WF_vars(Timeout) /\ WF_vars(\E v \in V : Suspend(v))

SpecWF == Init /\ [][Next]_vars /\ WF_vars(Tick) /\ WF_vars(\E i \in EV : Expire(i)) /\ WF_vars(ExpireEff) /\ WF_vars(Flag) /\ WF_vars(CloseObl)
        /\ WF_vars(ObBreach) /\ WF_vars(Respond) /\ WF_vars(Timeout) /\ WF_vars(\E v \in V : Suspend(v))


(* ---------- properties, stated at guard strength ---------- *)
\* Release safety: a version enters production only with a valid approval bound to the current policy, and releasable
ReleaseSafety == [][\A v \in V : (st'[v] = "DEPL" /\ st[v] # "DEPL") => (ValidApproval(v) /\ Releasable(v))]_vars
\* Update safety: a version enters production only if no update since its last approval is pending
ApproveSafety == [][\A v \in V : (st'[v] = "APPR" /\ st[v] # "APPR") => Releasable(v)]_vars
UpdateSafety == [][\A v \in V : (st'[v] = "DEPL" /\ st[v] # "DEPL") => ~pend[v]]_vars
\* Revocation persistence for evidence records
RevokePersist == [][(\A i \in EV : evs[i] = "REV" => evs'[i] = "REV") /\ (ee = "REV" => ee' = "REV")]_vars
\* Expiry or revocation of evidence never improves the gate
NoImprove == [][((\E i \in EV : evs'[i] \in {"EXP", "REV"} /\ evs[i] # evs'[i]) \/ (ee' \in {"EXP", "REV"} /\ ee # ee')) => Rank(Gate') >= Rank(Gate)]_vars

InvProdStatus == (prod # 0 => st[prod] = "DEPL") /\ (\A v \in V : st[v] = "DEPL" => prod = v)
InvExpiry == \A i \in EV : clock >= VE => ~SatI(i)
InvReleasable == \A v \in V : Releasable(v) => HardPass /\ RiskSt # "BLOCK"
InvRetire == \A v \in V : st[v] = "RETIRED" => art /\ (del \/ (hold /\ basis))
InvDecom == \A v \in V : st[v] \in {"DECOM", "RETIRED"} => ~cred[v] /\ prod # v
InvReviewBasis == \A v \in V : (Gate = "REVIEW" /\ Releasable(v)) => rvwB[v]
InvHold == ~(hold /\ del)
InvObligation == (Fail => oblOpen \/ FlagEn) /\ (oblOpen /\ clock > oblT + DC => ~AUTH)
InvIncident == inc = "OPEN" /\ clock > t0 + DR => ~AUTH
Inv == InvProdStatus /\ InvExpiry /\ InvReleasable /\ InvRetire /\ InvDecom /\ InvReviewBasis /\ InvHold /\ InvObligation /\ InvIncident

NoTimelock == <>(clock = CM)
IncidentResolved == (inc = "OPEN" /\ t0 + DR < CM) ~> (inc \in {"CLOSED", "BREACH"})
ObligationResolved == (Fail /\ clock + DC < CM) ~> (~Fail \/ oblBreach)
=============================================================================
