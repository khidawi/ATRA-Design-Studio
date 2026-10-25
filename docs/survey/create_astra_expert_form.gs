/**
 * Builds the ASTRA expert-evaluation questionnaire as a Google Form, and a Google Sheet that collects the answers.
 *
 * How to run (about 2 minutes):
 *   1. Go to https://script.google.com and choose New project.
 *   2. Delete the sample code, paste this whole file, save.
 *   3. Choose the function createAstraForm and press Run. Accept the permission prompt (it needs Forms and Sheets).
 *   4. Open View > Logs (or Execution log): it prints the link to SHARE, the link to EDIT, and the link to the response sheet.
 *
 * Before you share it: open the edit link and (a) put your ethics approval reference and contact details into the consent text,
 * (b) check the settings below, (c) send yourself a test response and export it to CSV once to see the column names.
 *
 * Every question title begins with a short code (P1, PU1, SUS3 ...). Google puts that title in the CSV column header, so the data can be
 * matched to the codebook in ASTRA-Expert-Survey-Design.md without renaming anything.
 */

var LIKERT = ['1 Strongly disagree', '2 Disagree', '3 Neutral', '4 Agree', '5 Strongly agree'];

function createAstraForm() {
  var form = FormApp.create('ASTRA: expert evaluation of an assurance framework for AI agents and AI models');
  form.setDescription(
    'Thank you for taking part. This survey collects expert feedback on ASTRA, a framework and platform for assuring AI agents and AI models ' +
    'from design to production. It takes about 15 minutes (about 20 if you also complete the optional usability section). ' +
    'There are no right or wrong answers: critical feedback is the most useful.');
  form.setCollectEmail(false);            // anonymous by default; no Google account is needed to answer
  form.setLimitOneResponsePerUser(false); // true would force a Google sign-in
  form.setAllowResponseEdits(false);
  form.setProgressBar(true);
  form.setShowLinkToRespondAgain(false);
  form.setConfirmationMessage('Thank you. Your response has been recorded.');

  // ───────────────────────── Consent ─────────────────────────
  form.addSectionHeaderItem().setTitle('Participant information and consent').setHelpText(
    'Purpose: to evaluate the ASTRA framework for academic research (including a conference paper) and for industry validation.\n\n' +
    'What we ask: your professional background and your views on the framework. We do not ask your name. Unless you choose to give an email address ' +
    'at the end, your answers are anonymous.\n\n' +
    'Voluntary: taking part is voluntary. You can stop at any time before submitting. Because answers are anonymous, a submitted response cannot be ' +
    'withdrawn later unless you gave an email address.\n\n' +
    'Use of data: responses are stored securely, analysed in aggregate, and reported without identifying individuals or organisations. ' +
    'Anonymised data may be shared with the published paper.\n\n' +
    'Ethics and contact: [ETHICS APPROVAL REFERENCE]. Researcher: [NAME, EMAIL]. Data controller: [INSTITUTION]. ' +
    'Please do not include confidential information about your employer or clients in free-text answers.');
  form.addCheckboxItem().setTitle('C1. Consent')
    .setChoiceValues([
      'I have read the information above, I am 18 or over, and I agree to take part.',
      'I agree that my anonymised answers may be used in research publications and shared as an anonymised data set.'])
    .setRequired(true);

  // ───────────────────────── Section A: profile ─────────────────────────
  form.addPageBreakItem().setTitle('Section A. About you').setHelpText('These questions let us describe the group of experts and compare views across sectors.');

  form.addMultipleChoiceItem().setTitle('P1. Which sector best describes where you mainly work?')
    .setChoiceValues(['Academia or research institute', 'Industry (technology or software)', 'Industry (finance, insurance)', 'Industry (health, life sciences)',
      'Industry (other sector)', 'Government, public sector or regulator', 'Standards body, non-profit or think tank', 'Consultancy, audit or assurance firm'])
    .showOtherOption(true).setRequired(true);

  form.addMultipleChoiceItem().setTitle('P2. Which best describes your current role?')
    .setChoiceValues(['Researcher or academic', 'PhD or postdoctoral researcher', 'AI/ML engineer or data scientist', 'Software or platform engineer',
      'Security professional', 'Risk, compliance or audit professional', 'Legal, policy or ethics professional',
      'Product, programme or engineering manager', 'Executive or senior leader'])
    .showOtherOption(true).setRequired(true);

  form.addMultipleChoiceItem().setTitle('P3. Total years of professional or research experience')
    .setChoiceValues(['Less than 2', '2 to 5', '6 to 10', '11 to 20', 'More than 20']).setRequired(true);

  form.addMultipleChoiceItem().setTitle('P4. Years of experience specifically with AI, machine learning or data science')
    .setChoiceValues(['None', 'Less than 2', '2 to 5', '6 to 10', 'More than 10']).setRequired(true);

  form.addCheckboxItem().setTitle('P5. Your areas of expertise (select all that apply)')
    .setChoiceValues(['AI/ML engineering', 'AI safety or security', 'AI governance, ethics or responsible AI', 'Risk management or internal control',
      'Audit or assurance', 'Regulation, law or policy', 'Software engineering or DevOps', 'Data engineering or data protection',
      'Requirements or systems engineering', 'Human factors or human oversight'])
    .showOtherOption(true).setRequired(true);

  form.addGridItem().setTitle('P6. How familiar are you with each of the following?')
    .setRows(['EU AI Act', 'NIST AI Risk Management Framework', 'ISO/IEC 42001 (AI management systems)', 'OWASP Top 10 for agentic applications or LLM applications'])
    .setColumns(['1 Not familiar', '2 Slightly', '3 Moderately', '4 Very', '5 Expert']).setRequired(true);

  form.addMultipleChoiceItem().setTitle('P7. Your hands-on experience with AI agents (systems that call tools and act with some autonomy)')
    .setChoiceValues(['None', 'I have read or studied about them', 'I have built or tested prototypes', 'I have deployed or governed them in production'])
    .setRequired(true);

  form.addMultipleChoiceItem().setTitle('P8. Size of your organisation')
    .setChoiceValues(['Self-employed or fewer than 10 people', '10 to 49', '50 to 249', '250 to 999', '1,000 or more', 'Not applicable']).setRequired(true);

  form.addMultipleChoiceItem().setTitle('P9. Region where you mainly work (optional)')
    .setChoiceValues(['United Kingdom', 'Europe (outside the UK)', 'North America', 'Asia', 'Middle East and Africa', 'Latin America', 'Oceania', 'Prefer not to say'])
    .setRequired(false);

  // ───────────────────────── Section B: evaluation ─────────────────────────
  form.addPageBreakItem().setTitle('Section B. Your evaluation of the ASTRA framework')
    .setHelpText('Please answer based on the presentation and any material you have seen. For each statement choose the option that best matches your view.');

  form.addGridItem().setTitle('B1. Perceived usefulness').setRows([
    'PU1 ASTRA would help organisations understand the risks of their AI agents and AI models.',
    'PU2 ASTRA would improve the quality of evidence available to auditors and regulators.',
    'PU3 Comparing an agent\'s live behaviour with an approved contract is a useful way to detect unsafe behaviour.',
    'PU4 Monitoring models in production (drift, unsafe outputs, how people use outputs) adds value beyond what organisations typically do today.'])
    .setColumns(LIKERT).setRequired(true);

  form.addGridItem().setTitle('B2. Relevance and coverage').setRows([
    'RL1 The framework addresses problems that matter in real organisations.',
    'RL2 The framework covers the main risks of AI agents (for example tool misuse, excessive autonomy, data leakage).',
    'RL3 The framework covers the main risks of AI models (for example drift, bias, unsafe outputs).',
    'RL4 The mapping to standards and regulation (EU AI Act, NIST AI RMF, ISO/IEC 42001, OWASP) is credible.'])
    .setColumns(LIKERT).setRequired(true);

  form.addGridItem().setTitle('B3. Understandability').setRows([
    'EU1 The main concepts (contract, finding, drift, assurance gap, attestation) are easy to understand.',
    'EU2 I could explain the framework to a colleague.',
    'EU3 The outputs (scores, findings, charts) are easy to interpret.',
    'EU4 The framework seems too complex for a typical organisation to apply. [reverse-scored]'])
    .setColumns(LIKERT).setRequired(true);

  form.addGridItem().setTitle('B4. Credibility and rigour').setRows([
    'CR1 The scoring and checks are transparent enough to be trusted.',
    'CR2 The approach is methodologically sound.',
    'CR3 The evidence it produces would be accepted by an auditor in my field.',
    'CR4 I am concerned that it could give organisations a false sense of assurance. [reverse-scored]'])
    .setColumns(LIKERT).setRequired(true);

  form.addGridItem().setTitle('B5. Intention to use').setRows([
    'IN1 I would recommend ASTRA to my organisation or to a client.',
    'IN2 I would be willing to take part in a pilot of ASTRA.',
    'IN3 My organisation could use ASTRA alongside the tools it already has.'])
    .setColumns(LIKERT).setRequired(true);

  form.addGridItem().setTitle('B6. How useful is each part of ASTRA for your field?').setRows([
    'M1 Design-time checks of agents and models (threat rules, requirements, scoring)',
    'M2 Agent contracts and drift review (approve what an agent may do)',
    'M3 Live agent monitoring (events compared with the contract, findings)',
    'M4 Model production monitoring (drift, safety flags, canaries, versions)',
    'M5 Human-use analytics (rubber-stamping, wrong outputs accepted)',
    'M6 Assurance gap, evidence packs and expiring attestations',
    'M7 Charts and trends for non-technical readers'])
    .setColumns(['1 Not useful', '2', '3', '4', '5 Very useful', 'Cannot judge']).setRequired(true);

  form.addScaleItem().setTitle('B7. Overall, how likely are you to recommend ASTRA to a colleague?').setBounds(0, 10)
    .setLabels('0 Not at all likely', '10 Extremely likely').setRequired(true);

  // ───────────────────────── Section C: hands-on usability (optional, branching) ─────────────────────────
  var pageC = form.addPageBreakItem().setTitle('Section C. Your experience using the ASTRA studio')
    .setHelpText('If you tried the ASTRA studio yourself (for example in a demo session), please rate it here. If not, you will skip the usability questions.');
  var handsOn = form.addMultipleChoiceItem().setTitle('U0. Did you use the ASTRA studio hands-on?').setRequired(true);

  var susPage = form.addPageBreakItem().setTitle('Usability of the ASTRA studio')
    .setHelpText('Ten statements from the System Usability Scale (Brooke, 1996). Answer on your first impression; "the system" means the ASTRA studio.');
  var sus = [
    'SUS1 I think that I would like to use this system frequently.',
    'SUS2 I found the system unnecessarily complex.',
    'SUS3 I thought the system was easy to use.',
    'SUS4 I think that I would need the support of a technical person to be able to use this system.',
    'SUS5 I found the various functions in this system were well integrated.',
    'SUS6 I thought there was too much inconsistency in this system.',
    'SUS7 I would imagine that most people would learn to use this system very quickly.',
    'SUS8 I found the system very cumbersome to use.',
    'SUS9 I felt very confident using the system.',
    'SUS10 I needed to learn a lot of things before I could get going with this system.'];
  form.addGridItem().setTitle('U1. System Usability Scale').setRows(sus).setColumns(LIKERT).setRequired(true);
  form.addGridItem().setTitle('U2. Experience of the studio').setRows([
    'UX1 I could find what I was looking for without help.',
    'UX2 The charts and summaries helped me understand what an agent or model was doing.',
    'UX3 The wording on screen was clear to someone who is not a specialist.',
    'UX4 The suggestions and fix buttons in the designers were helpful.'])
    .setColumns(LIKERT).setRequired(true);

  // ───────────────────────── Section D: priorities and adoption ─────────────────────────
  var pageD = form.addPageBreakItem().setTitle('Section D. Priorities and adoption');
  handsOn.setChoices([handsOn.createChoice('Yes', susPage), handsOn.createChoice('No', pageD)]);

  var limit3 = FormApp.createCheckboxValidation().setHelpText('Please choose up to 3.').requireSelectAtMost(3).build();
  form.addCheckboxItem().setTitle('D1. Which THREE capabilities matter most in your field? (choose up to 3)')
    .setChoiceValues(['Design-time risk checks', 'Approved behaviour contracts for agents', 'Live detection of agents acting outside their contract',
      'Model drift and performance monitoring', 'Monitoring how people use AI outputs', 'Evidence packs for auditors and regulators',
      'Mapping to regulation and standards', 'Real-time blocking of unsafe actions', 'Adversarial or red-team testing', 'Integration with identity and cloud tools'])
    .showOtherOption(true).setValidation(limit3).setRequired(true);

  form.addCheckboxItem().setTitle('D2. What would be the biggest barriers to adopting a framework like ASTRA? (choose up to 3)')
    .setChoiceValues(['Cost', 'Lack of skills or time', 'Fit with existing tools and processes', 'Concerns about data privacy or security of the platform',
      'Lack of independent validation', 'Resistance from teams or staff (monitoring concerns)', 'Unclear regulatory requirements', 'Preference to buy from a large vendor'])
    .showOtherOption(true).setValidation(limit3).setRequired(true);

  form.addMultipleChoiceItem().setTitle('D3. How would your organisation prefer to run a tool like this?')
    .setChoiceValues(['On our own servers or cloud account (self-hosted)', 'Hosted for us by the provider', 'Inside an existing platform we already use', 'No preference', 'Not applicable'])
    .setRequired(true);

  form.addMultipleChoiceItem().setTitle('D4. Would you consider a pilot of ASTRA?')
    .setChoiceValues(['Yes, within 6 months', 'Maybe, later', 'No', 'Not applicable to my role']).setRequired(true);

  // ───────────────────────── Section E: open feedback ─────────────────────────
  form.addPageBreakItem().setTitle('Section E. Your comments')
    .setHelpText('Your own words are very valuable. Short, specific answers are fine. Please avoid confidential details.');
  form.addParagraphTextItem().setTitle('Q1. What are the main strengths of ASTRA?').setRequired(true);
  form.addParagraphTextItem().setTitle('Q2. What are its main limitations or weaknesses?').setRequired(true);
  form.addParagraphTextItem().setTitle('Q3. What is missing that you would expect from a framework like this?').setRequired(false);
  form.addParagraphTextItem().setTitle('Q4. Could it be misused, or have unintended effects? (for example over-reliance, monitoring of staff)').setRequired(false);
  form.addParagraphTextItem().setTitle('Q5. If you could change one thing first, what would it be?').setRequired(true);
  form.addParagraphTextItem().setTitle('Q6. Any other comments or recommendations?').setRequired(false);

  form.addMultipleChoiceItem().setTitle('F1. May we contact you for a short follow-up conversation?')
    .setChoiceValues(['Yes', 'No']).setRequired(true);
  form.addTextItem().setTitle('F2. Email address (only if you answered Yes above; it will be stored with your answers)').setRequired(false);

  // ───────────────────────── Collect answers in a Google Sheet ─────────────────────────
  var ss = SpreadsheetApp.create('ASTRA expert survey: responses');
  form.setDestination(FormApp.DestinationType.SPREADSHEET, ss.getId());

  Logger.log('SHARE THIS LINK with the experts:  ' + form.getPublishedUrl());
  Logger.log('Edit the form (add ethics details):  ' + form.getEditUrl());
  Logger.log('Responses sheet (File > Download > CSV):  ' + ss.getUrl());
}
