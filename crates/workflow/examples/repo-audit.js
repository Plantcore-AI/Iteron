// A complete, runnable Iteron workflow script.
//
//   iteron workflow run crates/workflow/examples/repo-audit.js --args '{"topic":"the rollout writer"}'
//
// `meta.phases` is declarative: the live tree lays every phase box out on the first frame, before
// execution reaches it. `phase()` binds back to a declared box by title.
export const meta = {
  name: 'repo-audit',
  description: 'Fan out read-only investigators over one topic, then reduce their evidence.',
  phases: ['explore', 'synthesize'],
};

const topic = (args && args.topic) || 'this repository';

phase('explore');
log('investigating ' + topic);

// parallel() declares the whole fan at once. Every call gets a row immediately; the permit pool
// decides how many of them run at a time, so the done/total denominator never moves.
const questions = [
  'Which module owns ' + topic + '? Answer with exact path:line references.',
  'What invariant does ' + topic + ' rely on? Name it and cite where it is enforced.',
  'Where is ' + topic + ' tested? List the test names.',
];

const evidence = (
  await parallel(
    questions.map((question) => () =>
      agent(question, { label: question.slice(0, 40), phase: 'explore' })
    )
  )
).filter(Boolean); // a degraded agent resolves to null; it never throws.

if (evidence.length === 0) {
  log('no evidence survived; nothing to reduce');
  return { topic, findings: null, investigators: questions.length, answered: 0 };
}

phase('synthesize');
log('reducing ' + evidence.length + ' report(s)');

// A schema turns the reduction into a validated object instead of prose the caller has to parse.
const findings = await agent(
  'Reduce these investigator reports about ' +
    topic +
    ' into one grounded summary. Do not invent references.\n\n' +
    evidence.join('\n\n---\n\n'),
  {
    label: 'reduce evidence',
    phase: 'synthesize',
    schema: {
      type: 'object',
      properties: {
        summary: { type: 'string' },
        references: { type: 'array', items: { type: 'string' } },
      },
      required: ['summary', 'references'],
      additionalProperties: false,
    },
  }
);

return { topic, findings, investigators: questions.length, answered: evidence.length };
