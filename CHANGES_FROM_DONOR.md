# Owned changes from the retained GeoServer baseline

## Importer queue shutdown — PLT-01, 2026-10-04

Predecessor: `fd2fe1dfcc78fa974bdb81673872879336312077`
(tree `c12018e88493a351c60c370f2a43894701acf995`). Existing source history,
copyright and license notices remain unchanged.

`Importer` constructs asynchronous and synchronous job queues. Each queue starts
a scheduled cleaner, but the inherited `destroy()` closed only the asynchronous
queue. The owned change adds `synchronousJobs.shutdown()` immediately afterward,
before the existing store destruction. Cleanup order and exception propagation
otherwise remain unchanged; no thread sweep, forced JVM exit or timeout change.

`ImporterShutdownTest` and its test-only `JobQueueShutdownProbe` exercise actual
queue executors for idle shutdown, active worker interruption and repeated
shutdown with a repeat-safe memory store. All test-owned queues are stopped in
`finally`, including the failing predecessor baseline. Class-origin checks bind
focused test execution to the selected retained libraries and compiled variant.

The omitted synchronous cleanup is established from retained source and selected
WAR bytes. The observed post-stop scheduled worker has not been directly bound
to that queue; this change does not assert historical timeout causality. Native
focused tests, the complete owned-source rebuild and ordinary initializer
verification remain pending until their separate recorded executions.

## Per-module source identity — PLT-01, 2026-10-04

Predecessor: 190baba1d8074306629e7764e114ca3bb9581101.
The owned aggregate builds several source repositories in one Maven reactor.
Its parent POM now disables reactor-wide Git-property injection and defaults
to resolving Git metadata for each module. The retained plugin caches shared
properties when injection is enabled, so a single-repository default can
misidentify another owned root.

The build producer must supply genuine metadata for each selected owned Git
revision and verify embedded revisions after building. These POM settings alone
do not prevent discovery of an unrelated ancestor repository in a plain source
export. They change build provenance behavior, not GIS algorithms. The earlier
successful importer tests do not establish provenance or installation acceptance
for this successor.
