# Empty staging scaffold maintenance

An approved core prepare can create `staging/<operation>/<manifest>/files` and
then lose its acknowledgement before publishing any file. The controller must
retain `FAILED / RUNTIME_COMPLETION_UNCERTAIN`. The existing recovery classifier
accepts an empty operation directory, not this nested scaffold.

`node tools/retain-empty-stage.mjs inspect <device>` creates an owner-only,
immutable observation for this one failed operation. Review it before running
`apply <device>`. Only core-only uncertain state and the exact three-directory
topology are admitted: no package, capsule, work, trust, journal, runtime generation
or other operation. Existing pinned SSH and administrator checks remain in use.
This narrow version also rejects a pre-existing `retained-runtime` namespace;
it does not merge with an earlier retention or recover a partially created destination.

Apply retains the transaction under `retained-runtime/<operation>/<manifest>`.
It checks native directory identities, volume, exact children, ACL hashes, the
unchanged controller state, target binding, executor bytes, boot time and a
15-minute observation expiry. Parent handles and the runtime mutation mutex are
held; the source is renamed by handle without replacing an existing destination.
Postcheck verifies retained identities/ACLs and an empty original operation.
No files are deleted and no local runtime state is transitioned.

The attempt is exclusively created and fsynced before dispatch. There is no
automatic replay. `reconcile <device>` is a separate read-only postcheck. This
maintenance tool deliberately allows only one observation and one apply per
failed operation; an expired proposal, partial destination or lost reconciliation
requires investigation, not deleting records or running another attempt.

After `RETAINED`, use the existing `runtime-recover --inspect`, its required
authorized guest reboot, post-boot inspect and exact-ticket apply. That protocol
alone clears the failed state. Only then capture a new baseline and review a new
core plan. Retained material is outside the runtime tree and remains available.

Standalone approved provisioning now records a finite staging failure phase in
the controller's private `provision-diagnostics/` directory: initialize, inspect,
upload, cleanup or finalize. It captures no exception text, commands, addresses,
identifiers or credentials. This adds evidence to future failures; it cannot
retroactively determine which stage caused the original trial's uncertainty.

Validation: the Windows fixture exercises empty retention/reconciliation and
rejection of files, extra children, changed identities and an existing destination.
Local tests cover proof bindings, stage attribution, redaction and private storage.
This is a maintenance entry point in the engineering checkout, not a deployed
public installer change or an automatic recovery policy.
