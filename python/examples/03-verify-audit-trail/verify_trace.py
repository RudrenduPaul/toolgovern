"""Example 3: write a signed audit trail and verify it, in both signing modes.

Demonstrates the default unkeyed sha256: signing (proves an entry hasn't changed since it was
written, but is forgeable by anyone with write access to the file), the optional HMAC-keyed
signing (closes that gap for anyone who doesn't hold the key), and tamper detection via
verify_chain().

Run: python3 examples/03-verify-audit-trail/verify_trace.py
"""

import dataclasses
import tempfile
from pathlib import Path

from toolgovern import (
    ScopeDeclaration,
    TraceEntryInput,
    TraceWriter,
    TraceWriterOptions,
    VerifyChainOptions,
    read_trace,
    verify_chain,
)
from toolgovern.trace.trace_writer import compute_entry_signature


def main():
    with tempfile.TemporaryDirectory() as tmp:
        # -- Part 1: default unkeyed signing --
        unkeyed_path = str(Path(tmp) / "unkeyed-trace.jsonl")
        writer = TraceWriter(unkeyed_path)
        writer.append(
            TraceEntryInput(
                session_id="demo-session",
                agent_id="demo-agent",
                tool="shell",
                args={"command": "ls"},
                decision="allow",
                rule_fired=[],
                declared_scope=ScopeDeclaration(),
            )
        )
        writer.append(
            TraceEntryInput(
                session_id="demo-session",
                agent_id="demo-agent",
                tool="shell",
                args={"command": "rm -rf /"},
                decision="deny",
                rule_fired=["TG01-rm-rf"],
                declared_scope=ScopeDeclaration(),
            )
        )
        entries = read_trace(unkeyed_path)
        print(f"Wrote {len(entries)} entries, signature scheme: {entries[0].signature.split(':')[0]}")
        result = verify_chain(entries)
        print(f"verify_chain (no key): valid={result.valid}\n")

        # -- Part 2: the disclosed residual limitation of unkeyed signing --
        # An attacker with write access to the trace file can edit an entry AND recompute a
        # valid signature -- no secret is required for the unkeyed scheme.
        tampered = dataclasses.replace(entries[0], tool="ATTACKER-CONTROLLED", signature="")
        forged_signature = compute_entry_signature(tampered)
        forged = dataclasses.replace(tampered, signature=forged_signature)
        forged_result = verify_chain([forged])
        print(
            "Forged entry (edited + resigned with the unkeyed scheme) still verifies: "
            f"{forged_result.valid} -- this is the documented v0.1 limitation, not a bug.\n"
        )

        # -- Part 3: HMAC-keyed signing closes that gap --
        keyed_path = str(Path(tmp) / "keyed-trace.jsonl")
        secret_key = b"a-real-deployment-would-load-this-from-a-secret-manager"
        keyed_writer = TraceWriter(keyed_path, TraceWriterOptions(secret_key=secret_key))
        keyed_writer.append(
            TraceEntryInput(
                session_id="demo-session",
                agent_id="demo-agent",
                tool="shell",
                args={"command": "ls"},
                decision="allow",
                rule_fired=[],
                declared_scope=ScopeDeclaration(),
            )
        )
        keyed_entries = read_trace(keyed_path)
        print(f"HMAC-keyed entry signature scheme: {keyed_entries[0].signature.split(':')[0]}")

        ok_with_key = verify_chain(keyed_entries, VerifyChainOptions(secret_key=secret_key))
        print(f"verify_chain (correct key): valid={ok_with_key.valid}")

        no_key = verify_chain(keyed_entries)
        print(f"verify_chain (no key supplied): valid={no_key.valid}, issues={[i.reason for i in no_key.issues]}")

        wrong_key = verify_chain(keyed_entries, VerifyChainOptions(secret_key=b"wrong-key"))
        print(f"verify_chain (wrong key): valid={wrong_key.valid}")


if __name__ == "__main__":
    main()
