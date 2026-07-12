# Manual slate exchange

Phase 1B-A uses explicit copy-and-paste exchange for an experimental DOM slate
request and response. It is not Slatepack and does not claim compatibility
with any external transport.

## Transport

The transport text is deterministic:

```text
dom-slate-v1:<request|response>:<slate UUID>:<lowercase hex canonical DOM slate bytes>
```

The authoritative DOM slate bytes are canonical `dom_tx::slate::Slate`
serialization. Import bounds text size, ASCII encoding, prefix, role, UUID,
lowercase hexadecimal, trailing fields, canonical decode/re-encode equality,
supported protocol version, chain ID, participant response shape, and replay
binding. A same request imported by the recipient returns its durable record;
conflicting reuse of a slate identifier fails closed.

## Flow

1. Wallet A estimates the protocol fee and creates a send transaction. This
   reserves inputs and encrypts the sender context before any export.
2. Wallet A explicitly exports the request text.
3. Wallet B imports the request, reviews redacted details, and explicitly
   creates then exports a response. Its receive descriptor and non-reuse floor
   are durable before response export.
4. Wallet A imports the response, finalizes the canonical DOM transaction,
   then explicitly submits it through the configured node.

The frontend clears imported or exported pasted slate text after processing;
it does not persist slate text, passwords, credentials, or private material in
browser storage. Public slate identifiers, amounts, fee, lifecycle, kernel
identifier, and submission result may be displayed. Private contexts,
blindings, nonces, offsets, root material, passwords, and credentials are never
returned by the Tauri DTOs.

## Tauri commands

The native command boundary registers `transaction_fee_estimate`,
`transaction_send_create`, `slate_request_export`, `slate_request_import`,
`slate_response_create`, `slate_response_export`, `slate_response_import`,
`slate_summary_redacted`, `transaction_finalize`, `transaction_submit`,
`transaction_retry_submission`, `transaction_cancel`, `transaction_list`, and
`transaction_detail_redacted`. They require an unlocked wallet where state is
protected, have strict bounded inputs, and expose redacted serializable results
only. No generic filesystem, shell, process, or HTTP bridge is introduced.
