# Two bundles for the timestamp-binding cases (issue 23)

Both files are copies, byte for byte, of files that have been public since 14 November 2026 in
`reticuli-labs/panel-artifacts`, directory `arcaeon-exchange/touchstone-side-2026-11-14/variants/`. The manifest of that exchange
was revealed on 15 November (`reveal/manifest.json` there) and says what each file is.

| file here | file there | SHA-256 | what it is |
|---|---|---|---|
| `B10_as_served.json` | `B10.json` | `7de556fd5511bd1fdc0ad89454805c42aa0e8a19a851dc5ca1027156470a6dcc` | control C1: the full disclosure of the exchange's recorder exactly as the server served it |
| `B01_planted_response_of_another_head.json` | `B01.json` | `4e417ce6570e41a12aab5d961e9ea8fc8bf56c0832891f10894bbae93e3e970b` | **PLANTED**, defect D7: the whole bundle minted again under two other keys, with the genuine RFC 3161 response left in place |

`B01` is not a record of anything. It states a head (`640c22c9…44f8`) that the server never produced, and it carries the
timestamp response of the genuine head (`fad2143c…7af9`). Before issue 23 all three verifiers said `ok: true` for it when given
no expected server key. Nora (Arcaeon) found that in the exchange.

Nothing was built or signed for this change. No key is in this repository, and the script that made the exchange's planted files
is not published. The vectors in `../tsa_binding_cases.json` are made by each test harness from the timestamp anchor of
`B10_as_served.json` by the small edits that file names: another head string, a cut response, one byte written over another at
a stated position, a token that is not JSON. They are inputs to one function and are not bundles. The wiring cases edit the bundle
as served in memory so that it must be REJECTED or must lose a claim (a response cut or removed, anchors taken away); none of them
makes a bundle that claims more than the served one did. The two cases about a head that is not its last entry's hash use
`../conformance/plain_valid.json`, a fixture made with test keys.

If either file here ever differs from its SHA-256 above, the harnesses stop: they check the digest before using the file.
