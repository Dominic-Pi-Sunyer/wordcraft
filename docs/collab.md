# Share Mode (live co-editing)

> **Status:** first version · **Crate:** `crates/collab` (L5) · **UI:** `crates/ui-egui/src/share.rs` (Co-edit button, title bar)

Peer to peer over [simple-sync](https://github.com/Dominic-Pi-Sunyer/simple-sync): no server, links
carry the keys, traffic is end-to-end encrypted. Native builds only; the web build compiles a stub.

## What is sent
Every command that edits the document is sent as `{command id, params, the author's selection, a
version vector}`. Receivers shift the author's positions past the text any concurrent edit inserted
or removed in the same paragraph, run the command, and move their own caret past it. Two people
typing in one paragraph converge (`crates/collab/tests/multiplayer_wordcraft_test.rs`).

## What is not
| Command | Why |
|---|---|
| `edit.undo`, `edit.redo`, `edit.undoTo`, `edit.repeat` | refused while sharing: undo restores the whole document and would erase other people's edits |
| `edit.paste` without `text`, `edit.pasteSpecial` | read your own clipboard; applied locally, with a status-line notice |
| `tools.*`, `mailings.*`, `font.*`, `zotero.*`, anything with `path`/`password`/`file`/`url` params | depend on this machine or carry secrets; applied locally with a notice. Incoming edits of these kinds are ignored |
| `file.new/open/close/recover` | refused while sharing (they would swap the shared document away) |
| `edit.cut` | sent as the deletion it amounts to |
| carets and selections of others | not shown (simple-sync has no ephemeral presence channel yet) |

## Known limits
- Merging is a two-writer transform. With three or more people editing the same spot in the same
  instant, peers can end up different.
- Only edits inside one paragraph are transformed. Splitting, merging or deleting paragraphs is
  applied as sent and does not renumber concurrent edits aimed at later paragraphs.
- Formatting is not merged per character: concurrent formatting of overlapping text applies in arrival order.
- Anyone with a link can read the whole document and keep a copy. The host's address is in the link.
- `simple-sync` is vendored under `vendor/simple-sync` (`crates/collab/Cargo.toml`).
