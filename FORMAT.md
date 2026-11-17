# The Sock Drawer archive format

This is how a `.mjarchive` file is laid out: the file the app writes when you use
**Transfer → Save a Copy**. It's written down so a copy of your photos never depends on
the app still existing. `sockdrawer_open.py` implements exactly this and nothing more.

Everything uses standard primitives: PBKDF2-HMAC-SHA256, AES-256-GCM and JSON. All
integers are big-endian.

## 1. The archive

```
magic      4 bytes   "MJA1"
version    4 bytes   UInt32, currently 1
wrapLen    4 bytes   UInt32
wrap       wrapLen bytes of JSON: the key wrap (section 2)
tableLen   4 bytes   UInt32
table      tableLen bytes of JSON: [{"name": String, "length": Int}, ...]
payload    each table entry's bytes, concatenated in table order
```

`wrapLen` and `tableLen` are each between 1 byte and 64 MiB. The archive is complete only
if its size is at least the offset of `payload` plus the sum of every `length`.

The table is the only metadata in the clear. Its names are:

| name             | what it is                                                   |
|------------------|--------------------------------------------------------------|
| `index.mji`      | the index: every item, album and extra key (section 4)       |
| `<UUID>.mjv`     | one item's original file, sealed (section 3)                 |
| `<UUID>.mjt`     | that item's thumbnail JPEG, sealed the same way              |

`<UUID>` is the item's id as the app writes it: uppercase, with hyphens. Compare names
as strings; don't round-trip them through a UUID type that lowercases them.

The media files are copied into the archive **byte for byte** from the vault. The
archive re-wraps the vault's key and re-encrypts nothing.

## 2. The key wrap

```json
{"salt": "<base64>", "iterations": 600000, "ciphertext": "<base64>", "slot": "archive"}
```

1. Normalise the passphrase to Unicode **NFC**, then encode it as UTF-8. Without the
   normalisation, "café" typed with a combining accent would derive a different key.
2. `derived = PBKDF2-HMAC-SHA256(passphrase, salt, iterations, 32 bytes)`.
   `iterations` is not authenticated, so a reader refuses anything outside 1…10,000,000.
3. `ciphertext` is an AES-GCM combined box: `nonce(12) ‖ ciphertext(32) ‖ tag(16)`.
   Open it with `derived` as the key and the UTF-8 bytes of `slot` as associated data.
   The result is the 32-byte **vault key**. If it fails to authenticate, the passphrase
   is wrong. GCM can't tell a wrong passphrase from a damaged wrap.

## 3. A sealed file (`MJV1`)

```
header   32 bytes:  magic "MJV1" (4) ‖ chunkSize UInt32 (4) ‖ plaintextLength UInt64 (8) ‖ fileID (16, random)
frame*   each:      sealedLength UInt32 (4) ‖ AES-GCM combined box (sealedLength bytes)
```

- `chunkSize` is at most 64 MiB (the app uses 1 MiB). Each frame's plaintext is at most
  `chunkSize` bytes, so `sealedLength` is at most `chunkSize + 28`.
- Frame *i* (counting from 0) is authenticated with associated data
  `header (all 32 bytes) ‖ UInt64(i)`. That stops a frame from being moved to another
  position, or into another file.
- There is always at least one frame, even for an empty file.
- **There is no end marker.** A file cut off exactly at a frame boundary still
  authenticates frame by frame. Only checking that the frames add up to
  `plaintextLength` catches it, so a reader must not treat the output as finished
  until that check passes.

The key is the vault key, unless the item's `keyID` says otherwise (section 4).

## 4. The index (`index.mji`)

A sealed file as in section 3, under the vault key, whose plaintext is JSON written by
Swift's default `JSONEncoder`. Two consequences:

- **Dates are seconds since 2001-01-01 00:00:00 UTC**, not 1970. Add 978,307,200 to
  get a Unix time.
- **`keys` is a flat array**, `["<UUID>", "<base64>", "<UUID>", "<base64>", ...]`,
  because Swift writes a dictionary with non-string keys that way.

Optional fields are left out entirely when they have no value.

```
{
  "schemaVersion": 2,
  "items":  [Item],
  "albums": [{"id": UUID, "name": String, "createdAt": Date}],
  "keys":   [UUID, base64, ...],
  "didBackfillCaptureDates": Bool,
  "lastArchivedAt": Date?,               // app bookkeeping
  "backupReminderSnoozedUntil": Date?    // app bookkeeping
}
```

Older versions:

- **Schema 0:** the whole index is a bare `[Item]` array.
- **Schema 1:** no `schemaVersion` field and no `keys`.

Item:

| field           | type       | meaning                                                         |
|-----------------|------------|-----------------------------------------------------------------|
| `id`            | UUID       | names its `.mjv` and `.mjt`                                     |
| `kind`          | String     | `"photo"` or `"video"`                                          |
| `addedAt`       | Date       | when it entered the vault                                       |
| `capturedAt`    | Date?      | when it was taken, if the file said; else use `addedAt`         |
| `byteCount`     | Int        | original size in bytes                                          |
| `pixelWidth`, `pixelHeight` | Int | dimensions                                              |
| `duration`      | Double?    | seconds, videos only                                            |
| `fileExtension` | String     | the original's extension, e.g. `heic`, `jpg`, `mov`             |
| `albumIDs`      | [UUID]     | albums it is in                                                 |
| `isFavorite`    | Bool       |                                                                 |
| `deletedAt`     | Date?      | set while it is in Recently Deleted                             |
| `contentHash`   | String?    | SHA-256 of the original, hex                                    |
| `keyID`         | UUID?      | if set, the file is sealed with `keys[keyID]`, not the vault key|

An item can be listed whose `.mjv` isn't in the archive: the vault lost that file
before the copy was made. A reader should report it and carry on.

A copy of one album or a selection carries an index of just those items, with the
albums they're in and the keys they need. A copy of the whole vault includes items in
Recently Deleted.

## Compatibility

A change to anything above means a new archive `version`, a new index `schemaVersion`
or a new field. A reader that meets a version, schema, field, item kind or table entry
it doesn't know must **stop rather than guess**. A field it doesn't know might name a
second file that it would otherwise silently leave behind.

The app's tests write a fresh archive on every build and run `test_open.py` against it,
so the app can't change this format without the tool changing with it.
