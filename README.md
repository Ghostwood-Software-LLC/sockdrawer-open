# sockdrawer-open

Get your photos and videos out of a Sock Drawer archive (`.mjarchive`) on a Mac, Windows
or Linux computer, without the app.

You need the archive (the file **Transfer → Save a Copy** made) and the passphrase you
set when you saved it. Without the passphrase, nobody can open it, including this
script and us.

## Use it

1. Install Python 3.9 or newer from [python.org](https://www.python.org/downloads/).
   Macs and most Linux systems already have it.
2. Download `sockdrawer_open.py` from this repository.
3. In a terminal, in the folder you downloaded it to:

   ```sh
   python3 -m venv sockdrawer-env
   sockdrawer-env/bin/pip install cryptography
   sockdrawer-env/bin/python sockdrawer_open.py "vault-2026-11-17.mjarchive" "My Photos"
   ```

   On Windows, use `py` for `python3` and `sockdrawer-env\Scripts\` for `sockdrawer-env/bin/`.

4. Type the passphrase when it asks. It doesn't show as you type.

To see what's inside without writing anything:

```sh
sockdrawer-env/bin/python sockdrawer_open.py --list "vault-2026-11-17.mjarchive"
```

## What you get

- Every photo and video as its **original file**, named by when it was taken, in UTC:
  `2026-07-04_183012_79996237.heic`.
- Anything that was in Recently Deleted goes in a `Recently Deleted` folder.
- `manifest.csv` lists every item: its file, when it was taken, added and deleted,
  which albums it was in, and whether it was a favourite. Albums aren't made into
  folders, so a video in three albums doesn't take three times the space.

If a run is interrupted, run it again into the same folder. Finished files are skipped,
and a half-written file is only ever left as `name.part`, never under its real name.

When it finishes, it exits with one of these codes:

| exit | meaning |
|------|---------|
| 0 | everything was written |
| 1 | nothing was written: wrong passphrase, or the archive is incomplete, damaged or from a newer app |
| 2 | written, except for the items it names (their `file` cell in `manifest.csv` is empty) |

## Before you run it

- **The output isn't encrypted.** Write it somewhere you trust, and delete it when
  you're done if it was only for checking.
- The script reads the archive and writes the output folder. It makes no network
  connections. It's one file of plain Python, so you can read it before you run it.
- If it says the archive is from a newer version of the app, get the latest copy of
  this script. It refuses formats it doesn't know rather than guessing and quietly
  leaving files out.

## How it works

[FORMAT.md](FORMAT.md) describes the archive byte by byte. `test_open.py` checks the
script against `fixtures/`, a real archive written by the app's own export code:

```sh
sockdrawer-env/bin/python test_open.py
```

This repository is published from the app's source, where the app's tests run this
script against a freshly written archive on every build. Please report problems as
issues here. Changes are made at the source and published back.
