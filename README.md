# astblock

Switch off individual Python statements without editing or redeploying the code.

You write a small JSON blocklist naming statements by an AST fingerprint. When
the program starts with that blocklist, each blocked statement is rewritten at
import time so that it either **skips** (does nothing) or **raises**
`BlockedStatementError`. Everything not on the list is compiled exactly as normal.

The intended use is emergency mitigation: a third-party call that hangs, a
side effect that fires twice, a code path that corrupts data. It lets you turn
that one statement off with a config change and a restart, while the proper fix
goes through your normal release process.

## Workflow

```console
# 1. Find the statement's fingerprint
$ python -m astblock list shop.checkout --line 15
   15  ebfa39018db86a24  checkout   notify_partner_api(order)

# 2. Generate a rule (then add a reason)
$ python -m astblock list shop.checkout --line 15 --json --action skip > blocklist.json

# 3. Verify every rule matches the code you're about to run
$ python -m astblock check blocklist.json
OK       shop.checkout ebfa39018db86a24 [skip] line 15: notify_partner_api(order)

# 4. Run with it
$ python -m astblock run --blocklist blocklist.json -m shop.checkout
```

`examples/` contains this exact scenario.

## Activating it in an application

Pick one:

- **CLI wrapper:** `python -m astblock run --blocklist FILE -m yourapp` or
  `... run --blocklist FILE script.py`.
- **One line at the top of your entry point**, before your own modules are
  imported: `import astblock; astblock.install_from_env()`. It does nothing
  unless `ASTBLOCK_FILE` is set.
- **No code change:** a `.pth` file in site-packages containing the single line
  `import astblock; astblock.install_from_env()` runs at interpreter startup.
  This is powerful, so only do it in environments you control.

If `ASTBLOCK_FILE` is set but the file is missing or invalid, startup fails
rather than running unpatched.

## Fingerprints

A fingerprint is a hash of the module name, the enclosing function/class path,
the statement's AST (without positions), and an occurrence index for identical
statements in the same scope. So it:

- survives reformatting, comment changes and code added above it;
- changes if the statement itself changes or moves to another function, so an
  old rule stops matching instead of hitting the wrong code. Stale rules are
  logged at import time and reported by `astblock check`.

Generate fingerprints with the same Python minor version you run in
production: AST shapes occasionally change between versions.

## Blocklist format

```json
{
  "version": 1,
  "rules": [
    {
      "module": "shop.checkout",
      "fingerprint": "ebfa39018db86a24",
      "action": "skip",
      "reason": "Partner API outage, INC-2231"
    }
  ]
}
```

`action` is `"raise"` (the default) or `"skip"`. Scripts run directly use the
module name `__main__`; code run with `-m pkg.mod` uses `pkg.mod`.

## Semantics and limits: read before using in an incident

- **Skipping is not free.** A skipped assignment leaves the name undefined, a
  skipped `return` falls through to the following code, and a skipped `def` or
  `import` removes the name entirely. Block the narrowest statement that does
  the job, and prefer `raise` where the caller already handles errors.
- Blocking a compound statement (`if`, `for`, `with`, `def`) blocks all of it.
- If you block a function's only `yield`, it stays a generator (it just yields nothing).
- **Import time only.** Rules apply when a module is imported, so the process
  must restart. Modules imported before `install()` are not patched, and a
  warning names them.
- Only modules loaded from `.py` source are patchable, not extension modules or
  pyc-only distributions. Targeted modules are always compiled from source and
  never cached, so a stale `.pyc` can't bypass a rule.
- Hits are logged to the `astblock` logger (first hit at WARNING, later hits at
  DEBUG) and counted in `astblock.hits()`.
- **Security:** whoever can write the blocklist can disable any statement,
  including an authorization check. Treat the file and the `ASTBLOCK_FILE`
  variable with the same care as your deploy credentials.

## Python API

```python
import astblock

astblock.install("blocklist.json")        # or a Blocklist object
astblock.fingerprint_source(src, "mod")   # -> list[Statement]
astblock.hits()                           # {fingerprint: count}
astblock.uninstall()
```

## Development

```console
pip install -e ".[test]"
pytest
```
