# skein-1sat

The 1Sat Ordinals parsers an ordinal overlay for a
[skein](https://github.com/shruggr/skein) is built on, as one Zig module,
`onesat`, over bsvz. Used by shruggr/skein-collection and later ordinal
overlays (shruggr/skein#151). Version **0.1.0**, Zig 0.16.0.

## What it is

| module | file | what |
|---|---|---|
| `inscription` | `src/inscription.zig` | the `ord` envelope: content type, content, parent, named fields, the script before and after it, the P2PKH owner (1SAT_P2PKH) |
| `bitcom` | `src/bitcom.zig` | the tape after the first `OP_RETURN`, split into protocols on `\|`; each protocol's name, data and the offset of its separator |
| `map` | `src/map.zig` | MAP: the command and its `SET` key/value pairs |
| `sigma` | `src/sigma.zig` | SIGMA: algorithm, address, signature, `vin`; the signed message and BSM verification (bsvz `compat/bsm`); the first valid SIGMA of an output |
| `ordlock` | `src/ordlock.zig` | OrdLock v2 listings: the template, seller, price, payout; a spend classified purchase or cancel |
| `ordinal` | `src/ordinal.zig` | the ordinal position rule: the output an input's satoshi lands in, the input an output's satoshi came from |
| `script` | `src/script.zig` | the op reader the others use, the P2PKH template |

Each file's header states its rules. They follow 1sat-stack
(`pkg/template/{inscription,bitcom,ordlock}`, `pkg/types/ordinal.go`,
`pkg/parse`), except SIGMA verification, which follows 1sat-sdk
(`packages/templates/src/bitcom/sigma.ts`):

    sha256(sha256(txid in display order || vin index LE) || sha256(script before the tape))

1sat-stack hashes the txid in internal order and uses sha256d outside;
on-chain signatures (testdata `34adf92c…`) verify only the 1sat-sdk way.
`vin` is read as a decimal (`-1` and multi-digit), not Go's single digit.
The `BRC77` algorithm is not verified.

## Depend on it

`build.zig.zon`:

```zig
.dependencies = .{
    .skein_1sat = .{
        .url = "https://github.com/shruggr/skein-1sat/archive/refs/tags/v0.1.0.tar.gz",
        .hash = "<zig fetch --save prints it>",
    },
},
```

or `zig fetch --save=skein_1sat https://github.com/shruggr/skein-1sat/archive/refs/tags/v0.1.0.tar.gz`.

`build.zig`:

```zig
const onesat = b.dependency("skein_1sat", .{ .target = wasi, .optimize = .ReleaseSafe });
// … .imports = &.{.{ .name = "onesat", .module = onesat.module("onesat") }}
```

bsvz is pinned at the commit skein-sdk pins (`shruggr/bsvz` 309085f, the same
hash), so an app that also depends on skein-sdk or skein-overlay gets one
bsvz module and the `Transaction` types agree.

```zig
const onesat = @import("onesat");
const lock = tx.outputs[vout].locking_script.bytes;

const insc = onesat.inscription.decode(lock) orelse return; // content_type, content, owner, …
const tape = onesat.bitcom.decode(lock) orelse return;
const m = (try onesat.map.find(a, tape)) orelse return;      // m.get("subType")
const signer = try onesat.sigma.firstValid(a, &tx, vout);    // ?Sigma: address, …
const listing = onesat.ordlock.decode(lock);                 // ?Listing: seller, price, pay_script
const spend = onesat.ordlock.classify(unlocking_script);     // ?{purchase, cancel}

// `sources`: anything with sourceOutput(i) ?Output, e.g. a skein-overlay topic.Call,
// or onesat.ordinal.Hydrated{ .tx = &tx } for inputs that carry their source outputs.
const landed = try onesat.ordinal.output(&tx, vin, call);    // ?u32, or error.MissingSourceOutput
```

## Build and test

Zig 0.16.0 (`mise.toml`).

```
zig build test     # the modules against 1sat-stack's vectors, natively
```

`test.zig` ports the cases of 1sat-stack's `_test.go` files for these
templates and uses its testdata transactions (`testdata/`), plus SIGMA
sign/verify round trips and the ordinal rule's cases.

## Versions

| | |
|---|---|
| this package | 0.1.0 (tag `v0.1.0`) |
| bsvz | `git+https://github.com/shruggr/bsvz#309085f` by URL and hash in `build.zig.zon` (modules used: `transaction`, `crypto`, `compat`) |
| references | 1sat-stack 0699242, 1sat-sdk `packages/templates` 3ad99610 |

## Contributing

Work is tracked in shruggr/skein; this repo's issue is
[#151](https://github.com/shruggr/skein/issues/151). MIT, as skein.
