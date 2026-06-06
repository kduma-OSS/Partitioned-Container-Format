# Implementations

Production implementations of the Partitioned Container Format family, one
directory per language. Each language directory holds **one subfolder per
library**, so that profiles built *on top of* PCF (e.g. PFS) can live next to it:

```
implementations/
├── php/
│   └── pcf/                     # kduma/pcf            (Packagist split)
├── ts/
│   ├── package.json             # npm workspace root (private)
│   └── pcf/                     # @kduma-oss/pcf       (npm)
└── dotnet/
    ├── Directory.Build.props    # shared metadata + lockstep <Version>
    └── pcf/                     # KDuma.Pcf            (NuGet)
```

The Rust reference under [`../reference/`](../reference/) is the canonical model:
`PFS-MS-v1.0` depends on `PCF-v1.0` via a path dependency with a pinned version,
and every package is versioned **in lockstep** by
[`release-prepare.yml`](../../.github/workflows/release-prepare.yml).

## Adding a library that depends on PCF (e.g. PFS)

Drop a sibling folder (`…/pfs/`) next to `…/pcf/` and wire the dependency using
the per-ecosystem mechanism below. Local development resolves against the
on-disk PCF; published artifacts depend on the released PCF package.

| Language | Dependency declaration in the PFS manifest | Local dev | Published |
|----------|--------------------------------------------|-----------|-----------|
| Rust     | `pcf = { path = "../pcf", version = "X" }` | source on disk | crates.io |
| .NET     | `<ProjectReference Include="..\..\..\pcf\src\Pcf\Pcf.csproj" />` | project on disk | `dotnet pack` emits a NuGet dependency `KDuma.Pcf >= X` |
| TS / npm | `"@kduma-oss/pcf": "^X"` + add `pfs` to the root `workspaces` array | workspace symlink to `../pcf` | npm registry |
| PHP      | `repositories: [{ type: "path", url: "../pcf" }]` + `require: { "kduma/pcf": "^X" }` | path-repo symlink to `../pcf` | Packagist (path repo ignored downstream) |

What each ecosystem already provides for "readiness":

- **TypeScript** — `implementations/ts/package.json` is a private **npm
  workspaces** root with a single hoisted `package-lock.json`. Add `"pfs"` to
  `workspaces`; CI runs package scripts with `-w @kduma-oss/<pkg>`.
- **.NET** — `implementations/dotnet/Directory.Build.props` holds the shared
  package metadata and the single lockstep `<Version>`, auto-imported by every
  project beneath it. A new library only declares its own `PackageId` /
  `Description` and a `ProjectReference` to PCF.
- **PHP** — each library is a self-contained Composer package that is mirrored to
  its own Packagist repo by a split workflow. A new library gets its own
  `composer.json` (with the path repo above) and a sibling split workflow.
