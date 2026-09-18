# Nova/Cinder attachment ID audit

`cinder_nova_attachment_audit.py` is a read-only diagnostic for an OpenStack
project or all projects. It lists the project’s servers and their current Nova volume
attachments, then checks the corresponding database rows:

- Nova `block_device_mapping.attachment_id`
- Cinder `volume_attachment.id`
- instance UUID and volume UUID on both sides
- Nova `bdm_uuid` and Cinder attachment IDs returned by Compute microversion
  2.89 or newer
- soft-deleted/stale rows, duplicate active rows, and database-only records
- non-Cinder Nova block-device rows without `volume_id` are excluded from the
  database-only comparison and counted separately

Nova cells v2 use separate cell databases. By default, the script reads the
Nova cell database connection from `/etc/nova/nova.conf`; use repeated
`--nova-conf` options when additional cell configuration files are needed.
Cinder normally stores its connection in `/etc/cinder/cinder.conf`, which is
read automatically when present. If Cinder-specific database settings are kept
in `nova.conf`, use `--cinder-conf /etc/nova/nova.conf`. Use a read-only
database account. The script does not issue INSERT, UPDATE, DELETE, or
schema-changing statements.

## Install

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

Install the database driver appropriate for the deployment if it is not
already present. `PyMySQL` is included for MySQL/MariaDB URLs; uncomment the
PostgreSQL driver in `requirements.txt` when needed.

## Run

```bash
python3 cinder_nova_attachment_audit.py \
  --os-cloud admin \
  --project-id 11111111-1111-1111-1111-111111111111
```

For all projects:

```bash
python3 cinder_nova_attachment_audit.py --os-cloud admin --all-projects
```

The script reads `[database] connection` from `/etc/nova/nova.conf` and
`/etc/cinder/cinder.conf` automatically. Explicit `--nova-db-url` and
`--cinder-db-url` options, followed by `NOVA_DB_URL` and `CINDER_DB_URL`, take
precedence over configuration-file discovery. Database URLs are never printed.

If both database settings are held in one file, use:

```bash
python3 cinder_nova_attachment_audit.py \
  --nova-conf /etc/nova/nova.conf \
  --cinder-conf /etc/nova/nova.conf
```

When parsing a Nova file as the Cinder source, use an explicitly Cinder-named
section such as `[cinder_database]` with `connection`; the Nova
`[database] connection` is not reused as a Cinder URL.

The default output is a terminal-friendly table. Use `--format json` for
automation or to save the complete report as a JSON document. `--format text`
restores the original block-style human-readable output. The default Compute
microversion is `2.89`, which exposes Nova’s `attachment_id` and `bdm_uuid`
fields. For an older cloud, pass the supported version explicitly; the database
comparison still runs, but the API-side attachment ID fields may be unavailable.

Examples:

```bash
python3 cinder_nova_attachment_audit.py --all-projects --format table
python3 cinder_nova_attachment_audit.py --all-projects --format json > attachment-audit.json
python3 cinder_nova_attachment_audit.py --all-projects --width 100
```

Table output automatically fits the detected terminal width. Use `--width` to
override it when output is redirected or displayed in a fixed-width terminal.
The findings table emits one row per project/instance/volume and combines
multiple findings for that resource; per-finding severity is retained in the
details cell.

If the credential is already scoped to the target project and cannot use an
all-projects server listing, add `--no-all-projects`.

## Placement allocation audit (Zed)

`placement_allocation_audit.py` is a read-only Nova/Placement consistency
check. It maps Nova hypervisors to Placement compute resource providers, reads
provider allocations, detects live servers allocated to the wrong or multiple
compute-provider trees, reports live servers missing their expected compute
allocation, and reports allocation consumers absent from the visible Nova
server list as orphan candidates. Nested providers and shared providers are
kept separate from the compute-root comparison.

Use an administrative or system-scoped cloud credential so the server listing
is complete and Nova host attributes are visible:

```bash
python3 placement_allocation_audit.py --os-cloud admin
python3 placement_allocation_audit.py --os-cloud admin --format json > placement-audit.json
```

The defaults are Compute API microversion `2.53` and Placement microversion
`1.28`, both appropriate starting points for Zed. Override them if the cloud
advertises different supported versions. The script performs one Placement
allocation read per resource provider and does not repair or delete anything.
Table output wraps long findings instead of clipping them; use `--width 160`
to choose a wider fixed width. With `--project-id`, the Nova server result is
project-filtered and allocation consumers outside that project are excluded.
Placement allocation records do not contain a project ID, so orphan candidates
are suppressed in project-scoped mode; use an all-projects run for orphan
candidate discovery.

Nova already provides the authoritative, Nova-aware orphan check through
[`nova-manage placement audit`](https://docs.openstack.org/nova/zed/cli/nova-manage.html#placement-audit),
which understands instance and migration consumers and can optionally delete
confirmed orphan allocations. [`nova-manage placement heal_allocations`](https://docs.openstack.org/nova/zed/cli/nova-manage.html#placement-heal-allocations)
repairs missing allocations but is not a general mismatch/orphan detector.
See Nova's [Zed orphaned-allocation troubleshooting guide](https://docs.openstack.org/nova/zed/admin/troubleshooting/orphaned-allocations.html)
before taking corrective action.
