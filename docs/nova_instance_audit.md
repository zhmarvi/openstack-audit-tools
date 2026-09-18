# Nova instance directory audit

This directory contains a report-only audit for `/var/lib/nova/instances`.
It is designed for a large compute fleet:

1. Ansible collects directory, mount, and libvirt evidence from each compute.
2. The OpenStack client exports active and deleted server records.
3. Python correlates the data and reports duplicate UUIDs and stale-directory
   candidates.

The audit never deletes, renames, or changes a remote directory.

## Collect from computes

Put the compute hosts in an Ansible group named `nova_compute`, or override the
group name with `-e nova_compute_group=...`.

Run from this directory:

```bash
ansible-playbook -i /path/to/inventory audit_instances.yml
```

The playbook writes one JSON file per compute below `audit-data/`. Override the
path when needed:

```bash
ansible-playbook -i /path/to/inventory audit_instances.yml \
  -e instances_path=/var/lib/nova/instances \
  -e output_dir="$PWD/audit-data" \
  -e collect_directory_sizes=true
```

Directory sizes are disabled by default because `du` can be expensive when
local instance disks are large. Enable them after the initial scan if useful.

## Export Nova state

Use an administrative or system-scoped OpenStack credential so host attributes
and all projects are visible:

```bash
openstack server list --all-projects --long --limit -1 -f json \
  > control-servers.json
openstack server list --all-projects --deleted --long --limit -1 -f json \
  > control-deleted-servers.json
openstack compute service list -f json > compute-services.json
openstack hypervisor list --long -f json > hypervisors.json
```

If the cloud limits the result size, paginate the server listing and pass
multiple `--servers` or `--deleted` arguments to the analyzer.

## Analyze

```bash
python3 nova_instance_audit.py \
  --compute-dir audit-data \
  --servers control-servers.json \
  --deleted control-deleted-servers.json \
  --format table
```

For automation:

```bash
python3 nova_instance_audit.py \
  --compute-dir audit-data \
  --servers control-servers.json \
  --deleted control-deleted-servers.json \
  --findings-only --format json > instance-directory-audit.json
```

The default age threshold is seven days. It is a safety filter, not proof that
a directory is stale:

```bash
python3 nova_instance_audit.py \
  --compute-dir audit-data \
  --servers control-servers.json \
  --deleted control-deleted-servers.json \
  --min-age-days 14 --format csv > instance-directory-audit.csv
```

## Interpret classifications

Important classifications include:

- `LIVE_OR_STOPPED`: Nova's host matches a libvirt domain on the compute.
- `EXPECTED_RESIZE`: a `_resize` directory exists while Nova reports a
  resize, migration, or verification-related state.
- `STALE_ORPHAN_CANDIDATE`: no Nova record or libvirt domain, and old enough
  to review as a possible stale directory.
- `STALE_DELETE_CANDIDATE`: an old `_del` directory without a libvirt domain
  or active deletion context.
- `DUPLICATE_NONOWNER_CANDIDATE`: the same UUID is on local storage on more
  than one compute, with one other compute showing the only active
  libvirt/Nova-host match.
- `INCOMPLETE_LIBVIRT_DATA`: collection failed, so the row must not be treated
  as stale.

Do not remove a candidate until you verify the path is not shared, no process
has it open, no libvirt XML references it, and no migration, evacuation,
resize, rebuild, or deletion operation is still active. A deleted or absent
Nova record is useful evidence, but is not by itself sufficient for cleanup.
