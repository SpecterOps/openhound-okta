# Run the Okta collector with Docker Compose

Run the published Okta scheduler image against a BloodHound Enterprise (BHE)
tenant using an Okta OAuth service app. The images support Linux AMD64 and
ARM64, and Docker automatically selects the image for the host architecture.

The scheduler polls BHE for jobs. Starting the container does not start a
collection: run an on-demand scan or configure a schedule in BHE.

## Prerequisites

- Docker Engine with the Compose plugin on Linux, or Docker Desktop on macOS.
- A BHE tenant with OpenHound enabled and the Okta extension assets installed.
- An Okta OpenHound collector client in BHE and its token ID and token key.
  These are collector-client credentials, not a general user's API token.
- Okta credentials with the collector's required scopes and admin roles, using
  one of the authentication methods described in the main README: an OAuth
  service app's client ID and private RSA JWK JSON object containing a `kid`
  (mounted as a file or supplied base64-encoded), an API Service Integration's
  client ID and client secret, or an SSWS API token. A PEM file cannot be used
  as `private_key_path` by this collector.

## Prepare configuration

From the repository root:

```sh
cd docker-compose
cp .env.example .env
cp .dlt/config.toml.example .dlt/config.toml
cp .dlt/secrets.toml.example .dlt/secrets.toml
cp /path/to/okta-app.jwk .dlt/okta-app.jwk   # private key file authentication only
```

The resulting layout is:

```text
docker-compose/
├── compose.yaml
├── check_config.py
├── .env
└── .dlt/
    ├── config.toml
    ├── secrets.toml
    └── okta-app.jwk
```

Edit `.dlt/config.toml` and `.dlt/secrets.toml` locally and replace the placeholders:

| Setting | Value |
| --- | --- |
| BHE `url` (in `config.toml`) | Your BHE tenant's HTTPS URL |
| BHE `token_id`, `token_key` | The Okta OpenHound collector client's credentials |
| Okta `base_url` | Your Okta org's HTTPS URL, such as `https://example.okta.com` |
| Okta `client_id` | The Okta OAuth service app's or API Service Integration's client ID |
| Okta `private_key_path` | Leave `/app/.dlt/okta-app.jwk` when using the layout above |
| Okta `private_key_b64` | The base64-encoded JWK, instead of mounting `private_key_path` |
| Okta `client_secret` | The API Service Integration's client secret, instead of a private key |
| Okta `token` | An SSWS API token, instead of `client_id` and a key or secret |

Actual `.env`, `.dlt` configuration files, and private keys are ignored by Git.
Only the example files are intended for publication. The `.dlt` directory is
mounted read-only into the container.

The container runs as UID/GID `65532` on every host. Its mounted files must be
readable by that user. On Linux and macOS, keep this host directory owner-only
while allowing the container to read the mounted copies:

```sh
chmod 700 .
chmod 755 .dlt
chmod 644 .dlt/config.toml .dlt/secrets.toml .dlt/okta-app.jwk
```

These commands affect the local key copy, not the original downloaded key. The
owner-only parent directory protects the host copies while the mounted `.dlt`
directory and files remain readable inside the container. On Linux systems
with enforcing SELinux, the bind-mounted `.dlt` directory must also have a
container-readable SELinux label permitted by the host policy.

## Validate and start

```sh
docker compose config --quiet
docker compose pull
docker compose run --rm --entrypoint python scheduler-okta /opt/openhound-check-config.py
docker compose up -d scheduler-okta
docker compose logs -f scheduler-okta
```

The preflight resolves the same credential kind the collector would, checks
RSA private JWK validity for private key authentication, and probes writable
storage. It does not authenticate to Okta or BHE. The one-shot
`storage-init` service prepares the named volumes before the scheduler starts;
the scheduler itself runs as non-root.

In BHE, run an on-demand scan for the matching collector client. Follow the
container logs and BHE's collection, ingest, and analysis status. API rate-limit
retries can make a large collection take longer.

## Image versions and updates

`.env.example` follows the `latest` scheduler release. Set `OPENHOUND_IMAGE` in
`.env` to a specific published version if you need a fixed deployment. Use the
scheduler image, without the `-cli` suffix.

After changing the image, or to update a deployment using `latest`, run:

```sh
docker compose pull
docker compose up -d scheduler-okta
```

A running container does not update automatically when a tag changes in GHCR.

## Storage and operations

| Named volume | Contents |
| --- | --- |
| `collector-data` | DLT state, the DuckDB lookup database, and application logs under `/var/lib/openhound` |
| `raw-data` | Raw collection output under `/tmp/openhound` |

```sh
docker compose ps -a
docker compose logs --tail 100 scheduler-okta
docker compose stop scheduler-okta
docker compose down
```

Normal `down` and container recreation preserve the named volumes.
`docker compose down --volumes` deletes them and their stored collection data.
Stop the scheduler after a collection completes. Idle shutdown can take up to
the 30-second polling interval; Compose allows 45 seconds before forcing exit.

The collector needs outbound access to Okta and BHE; no inbound host ports
are required. Each deployment should have its own BHE collector client and
Compose project name. Use `docker compose -p <name> ...` consistently if running
multiple copies so their containers and volumes remain separate.

## Troubleshooting

- **Preflight reports a placeholder:** fill in `.dlt/config.toml` and `.dlt/secrets.toml` and rerun it.
- **Private key or secrets cannot be read:** verify the mounted file paths and
  UID `65532` read permissions. On Linux with enforcing SELinux, also verify
  that policy permits the `.dlt` bind mount. The container key path is
  different from the path of the downloaded key on your host.
- **BHE authentication fails:** check the tenant URL and the matching Okta
  OpenHound collector client's token ID/key.
- **Scheduler is idle:** start an on-demand scan or schedule a collection in BHE.
- **Okta authentication fails:** confirm the JWK belongs to the configured
  service app and that its scopes and admin roles allow collection.
