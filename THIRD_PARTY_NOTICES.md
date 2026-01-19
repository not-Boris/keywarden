# Third-party notices

This project is licensed under the GNU AGPL v3. It includes third-party components that
are distributed under their own licenses. When redistributing Keywarden (source or binary),
ensure you comply with each component's license terms and include required notices.

## Valkey
Valkey is included in the container image and used as the cache backend.
License: BSD 3-Clause. See `LICENSES/valkey.BSD-3-Clause.txt`.

## Other third-party components
This repository and container image include additional dependencies (Python packages and
system packages). Their licenses typically require you to retain copyright notices and
license texts when redistributing binaries. Review the following sources to determine
exact obligations:

- `requirements.txt` for Python dependencies.
- `Dockerfile` for system packages installed into the image.
- `app/static/` and `app/theme/` for bundled frontend assets.

If you need a full license inventory, generate it from your build environment and add
corresponding license texts under `LICENSES/`.
