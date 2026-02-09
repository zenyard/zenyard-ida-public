# Pre-requisites

- IDA 9 Pro or newer.
- Python 3.10 or newer with Pip. Use `idapyswitch` (in your IDA installation
  folder) to configure which Python environment is used by IDA. Note that IDA
  versions are incompatible with later Python releases.
- Git (for installation).

# Quick installation and upgrade from IDA

Switch IDA console from **IDC** to **Python**, and run the following:

```python
try:
  from pip._vendor import truststore; truststore.inject_into_ssl()
except: pass
GIT_TOKEN="<GIT_TOKEN>"; import urllib.request; import base64; req = urllib.request.Request("https://raw.githubusercontent.com/zenyard/decompai-ida-public/main/install_from_ida.py"); req.add_header("Authorization", f"Basic {base64.b64encode(GIT_TOKEN.encode('utf-8')).decode('utf-8')}"); exec(urllib.request.urlopen(req).read())
```

This will run a script performing the steps in next section.

# Manual installation

**Note:** by following these steps, you accept [Zenyard Terms of Service](https://www.zenyard.ai/eula).

- Install package in same Python environment used by IDA:

  ```sh
  pip3 install --upgrade \
    $IDAUSR/plugins/decompai_packages \
    git+https://github.com/zenyard/decompai-ida-public.git
  ```

  Use `idapyswitch` to verify or change the Python environment used by IDA.

  **Note** - the above will install all packages to a folder. You may choose to
  install package globally, to the user (with `--user`) or to a virtualenv if
  your setup is properly configured for these options.

- Add `decompai_stub.py` to [`$IDAUSR/plugins/`][1] folder (you may need to
  create this folder).

- Add the `decompai.json` to [`$IDAUSR/`][1] folder, and replace `<API KEY>`
  with your API key.

[1]: https://hex-rays.com/blog/igors-tip-of-the-week-33-idas-user-directory-idausr
