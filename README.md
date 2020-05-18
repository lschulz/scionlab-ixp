Experimental Peering Extension for SCIONLab
===========================================
Automatically creates peering links between user ASes based on peering policies configured via a
REST API.

Installation
------------
1. Follow the installation instructions for installing the SCIONLab Coordinator at
<https://github.com/netsec-ethz/scionlab#installation>. Make sure the scionlab venv is active and
navigate to the root of the SCIONLab source tree.

2. Clone this repository as a git submodule into the SCIONLab source tree.
```bash
git submodule add https://github.com/lschulz/scionlab-ixp scionlab_ixp
```

3. Install the additional Python requirements.
```bash
pip install --require-hashes -r scionlab_ixp/requirements.txt
```

4. Add `scionlab_ixp` to the `INSTALLED_APPS` in `scionlab/settings/common.py`, e.g.,
```python
INSTALLED_APPS = [
    'scionlab',
    'scionlab_ixp',
    # ...
]
```

5. Include the peering API into the coordinator's URLconf in `scionlab/urls.py`:
```python
urlpatterns = [
    # ...
    path('api/peering/', include('scionlab_ixp.urls')), # Add this line.
    # ...
]
```

6. Apply the database migrations.
```bash
./manage.py migrate
```
