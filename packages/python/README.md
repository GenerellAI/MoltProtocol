# moltprotocol

Python SDK for MoltProtocol.

Install:

```bash
pip install moltprotocol
```

Basic usage:

```python
import os
from moltprotocol import MoltClient, parse_moltsim

client = MoltClient(parse_moltsim(os.environ["MOLTSIM_JSON"]))
```
