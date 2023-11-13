API endpoints same as at https://github.com/Hhacel/BezpSerwerHacel.

Dependencies:
- Flask
- cryptography

Public keys are expected to be exchanged in PEM format

Run with `flask run` or `flask run --host=0.0.0.0` for the server to be accessible on network, with environment variable `FLASK_APP = server.py`

All fields, as well as top level keys (message ids) of json returned by the GET endpoint are encrypted and base64 encoded.

Expects files `private_key` and `public_key` to be in same directory, containing respective keys in PEM format (no examples provided).

Will automatically create database.db if it does not exist.
### Database diagram
![Database diagram](diagram.png)
