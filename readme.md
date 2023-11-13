API endpoints same as at https://github.com/Hhacel/BezpSerwerHacel.

Dependencies:
- Flask
- cryptography

Public keys are expected to be exchanged in PEM format

Run with `flask run` or `flask run --host=0.0.0.0` for the server to be accessible on network, with environment variable `FLASK_APP = server.py`