Basic use of Flask-Login with
- Users roles
- Passwords hashed with passlib
- Timed session expiration

To use first clone the repo. Then create a virtual environment:

```
python -m venv
```

You may need to use ```python3``` instead of ```python``` if python 3.x isn't the default for your OS.

Next install the requirements:

```
env/bin/pip install -r requirements.txt
```

Make app.py executable:

```
chmod +x app.py
```

Run ```./app.py``` and open a web browser to ```http://localhost:5000```.

There are 10 users named ```user1``` through ```user10```. Each user's password is ```username``` + ```_secret```. ```user1``` has the ```admin``` role.
