import jwt
from flask import request, abort, current_app


def auth_requered(func):
    def wrapper(*args, **kwargs):
        if not "Authorization" in request.headers:
            abort(401)

        token = (request.headers['Authorization']).split("Bearer ")[-1]
        try:
            jwt.decode(token, key=current_app.config['SECRET_KEY'], algorithms=current_app.config['ALGORITHM'])
        except Exception as e:
            print(f"JWT decode error {e}")
            abort(401)
        return func(*args, **kwargs)

    return wrapper
