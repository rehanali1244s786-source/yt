# gunicorn / Pella / Render / Heroku entry point:  gunicorn -c gunicorn.conf.py main:app
from app import app, run

if __name__ == "__main__":
    run()
