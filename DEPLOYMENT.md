# Deployment Notes

## Local Setup

```powershell
C:\Users\23503\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -m pip install -r requirements.txt
C:\Users\23503\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe app.py
```

Open:

```text
http://127.0.0.1:5000/
```

## Before Publishing

- Keep `SECRET_KEY` in an environment variable before deploying publicly.
- Do not commit `instance/database.db`; the app can rebuild artwork data from `artwork.csv`.
- SQLite is fine for a demo, but Postgres is better for a real public deployment.
- Use `debug=False` in production.
- Render, Railway, Fly.io, or PythonAnywhere are all reasonable hosts for this Flask app.

## Render Deployment

1. Push this folder to a GitHub repository.
2. In Render, create a new Blueprint and select the repository.
3. Render can use `render.yaml` to create the web service and Postgres database.
4. Start command: `gunicorn app:app`.
5. Required environment variables:
   - `SECRET_KEY`
   - `DATABASE_URL`
