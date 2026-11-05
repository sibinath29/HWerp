# Team ERP
Run:  pip install -r requirements.txt && python app.py   → http://localhost:5000
Production: gunicorn app:app  (set ERP_SECRET env var; keep erp.db on a persistent disk)
Logins are in CREDENTIALS.txt. Change passwords after first login, then delete that file.
