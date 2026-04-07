web: gunicorn app:app --bind 0.0.0.0:$PORT
worker: python worker.py
sales_bot: python -m workers.sales.inside_sales_bot
sales_digest: python -m workers.sales.daily_sales_digest
