#!/bin/sh
python -c "
from app import create_app, db
from sqlalchemy import text
app = create_app()
with app.app_context():
    try:
        db.session.execute(text('ALTER TABLE files ADD COLUMN IF NOT EXISTS content BYTEA'))
        db.session.execute(text('''
            CREATE TABLE IF NOT EXISTS faiss_index_store (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL UNIQUE,
                index_data BYTEA,
                metadata_json JSONB,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        '''))
        db.session.commit()
        print('Migration OK')
    except Exception as e:
        db.session.rollback()
        print('Migration error:', e)
"
flask db upgrade
gunicorn "app:create_app()" --bind "0.0.0.0:${PORT:-8080}" --workers 1 --timeout 120
