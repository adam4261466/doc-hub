import os
import shutil
from sqlalchemy import text
from app import create_app, db
from app.models import User, File, Chunk, IndexMeta

app = create_app()

with app.app_context():
    try:
        # Delete chunks first (lowest level)
        db.session.query(Chunk).delete()
        db.session.commit()
        print("✅ Deleted all chunks")

        # Delete files
        db.session.query(File).delete()
        db.session.commit()
        print("✅ Deleted all files")

        # Delete index metadata
        db.session.query(IndexMeta).delete()
        db.session.commit()
        print("✅ Deleted all index metadata")

        # Delete users
        db.session.query(User).delete()
        db.session.commit()
        print("✅ Deleted all users")

        # Reset sequences
        db.session.execute(text("ALTER SEQUENCE users_id_seq RESTART WITH 1"))
        print("🔄 Reset users ID sequence")

        db.session.execute(text("ALTER SEQUENCE files_id_seq RESTART WITH 1"))
        print("🔄 Reset files ID sequence")

        db.session.execute(text("ALTER SEQUENCE chunks_id_seq RESTART WITH 1"))
        print("🔄 Reset chunks ID sequence")

        db.session.execute(text("ALTER SEQUENCE index_meta_id_seq RESTART WITH 1"))
        print("🔄 Reset index_meta ID sequence")

        db.session.commit()
        print("🎉 All data deleted and ID sequences reset successfully!")

    except Exception as e:
        db.session.rollback()
        print(f"❌ Error: {e}")

    
    # Clear the data folder
    data_dir = 'data'
    if os.path.exists(data_dir):
        for item in os.listdir(data_dir):
            item_path = os.path.join(data_dir, item)
            if os.path.isdir(item_path):
                shutil.rmtree(item_path)
                print(f"Deleted directory: {item_path}")
            else:
                os.remove(item_path)
                print(f"Deleted file: {item_path}")
        print("All contents of the data folder have been cleared.")
    else:
        print("Data folder does not exist.")
