import os
import datetime

# Config
DOCS_DIR = "docs"
STALE_DAYS = 30  # how many days before we consider a file stale

# Today's date
now = datetime.datetime.now()

print("🔎 Checking for stale documentation...\n")

for filename in os.listdir(DOCS_DIR):
    if filename.endswith(".md"):
        filepath = os.path.join(DOCS_DIR, filename)
        last_modified = datetime.datetime.fromtimestamp(os.path.getmtime(filepath))
        age_days = (now - last_modified).days

        if age_days >= STALE_DAYS:
            print(f"⚠️ STALE: {filename} (Last modified {age_days} days ago)")
        else:
            print(f"✅ Fresh: {filename} (Last modified {age_days} days ago)")

print("\n✅ Done.")
