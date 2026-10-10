import os

# must run before app.main is imported: keep tests off the real database file
os.environ["DATABASE_URL"] = "sqlite://"
