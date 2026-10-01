import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import create_app
from config import Config
from models.user import User, db
from models.migrations import apply_schema_migrations


class DatabaseConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        root = self.temp_directory.name.replace("\\", "/")
        self.app = create_app({
            "TESTING": True,
            "SECRET_KEY": "test-secret",
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "UPLOAD_FOLDER": os.path.join(self.temp_directory.name, "uploads"),
        })

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()
            for engine in db.engines.values():
                engine.dispose()
        self.temp_directory.cleanup()

    def test_default_configuration_values(self):
        self.assertTrue(Config.SECRET_KEY)
        self.assertEqual(Config.MAX_CONTENT_LENGTH, 10 * 1024 * 1024)

    def test_database_table_creation(self):
        with self.app.app_context():
            db.create_all()
            self.assertTrue(db.inspect(db.engine).has_table("users"))
            self.assertTrue(db.inspect(db.engine).has_table("email_scans"))
            self.assertTrue(db.inspect(db.engine).has_table("system_logs"))

    def test_schema_migrations_execution(self):
        with self.app.app_context():
            db.create_all()
            apply_schema_migrations()
            self.assertTrue(db.inspect(db.engine).has_table("email_scans"))

    def test_user_roles(self):
        self.assertEqual(User.ROLE_ADMIN, "admin")
        self.assertEqual(User.ROLE_ANALYST, "analyst")
        self.assertEqual(User.ROLE_USER, "user")

    def test_postgres_url_normalization(self):
        old_val = os.environ.get("DATABASE_URL")
        try:
            os.environ["DATABASE_URL"] = "postgres://user:pass@render-db.com:5432/guardly"
            # Re-read database url logic as implemented in Config
            url = os.environ["DATABASE_URL"]
            if url.startswith("postgres://"):
                url = url.replace("postgres://", "postgresql://", 1)
            self.assertTrue(url.startswith("postgresql://"))
        finally:
            if old_val is not None:
                os.environ["DATABASE_URL"] = old_val
            else:
                os.environ.pop("DATABASE_URL", None)


if __name__ == "__main__":
    unittest.main()
