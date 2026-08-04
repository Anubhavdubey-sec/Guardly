import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sqlalchemy.exc import SQLAlchemyError
from app import create_app
from models.system_log import SystemLog
from models.user import User, db
from services.audit import logger, record_event


class AuditLoggingServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        root = self.temp_directory.name.replace("\\", "/")
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-secret",
                "SQLALCHEMY_DATABASE_URI": f"sqlite:///{root}/test.db",
                "PUBLIC_LOOKUPS_ENABLED": False,
            }
        )
        with self.app.app_context():
            db.drop_all()
            db.create_all()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()
            for engine in db.engines.values():
                engine.dispose()
        self.temp_directory.cleanup()

    def test_record_event_success(self):
        with self.app.app_context():
            record_event("test_event", detail="Audit test detail")
            db.session.commit()

            log = db.session.scalar(db.select(SystemLog).filter_by(event="test_event"))
            self.assertIsNotNone(log)
            self.assertEqual(log.detail, "Audit test detail")
            self.assertEqual(log.target_type, "system")
            self.assertEqual(log.actor_name, "System")

    def test_record_event_with_actor(self):
        with self.app.app_context():
            user = User(username="analyst_jane", email="jane@sec.example", password="hash", role=User.ROLE_ANALYST)
            db.session.add(user)
            db.session.commit()

            record_event("login_succeeded", target_type="user", target_id=user.id, detail="User logged in", actor=user)
            db.session.commit()

            log = db.session.scalar(db.select(SystemLog).filter_by(event="login_succeeded"))
            self.assertIsNotNone(log)
            self.assertEqual(log.actor_id, user.id)
            self.assertEqual(log.actor_name, "analyst_jane")
            self.assertEqual(log.target_type, "user")

    def test_record_event_simulated_db_failure(self):
        with self.app.app_context():
            with patch("models.user.db.session.begin_nested", side_effect=SQLAlchemyError("Simulated DB Failure")):
                with patch.object(logger, "exception") as mock_logger_exception:
                    # Should not raise any exception to the caller
                    record_event("simulated_failure_event", detail="Failing log write")
                    
                    mock_logger_exception.assert_called_once()
                    self.assertIn("simulated_failure_event", mock_logger_exception.call_args[0][1])

    def test_record_event_simulated_unexpected_failure(self):
        with self.app.app_context():
            with patch("models.user.db.session.begin_nested", side_effect=RuntimeError("Simulated Unexpected Failure")):
                with patch.object(logger, "exception") as mock_logger_exception:
                    # Should not raise any exception to the caller
                    record_event("unexpected_failure_event", detail="Unexpected failure")
                    
                    mock_logger_exception.assert_called_once()
                    self.assertIn("unexpected_failure_event", mock_logger_exception.call_args[0][1])


if __name__ == "__main__":
    unittest.main()
