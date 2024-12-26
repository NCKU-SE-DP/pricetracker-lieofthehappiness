# tests/test_database.py
import pytest
from unittest.mock import patch, MagicMock
from src.database import session_opener
from src.exceptions import DatabaseConnectionError

def test_session_opener_raises_database_connection_error():
    with patch('src.database.Session') as mock_session:
        # 模擬 Session 的行為，讓它引發異常
        mock_session.side_effect = Exception("Connection failed")
        
        with pytest.raises(DatabaseConnectionError) as exc_info:
            list(session_opener())
        
        assert "Database connection error: Connection failed" in str(exc_info.value)