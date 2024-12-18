class UserException(Exception):
    """Base exception class for user service"""
    def __init__(self, message: str = "User service error"):
        self.message = message
        super().__init__(self.message)

class UserAuthenticationError(UserException):
    """Exception raised when user authentication fails"""
    def __init__(self, message: str = "User authentication failed"):
        super().__init__(message)

class UserRegistrationError(UserException):
    """Exception raised when user registration fails"""
    def __init__(self, message: str = "User registration failed"):
        super().__init__(message)