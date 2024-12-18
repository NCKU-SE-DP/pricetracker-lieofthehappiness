class PasswordVerificationError(Exception):
    """密碼驗證錯誤"""
    def __init__(self, message="Password verification failed"):
        self.message = message
        super().__init__(self.message)
class UserNotFoundException(Exception):
    """使用者不存在錯誤"""
    def __init__(self, message="User not found"):
        self.message = message
        super().__init__(self.message)

class TokenDecodeError(Exception):
    """Token 解碼錯誤"""
    def __init__(self, message="Token decode failed"):
        self.message = message
        super().__init__(self.message)