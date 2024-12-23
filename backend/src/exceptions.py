class MainException(Exception):
    """Base exception class for main service"""
    def __init__(self, message: str = "Main service error"):
        self.message = message
        super().__init__(self.message)

class SchedulerStartupError(MainException):
    """Exception raised when scheduler startup fails"""
    def __init__(self, message: str = "Scheduler startup failed"):
        super().__init__(message)

class SchedulerShutdownError(MainException):
    """Exception raised when scheduler shutdown fails"""
    def __init__(self, message: str = "Scheduler shutdown failed"):
        super().__init__(message)
