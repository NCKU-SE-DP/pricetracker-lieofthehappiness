class NewsServiceException(Exception):
    """Base exception class for news service"""
    def __init__(self, message: str = "News service error"):
        super().__init__(message)

class NewsAddException(NewsServiceException):
    """Exception when adding news"""
    def __init__(self, message: str = "Failed to add news"):
        super().__init__(message)
class UpvoteOperationException(NewsServiceException):
    """Exception when upvoting"""
    def __init__(self, message: str = "Failed to upvote"):
        super().__init__(message)

class NewsSearchException(NewsServiceException):
    """Exception when searching news"""
    def __init__(self, message: str = "Failed to search news"):
        super().__init__(message)

class NewsSummaryException(NewsServiceException):
    """Exception when generating news summary"""
    def __init__(self, message: str = "Failed to generate news summary"):
        super().__init__(message)

class UpvoteException(NewsServiceException):
    """Exception when upvoting"""
    def __init__(self, message: str = "Failed to upvote"):
        super().__init__(message)
