class NewsServiceException(Exception):
    """Base exception class for news service"""
    def __init__(self, message: str = "News service error"):
        self.message = message
        super().__init__(self.message)

class NewsAddException(NewsServiceException):
    """Exception when adding news"""
    def __init__(self, message: str = "Failed to add news"):
        super().__init__(message)

class NewsRetrievalException(NewsServiceException):
    """Exception when retrieving news"""
    def __init__(self, message: str = "Failed to retrieve news"):
        super().__init__(message)

class UpvoteOperationException(NewsServiceException):
    """Exception when upvoting"""
    def __init__(self, message: str = "Failed to upvote"):
        super().__init__(message)
class NewsSearchException(Exception):
    """Exception when searching news"""
    def __init__(self, message: str = "Failed to search news"):
        self.message = message
        super().__init__(self.message)

class NewsSummaryException(Exception):
    """Exception when generating news summary"""
    def __init__(self, message: str = "Failed to generate news summary"):
        self.message = message
        super().__init__(self.message)

class UpvoteException(Exception):
    """Exception when upvoting"""
    def __init__(self, message: str = "Failed to upvote"):
        self.message = message
        super().__init__(self.message)
