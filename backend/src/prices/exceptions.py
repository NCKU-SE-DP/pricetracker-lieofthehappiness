class PriceServiceException(Exception):
    """Base exception class for price service"""
    def __init__(self, message: str = "Price service error"):
        self.message = message
        super().__init__(self.message)

class PriceRetrievalException(PriceServiceException):
    """Exception when retrieving price information"""
    def __init__(self, message: str = "Failed to retrieve price information"):
        super().__init__(message)
