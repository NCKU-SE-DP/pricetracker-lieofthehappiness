
class DomainMismatchException(Exception):
    """Exception raised for URLs whose domain does not match the news website's domain."""

    def __init__(
        self,
        url: str,
        message: str = "URL's domain does not match the news website's domain",
    ):
        self.url = url
        self.message = message
        super().__init__(self.message)
class InvalidSearchTermException(Exception):
    """Exception raised when search term is empty or invalid"""
    def __init__(self, search_term: str, message: str = "Invalid search term"):
        self.search_term = search_term
        self.message = message
        super().__init__(self.message)


class InvalidPageException(Exception):
    """Exception raised when page number is invalid"""
    def __init__(self, page: int | tuple[int, int], message: str = "Invalid page number"):
        self.page = page
        self.message = message
        super().__init__(self.message)


class ParseException(Exception):
    """Exception raised when parsing news content fails"""
    def __init__(self, url: str, message: str = "Failed to parse news content"):
        self.url = url
        self.message = message
        super().__init__(self.message)


class SaveException(Exception):
    """Exception raised when saving news content fails"""
    def __init__(self, news, message: str = "Failed to save news content"):
        self.news = news
        self.message = message
        super().__init__(self.message)