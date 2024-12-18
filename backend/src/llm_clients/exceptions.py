class ClientException(Exception):
    """Exception raised when there is an error with the client."""
    def __init__(self, message: str = "Error with client"):
        self.message = message
        super().__init__(self.message)
class MessageValidationError(Exception):
    """Exception raised when message content validation fails"""
    def __init__(self, message: str = "Message content validation failed"):
        self.message = message
        super().__init__(self.message)

class MessageFormatError(Exception):
    """Exception raised when message format conversion fails"""
    def __init__(self, message: str = "Message format conversion failed"):
        self.message = message
        super().__init__(self.message)
class TextGenerationError(Exception):
    """Exception raised when text generation fails"""
    def __init__(self, message: str = "Text generation failed"):
        self.message = message
        super().__init__(self.message)
