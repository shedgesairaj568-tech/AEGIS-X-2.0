"""
Application-level exception hierarchy.

Business logic and repositories raise these instead of HTTPException, so
that `services/` and `repositories/` stay framework-agnostic (they don't
need to import FastAPI). The exception middleware (app/middleware/error_handler.py)
is responsible for translating these into HTTP responses at the edge.
"""


class AegisError(Exception):
    """Base class for all application-raised errors."""

    status_code: int = 500
    error_code: str = "internal_error"

    def __init__(self, message: str | None = None):
        self.message = message or self.__class__.__doc__ or "An error occurred"
        super().__init__(self.message)


class NotFoundError(AegisError):
    """The requested resource does not exist."""

    status_code = 404
    error_code = "not_found"


class ValidationError(AegisError):
    """The request failed a business-rule validation."""

    status_code = 422
    error_code = "validation_error"


class UnauthorizedError(AegisError):
    """Authentication is missing or invalid."""

    status_code = 401
    error_code = "unauthorized"


class ForbiddenError(AegisError):
    """The authenticated user lacks permission for this action."""

    status_code = 403
    error_code = "forbidden"


class ConflictError(AegisError):
    """The request conflicts with the current state of the resource."""

    status_code = 409
    error_code = "conflict"


class InvalidCredentialsError(UnauthorizedError):
    """Email or password is incorrect."""

    error_code = "invalid_credentials"


class UserAlreadyExistsError(ConflictError):
    """A user with this email already exists."""

    error_code = "user_already_exists"
