from pydantic import BaseModel, Field


class ErrorResponse(BaseModel):
    """
    Standardized API error response format.
    """
    detail: str = Field(..., description="A human-readable explanation of the error.")
    error_code: str = Field(..., description="A unique code identifying the specific type of error.")
    status_code: int = Field(..., description="The HTTP status code.")

    model_config = {
        "json_schema_extra": {
            "example": {
                "detail": "Scan with ID e93f8e6c-7f24-4f05-83e3-78b1d9bf5b99 not found",
                "error_code": "NOT_FOUND",
                "status_code": 404
            }
        }
    }
