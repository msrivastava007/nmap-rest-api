from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError


class InvalidTargetError(Exception):
    def __init__(self, message: str, target: str = None):
        self.message = message
        self.target = target


class DisallowedTargetError(Exception):
    def __init__(self, message: str, target: str = None):
        self.message = message
        self.target = target


class NotFoundError(Exception):
    def __init__(self, message: str):
        self.message = message


class InsufficientScansError(Exception):
    def __init__(self, message: str):
        self.message = message


class ScanTimeoutError(Exception):
    def __init__(self, message: str, scan_id: str = None):
        self.message = message
        self.scan_id = scan_id


class ScanExecutionError(Exception):
    def __init__(self, message: str):
        self.message = message


class ScanParseError(Exception):
    def __init__(self, message: str):
        self.message = message


class NmapNotFoundError(Exception):
    pass


def register_exception_handlers(app):
    @app.exception_handler(InvalidTargetError)
    async def invalid_target_handler(request: Request, exc: InvalidTargetError):
        return JSONResponse(
            status_code=400,
            content={"error": exc.message, "code": "INVALID_TARGET", "detail": exc.target},
        )

    @app.exception_handler(DisallowedTargetError)
    async def disallowed_target_handler(request: Request, exc: DisallowedTargetError):
        return JSONResponse(
            status_code=400,
            content={"error": exc.message, "code": "DISALLOWED_TARGET", "detail": exc.target},
        )

    @app.exception_handler(NotFoundError)
    async def not_found_handler(request: Request, exc: NotFoundError):
        return JSONResponse(
            status_code=404,
            content={"error": exc.message, "code": "NOT_FOUND", "detail": None},
        )

    @app.exception_handler(InsufficientScansError)
    async def insufficient_scans_handler(request: Request, exc: InsufficientScansError):
        return JSONResponse(
            status_code=404,
            content={"error": exc.message, "code": "INSUFFICIENT_SCANS", "detail": None},
        )

    @app.exception_handler(ScanTimeoutError)
    async def scan_timeout_handler(request: Request, exc: ScanTimeoutError):
        return JSONResponse(
            status_code=504,
            content={"error": exc.message, "code": "SCAN_TIMEOUT", "detail": exc.scan_id},
        )

    @app.exception_handler(ScanExecutionError)
    async def scan_execution_handler(request: Request, exc: ScanExecutionError):
        return JSONResponse(
            status_code=500,
            content={"error": exc.message, "code": "SCAN_FAILED", "detail": None},
        )

    @app.exception_handler(ScanParseError)
    async def scan_parse_handler(request: Request, exc: ScanParseError):
        return JSONResponse(
            status_code=500,
            content={"error": exc.message, "code": "PARSE_FAILED", "detail": None},
        )

    @app.exception_handler(NmapNotFoundError)
    async def nmap_not_found_handler(request: Request, exc: NmapNotFoundError):
        return JSONResponse(
            status_code=500,
            content={
                "error": "nmap is not installed or not on PATH",
                "code": "NMAP_NOT_FOUND",
                "detail": None,
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError):
        # Normalise Pydantic/FastAPI 422 errors to the same {error, code, detail} shape
        messages = "; ".join(
            f"{' -> '.join(str(l) for l in e['loc'])}: {e['msg']}"
            for e in exc.errors()
        )
        return JSONResponse(
            status_code=422,
            content={"error": messages, "code": "VALIDATION_ERROR", "detail": None},
        )
