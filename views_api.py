from http import HTTPStatus

from fastapi import APIRouter, Depends, HTTPException, Response
from lnbits.core.models import SimpleStatus
from lnbits.core.models.users import AccountId
from lnbits.decorators import check_account_id_exists

from .models import (
    ConnectionView,
    ConnectionWithOperation,
    CreateBunkerConnection,
    CreateNostrConnectConnection,
    CreateSignerRequest,
    OperationView,
    PermissionPreset,
)
from .services import (
    SignerCapacityError,
    SignerRateLimitError,
    connection_view,
    create_bunker_connection,
    create_nostrconnect_connection,
    get_connection_view,
    get_operation_view,
    list_connection_views,
    operation_view,
    permission_presets,
    request_signer_for_user,
    retry_connection,
    revoke_connection,
)

externalsigner_api_router = APIRouter()


def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


@externalsigner_api_router.get(
    "/api/v1/presets",
    response_model=list[PermissionPreset],
)
async def api_permission_presets(
    response: Response,
    _account_id: AccountId = Depends(check_account_id_exists),
) -> list[PermissionPreset]:
    _no_store(response)
    return permission_presets()


@externalsigner_api_router.get(
    "/api/v1/connections",
    response_model=list[ConnectionView],
)
async def api_connections(
    response: Response,
    account_id: AccountId = Depends(check_account_id_exists),
) -> list[ConnectionView]:
    _no_store(response)
    return await list_connection_views(account_id.id)


@externalsigner_api_router.get(
    "/api/v1/connections/{connection_id}",
    response_model=ConnectionView,
)
async def api_connection(
    connection_id: str,
    response: Response,
    account_id: AccountId = Depends(check_account_id_exists),
) -> ConnectionView:
    _no_store(response)
    item = await get_connection_view(account_id.id, connection_id)
    if not item:
        raise HTTPException(HTTPStatus.NOT_FOUND, "External signer connection not found.")
    return item


@externalsigner_api_router.post(
    "/api/v1/connections/bunker",
    response_model=ConnectionWithOperation,
    status_code=HTTPStatus.CREATED,
)
async def api_create_bunker_connection(
    data: CreateBunkerConnection,
    response: Response,
    account_id: AccountId = Depends(check_account_id_exists),
) -> ConnectionWithOperation:
    _no_store(response)
    try:
        connection, operation = await create_bunker_connection(account_id.id, data)
        return ConnectionWithOperation(
            connection=await connection_view(connection),
            operation=await operation_view(operation),
        )
    except SignerCapacityError as exc:
        raise HTTPException(HTTPStatus.CONFLICT, str(exc)) from exc
    except (PermissionError, ValueError) as exc:
        raise HTTPException(HTTPStatus.BAD_REQUEST, str(exc)) from exc


@externalsigner_api_router.post(
    "/api/v1/connections/nostrconnect",
    response_model=ConnectionWithOperation,
    status_code=HTTPStatus.CREATED,
)
async def api_create_nostrconnect_connection(
    data: CreateNostrConnectConnection,
    response: Response,
    account_id: AccountId = Depends(check_account_id_exists),
) -> ConnectionWithOperation:
    _no_store(response)
    try:
        connection = await create_nostrconnect_connection(account_id.id, data)
        return ConnectionWithOperation(
            connection=await connection_view(connection),
            operation=None,
        )
    except SignerCapacityError as exc:
        raise HTTPException(HTTPStatus.CONFLICT, str(exc)) from exc
    except (PermissionError, ValueError) as exc:
        raise HTTPException(HTTPStatus.BAD_REQUEST, str(exc)) from exc


@externalsigner_api_router.post(
    "/api/v1/connections/{connection_id}/retry",
    response_model=ConnectionWithOperation,
)
async def api_retry_connection(
    connection_id: str,
    response: Response,
    account_id: AccountId = Depends(check_account_id_exists),
) -> ConnectionWithOperation:
    _no_store(response)
    try:
        operation = await retry_connection(account_id.id, connection_id)
        connection = await get_connection_view(account_id.id, connection_id)
        if not connection:
            raise ValueError("External signer connection not found.")
        return ConnectionWithOperation(
            connection=connection,
            operation=await operation_view(operation) if operation else None,
        )
    except SignerCapacityError as exc:
        raise HTTPException(HTTPStatus.CONFLICT, str(exc)) from exc
    except (PermissionError, ValueError) as exc:
        raise HTTPException(HTTPStatus.BAD_REQUEST, str(exc)) from exc


@externalsigner_api_router.delete(
    "/api/v1/connections/{connection_id}",
    response_model=SimpleStatus,
)
async def api_revoke_connection(
    connection_id: str,
    response: Response,
    account_id: AccountId = Depends(check_account_id_exists),
) -> SimpleStatus:
    _no_store(response)
    try:
        await revoke_connection(account_id.id, connection_id)
        return SimpleStatus(
            success=True,
            message="Connection revoked and the local client capability was erased.",
        )
    except ValueError as exc:
        raise HTTPException(HTTPStatus.NOT_FOUND, str(exc)) from exc


@externalsigner_api_router.post(
    "/api/v1/connections/{connection_id}/requests",
    response_model=OperationView,
    status_code=HTTPStatus.ACCEPTED,
)
async def api_create_request(
    connection_id: str,
    data: CreateSignerRequest,
    response: Response,
    account_id: AccountId = Depends(check_account_id_exists),
) -> OperationView:
    _no_store(response)
    try:
        operation = await request_signer_for_user(
            account_id.id,
            connection_id,
            data.method,
            data.params,
        )
        return await operation_view(operation)
    except SignerRateLimitError as exc:
        raise HTTPException(HTTPStatus.TOO_MANY_REQUESTS, str(exc)) from exc
    except SignerCapacityError as exc:
        raise HTTPException(HTTPStatus.CONFLICT, str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(HTTPStatus.FORBIDDEN, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(HTTPStatus.BAD_REQUEST, str(exc)) from exc


@externalsigner_api_router.get(
    "/api/v1/operations/{operation_id}",
    response_model=OperationView,
)
async def api_operation(
    operation_id: str,
    response: Response,
    account_id: AccountId = Depends(check_account_id_exists),
) -> OperationView:
    _no_store(response)
    operation = await get_operation_view(account_id.id, operation_id)
    if not operation:
        raise HTTPException(HTTPStatus.NOT_FOUND, "External signer operation not found.")
    return operation
