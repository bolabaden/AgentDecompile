"""Await native work without releasing invocation locks during cancellation."""

import asyncio


async def native_call(function, *values, **keywords):
    # Native import and analysis can take minutes. Keep HTTP status
    # requests responsive without releasing the invocation's locks.
    worker = asyncio.create_task(asyncio.to_thread(function, *values, **keywords))
    try:
        return await asyncio.shield(worker)
    except asyncio.CancelledError:
        while not worker.done():
            try:
                await asyncio.shield(worker)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        if not worker.cancelled():
            worker.exception()
        raise
