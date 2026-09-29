"""Drain one bounded batch per tenant. Run repeatedly with an external scheduler.

Usage: make auth-mail  (one pass; never prints addresses, content or credentials)
Multiple processes may run safely using PostgreSQL FOR UPDATE SKIP LOCKED.
"""

from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from uuid import UUID

from sqlalchemy import select

from app.core.config import get_settings
from app.db.session import Database
from app.integrations.auth_mail import transport_for
from app.models.identity import Tenant
from app.services.auth_delivery import AuthDelivery


async def drain_once(batch_size: int = 25) -> dict[str, int]:
    settings = get_settings()
    problems = settings.validate_for_startup()
    if problems:
        raise RuntimeError("Invalid worker settings: " + "; ".join(problems))
    database = Database(settings.database_url, use_null_pool=True)
    totals: Counter[str] = Counter()
    try:
        # Keyset pages bound memory, including cancelled/deleted tenants so their
        # pending payloads can be erased rather than stranded forever.
        after: UUID | None = None
        while True:
            async with database.session() as session:
                query = select(Tenant.id).order_by(Tenant.id).limit(100)
                if after is not None:
                    query = query.where(Tenant.id > after)
                tenants = list((await session.execute(query)).scalars())
            if not tenants:
                break
            for tenant_id in tenants:
                async with database.session() as session:
                    result = await AuthDelivery(session, settings).deliver_batch(
                        tenant_id, transport_for(settings), limit=batch_size
                    )
                    await session.commit()
                    totals.update(result)
            after = tenants[-1]
        return dict(totals)
    finally:
        await database.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch-size", type=int, default=25, choices=range(1, 101))
    args = parser.parse_args()
    # Only aggregate counts; no secrets/PII go to stdout.
    from app.core.logging import get_logger

    get_logger(__name__).info(
        "auth_mail_pass_completed", counts=asyncio.run(drain_once(args.batch_size))
    )


if __name__ == "__main__":
    main()
