from sqlalchemy import create_engine, or_
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker

from config import DATABASE_URL

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def search_scans_by_query(db, query: str, owner_id: int) -> list:
    """Search one user's scans with bound ORM expressions.

    Escaping LIKE metacharacters makes user input a literal substring rather
    than an accidental wildcard query. ORM binding prevents SQL injection.
    """
    # Imported here to avoid the models -> database.Base import cycle.
    import models

    escaped_query = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    pattern = f"%{escaped_query}%"
    rows = (
        db.query(models.ScanResult)
        .filter(models.ScanResult.owner_id == owner_id)
        .filter(
            or_(
                models.ScanResult.title.like(pattern, escape="\\"),
                models.ScanResult.description.like(pattern, escape="\\"),
                models.ScanResult.cve_id.like(pattern, escape="\\"),
            )
        )
        .limit(100)
        .all()
    )
    return [
        {
            "id": row.id,
            "title": row.title,
            "description": row.description,
            "severity": row.severity,
            "status": row.status,
            "cve_id": row.cve_id,
            "affected_component": row.affected_component,
            "owner_id": row.owner_id,
            "created_at": row.created_at,
        }
        for row in rows
    ]
