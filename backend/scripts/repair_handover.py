"""
repair_handover.py
Purpose:
- Repair missing ACL rows for all existing documents/cases.
- Print which client document belongs to which lawyer.
- Does NOT force everything to one lawyer.

Run from backend folder:
  python scripts/repair_handover.py

Optional targeted reassignment only if needed:
  python scripts/repair_handover.py --client-email client@example.com --to-lawyer-email lawyer@example.com
"""
import argparse
from app.db import SessionLocal
from app.models import Case, Document, DocumentAccess, PermissionType, User, UserRole


def grant(db, document_id, user_id, granted_by_id, permission):
    if not user_id:
        return None
    existing = db.query(DocumentAccess).filter_by(
        document_id=document_id,
        user_id=user_id,
        permission_type=permission,
    ).first()
    if existing:
        return existing
    access = DocumentAccess(
        document_id=document_id,
        user_id=user_id,
        granted_by_id=granted_by_id,
        permission_type=permission,
    )
    db.add(access)
    return access


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--client-email", help="Optional: only reassign this client's cases")
    parser.add_argument("--to-lawyer-email", help="Optional: move matching client cases to this lawyer")
    args = parser.parse_args()

    db = SessionLocal()
    try:
        if args.to_lawyer_email:
            if not args.client_email:
                raise SystemExit("Use --client-email with --to-lawyer-email so reassignment is not applied to everyone.")
            client = db.query(User).filter(User.email == args.client_email.lower(), User.role == UserRole.CLIENT.value).first()
            lawyer = db.query(User).filter(User.email == args.to_lawyer_email.lower(), User.role == UserRole.LAWYER.value).first()
            if not client:
                raise SystemExit(f"No CLIENT found with email: {args.client_email}")
            if not lawyer:
                raise SystemExit(f"No LAWYER found with email: {args.to_lawyer_email}")
            for case in db.query(Case).filter(Case.client_id == client.id).all():
                case.lawyer_id = lawyer.id
            db.commit()
            print(f"Reassigned cases for {client.email} to lawyer {lawyer.email}")

        for doc in db.query(Document).all():
            case = db.get(Case, doc.case_id)
            if not case:
                continue
            grant(db, doc.id, case.lawyer_id, case.lawyer_id, PermissionType.MANAGE.value)
            grant(db, doc.id, case.client_id, case.lawyer_id, PermissionType.VIEW.value)
            grant(db, doc.id, case.client_id, case.lawyer_id, PermissionType.DOWNLOAD.value)
            uploader = db.get(User, doc.uploaded_by_id)
            if uploader and uploader.role != UserRole.ADMIN.value:
                grant(db, doc.id, uploader.id, case.lawyer_id, PermissionType.VIEW.value)
                grant(db, doc.id, uploader.id, case.lawyer_id, PermissionType.DOWNLOAD.value)
        db.commit()

        print("\nUSERS")
        for u in db.query(User).order_by(User.id).all():
            print(f"{u.id}: {u.email} [{u.role}]")

        print("\nCASES")
        for c in db.query(Case).order_by(Case.id).all():
            lw = db.get(User, c.lawyer_id)
            cl = db.get(User, c.client_id)
            print(f"case {c.id}: lawyer={lw.email if lw else c.lawyer_id}, client={cl.email if cl else c.client_id}, title={c.case_title}")

        print("\nDOCUMENTS")
        for d in db.query(Document).order_by(Document.id).all():
            up = db.get(User, d.uploaded_by_id)
            c = db.get(Case, d.case_id)
            lw = db.get(User, c.lawyer_id) if c else None
            cl = db.get(User, c.client_id) if c else None
            print(f"doc {d.id}: {d.original_filename} | uploaded_by={up.email if up else d.uploaded_by_id} | lawyer={lw.email if lw else 'none'} | client={cl.email if cl else 'none'}")

        print("\nRepair complete. No one-lawyer reassignment was used unless you passed --to-lawyer-email.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
