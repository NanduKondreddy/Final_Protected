# delete_user.py
from database import SessionLocal
import db_models

db = SessionLocal()

user = db.query(db_models.User).filter(db_models.User.email == "kayodeteniola100@gmail.com").first()

if user:
    # Delete scans first (foreign key)
    db.query(db_models.Scan).filter(db_models.Scan.user_id == user.id).delete()
    db.delete(user)
    db.commit()
    print(f"✓ Deleted user: {user.email} (id={user.id})")
else:
    print("✗ User not found")

db.close()