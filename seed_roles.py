from app import create_app, db
from app.models.role import Role, Permission

def seed_roles_permissions():
    app = create_app()
    with app.app_context():
        # Define roles
        roles = ["super_admin", "admin", "auditor", "manager", "employee"]
        for role_name in roles:
            role = Role.query.filter_by(name=role_name).first()
            if not role:
                role = Role(name=role_name)
                db.session.add(role)

        # Define permissions
        permissions = ["view_users", "delete_user", "change_role", "view_reports"]
        for perm_name in permissions:
            perm = Permission.query.filter_by(name=perm_name).first()
            if not perm:
                perm = Permission(name=perm_name)
                db.session.add(perm)

        db.session.commit()

        # Attach permissions to roles
        super_admin = Role.query.filter_by(name="super_admin").first()
        admin = Role.query.filter_by(name="admin").first()

        delete_user = Permission.query.filter_by(name="delete_user").first()
        view_users = Permission.query.filter_by(name="view_users").first()

        if super_admin and delete_user and view_users:
            super_admin.permissions.extend([delete_user, view_users])

        if admin and view_users:
            admin.permissions.append(view_users)

        db.session.commit()
        print("Roles, permissions, and assignments seeded successfully.")

if __name__ == "__main__":
    seed_roles_permissions()