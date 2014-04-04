import sqlalchemy as sql
from .database import Base

class ModelError(Exception):
    pass

class Permission(Base):
    """The representation of a single permission in the DB"""
    __tablename__ = "permissions"
    
    uid = sql.Column(sql.Integer, sql.ForeignKey("users.id"))
    space_key = sql.Column(sql.String(64))
    permissions = sql.Column(sql.Integer)

    __table_args__ = (sql.PrimaryKeyConstraint(uid, space_key),)

class Status(Base):
    """Lookup table for statuses"""
    __tablename__ = 'status'

    id = sql.Column(sql.Integer, sql.Sequence('status_id_seq'), primary_key=True)
    value = sql.Column(sql.String(32), unique=True)

class User(Base):
    """Representation of a 'user' in the database"""
    __tablename__ = 'users'

    id = sql.Column(sql.Integer, sql.Sequence('user_id_seq'), primary_key=True)
    email = sql.Column(sql.String(50))
    description = sql.Column(sql.String(128))
    created = sql.Column(sql.DateTime())
    status_id = sql.Column(sql.Integer, sql.ForeignKey("status.id"))
    key = sql.Column(sql.String(36), unique=True)

    permissions = sql.orm.relationship("Permission", backref="user")
    status = sql.orm.relationship("Status", uselist=False)
    
    def __repr__(self):
        return "User({0}, {1}, {2})".format(self.email,
                                            self.status,
                                            self.key)

    def _get_permission(self, space):
        perms = [x for x in self.permissions if x.space_key == space]
        if len(perms) > 1:
            raise ModelError("user %d has multiple perms %s".format(self.id,
                                                                    space))
        return perms[0] if len(perms) else None

    def can(self, op, space):
        perm = self._get_permission(space)
        return False if perm is None else (op & perm.permissions != 0)

    def set_permission(self, space, *mode):
        perms = reduce(lambda x, y: x | y, mode)
        perm = self._get_permission(space)
        if perm is None:
            self.permissions.append(Permission(space_key=space, permissions=perms))
        else:
            perm.permissions = perms
