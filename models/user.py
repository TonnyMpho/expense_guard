#!/usr/bin/env python3
""" User model """
from models.base_model import Base
import bcrypt


class User(Base):
    """ Class for creating a user instance """

    def __init__(self, *args, **kwargs):
        """ initialization of a user instance """
        super().__init__(*args, **kwargs)
        self.username = kwargs.get('usernamr')
        self.email = kwargs.get('email')
        self._password = kwargs.get('_password')

    @property
    def password(self)
