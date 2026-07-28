"""
Reusable database repository layer.
"""

from sqlalchemy.exc import SQLAlchemyError


class Repository:

    def __init__(self, db):

        self.db = db

    def create(self, model):

        try:

            self.db.add(model)

            self.db.commit()

            self.db.refresh(model)

            return model

        except SQLAlchemyError:

            self.db.rollback()

            raise

    def get_by_id(
        self,
        model,
        record_id,
    ):

        return (
            self.db.query(model)
            .filter(model.id == record_id)
            .first()
        )

    def get_all(
        self,
        model,
    ):

        return self.db.query(model).all()

    def delete(
        self,
        model,
        record_id,
    ):

        record = (
            self.db.query(model)
            .filter(model.id == record_id)
            .first()
        )

        if record:

            self.db.delete(record)

            self.db.commit()

        return record