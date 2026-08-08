"""
database/repositories.py

Reusable database repository layer for NTCF.
"""

from sqlalchemy.exc import SQLAlchemyError

from database.models import (
    ThreatEvent,
    DetectionResult,
    FirewallAction,
)


class Repository:
    """
    Generic CRUD repository.
    """

    def __init__(self, db):
        self.db = db

    def create(self, model):
        """
        Create and persist a model.
        """

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
        """
        Retrieve a record by primary key.
        """

        return (
            self.db.query(model)
            .filter(
                model.id == record_id
            )
            .first()
        )

    def get_all(self, model):
        """
        Retrieve all records for a model.
        """

        return self.db.query(model).all()

    def delete(
        self,
        model,
        record_id,
    ):
        """
        Delete a record by primary key.
        """

        record = (
            self.db.query(model)
            .filter(
                model.id == record_id
            )
            .first()
        )

        if record:

            self.db.delete(record)

            self.db.commit()

        return record

    def save_detection_event(
        self,
        *,
        source_ip,
        destination_ip,
        prediction,
        confidence,
        label,
        confidence_level,
        severity,
        action,
        firewall_status=None,
        reason=None,
    ):
        """
        Store a complete NTCF detection/decision event.

        Transaction:

            ThreatEvent
                +
            DetectionResult
                +
            optional FirewallAction

        All records are committed together.
        """

        try:

            # ---------------------------------------------
            # Threat event
            # ---------------------------------------------

            threat_event = ThreatEvent(
                source_ip=source_ip,
                destination_ip=destination_ip,
                threat_type=prediction,
                confidence=confidence,
                severity=severity,
            )

            self.db.add(threat_event)

            self.db.flush()

            # ---------------------------------------------
            # ML detection result
            # ---------------------------------------------

            detection_result = DetectionResult(
                threat_event_id=threat_event.id,
                prediction=prediction,
                confidence=confidence,
                label=label,
                confidence_level=confidence_level,
            )

            self.db.add(detection_result)

            # ---------------------------------------------
            # Response / firewall action
            # ---------------------------------------------

            firewall_action = None

            if action is not None:

                firewall_action = FirewallAction(
                    threat_event_id=threat_event.id,
                    action=action,
                    status=(
                        firewall_status
                        if firewall_status
                        else "not_executed"
                    ),
                    reason=reason,
                )

                self.db.add(
                    firewall_action
                )

            # ---------------------------------------------
            # Commit complete event
            # ---------------------------------------------

            self.db.commit()

            self.db.refresh(
                threat_event
            )

            self.db.refresh(
                detection_result
            )

            if firewall_action is not None:
                self.db.refresh(
                    firewall_action
                )

            return {
                "threat_event": threat_event,
                "detection_result": detection_result,
                "firewall_action": firewall_action,
            }

        except SQLAlchemyError:

            self.db.rollback()

            raise