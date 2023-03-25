from celery import shared_task
from celery.exceptions import MaxRetriesExceededError

from django.core.mail.message import EmailMessage

import logging

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def send_email(self, message):
    logger.info(
        f"Sending email to {message['to_email']}, \
        subject: {message['email_subject']}, \
        Task ID: {self.request.id}"
    )

    try:
        email = EmailMessage(
            subject=message["email_subject"],
            body=message["email_body"],
            to=[message["to_email"]],
        )
        email.send(fail_silently=False)

    except Exception as e:
        try:
            self.retry(exc=e)
            logger.warning(
                f"Retrying to send email to {message['to_email']}, \
                    subject: {message['email_subject']}, \
                    Exception: {e}, \
                    Retries: {self.request.retries}"
            )

        except MaxRetriesExceededError:
            logger.error(
                f"Failed to send email to {message['to_email']}, \
                subject: {message['email_subject']}, \
                Exception: {e}"
            )

    else:
        logger.info(
            f"Email sent successfully to {message['to_email']}, \
            subject: {message['email_subject']}, \
            Task ID: {self.request.id}"
        )
