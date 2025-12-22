from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
import json
import os
import time
import glob
import uuid
import boto3
from pathlib import Path
from ..config import settings
from ..logger import get_logger

logger = get_logger(__name__)

class QueueMessage:
    def __init__(self, message_id: str, body: Dict[str, Any], receipt_handle: str):
        self.message_id = message_id
        self.body = body
        self.receipt_handle = receipt_handle

class QueueService(ABC):
    @abstractmethod
    def send_message(self, message_body: Dict[str, Any]) -> str:
        pass

    @abstractmethod
    def receive_messages(self, max_messages: int = 1) -> List[QueueMessage]:
        pass

    @abstractmethod
    def delete_message(self, receipt_handle: str):
        pass

class LocalQueueService(QueueService):
    """File-based queue for local development."""
    def __init__(self):
        self.queue_dir = Path(settings.WORK_DIR) / "queue"
        self.queue_dir.mkdir(parents=True, exist_ok=True)

    def send_message(self, message_body: Dict[str, Any]) -> str:
        """
        Writes a message to a JSON file in the queue directory.

        Args:
            message_body (Dict[str, Any]): The message payload.

        Returns:
            str: The unique ID of the created message.
        """
        msg_id = str(uuid.uuid4())
        file_path = self.queue_dir / f"{msg_id}.json"
        with open(file_path, "w") as f:
            json.dump(message_body, f)
        logger.info(f"Queued local message {msg_id}")
        return msg_id

    def receive_messages(self, max_messages: int = 1) -> List[QueueMessage]:
        """
        Reads pending JSON message files from the queue directory.
        Simulates FIFO by sorting by file modification time.

        Args:
            max_messages (int): The maximum number of messages to retrieve.

        Returns:
            List[QueueMessage]: A list of retrieved messages.
        """
        # Simple FIFO-ish: list files, pick oldest
        files = glob.glob(str(self.queue_dir / "*.json"))
        # Sort by creation time (simulated by filename/system)
        files.sort(key=os.path.getmtime)
        
        messages = []
        for fpath in files[:max_messages]:
            try:
                with open(fpath, "r") as f:
                    body = json.load(f)
                msg_id = Path(fpath).stem
                messages.append(QueueMessage(msg_id, body, receipt_handle=fpath))
            except Exception:
                continue
        return messages

    def delete_message(self, receipt_handle: str):
        """
        Deletes the message file (simulating SQS delete).

        Args:
            receipt_handle (str): The file path of the message to delete.
        """
        if os.path.exists(receipt_handle):
            os.remove(receipt_handle)

class SQSQueueService(QueueService):
    def __init__(self):
        self.sqs = boto3.client("sqs", region_name=settings.AWS_REGION)
        self.queue_url = settings.SQS_QUEUE_URL

    def send_message(self, message_body: Dict[str, Any]) -> str:
        """
        Sends a message to the configured AWS SQS queue.

        Args:
            message_body (Dict[str, Any]): The message payload.

        Returns:
            str: The SQS MessageId.
        """
        response = self.sqs.send_message(
            QueueUrl=self.queue_url,
            MessageBody=json.dumps(message_body)
        )

        msg_id = response.get("MessageId")
        logger.info(f"Queued SQS message {msg_id}")
        return msg_id

    def receive_messages(self, max_messages: int = 1) -> List[QueueMessage]:
        """
        Polls the AWS SQS queue for new messages.

        Args:
            max_messages (int): The maximum number of messages to retrieve.

        Returns:
            List[QueueMessage]: A list of retrieved messages.
        """
        response = self.sqs.receive_message(
            QueueUrl=self.queue_url,
            MaxNumberOfMessages=max_messages,
            WaitTimeSeconds=5 # Long polling
        )
        
        if "Messages" not in response:
            return []
            
        messages = []
        for msg in response["Messages"]:
            messages.append(QueueMessage(
                message_id=msg["MessageId"],
                body=json.loads(msg["Body"]),
                receipt_handle=msg["ReceiptHandle"]
            ))
        return messages

    def delete_message(self, receipt_handle: str):
        """
        Deletes a message from the AWS SQS queue using its receipt handle.

        Args:
            receipt_handle (str): The receipt handle provided when receiving the message.
        """
        self.sqs.delete_message(
            QueueUrl=self.queue_url,
            ReceiptHandle=receipt_handle
        )

def get_queue() -> QueueService:
    if settings.APP_ENV == "local" or settings.APP_ENV == "local_mock":
        return LocalQueueService()
    return SQSQueueService()

queue_service = get_queue()
