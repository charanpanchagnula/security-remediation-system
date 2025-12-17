import asyncio
import time
from .agents.orchestrator import orchestrator
from .services.queue import queue_service
from .logger import get_logger

logger = get_logger(__name__)

async def run_worker():
    logger.info("Worker started. Polling queue...")
    while True:
        try:
            messages = queue_service.receive_messages(max_messages=1)
            for msg in messages:
                logger.info(f"Received job {msg.message_id}")
                
                # Process
                await orchestrator.process_scan_job(msg.body)
                
                # Delete
                queue_service.delete_message(msg.receipt_handle)
                logger.info(f"Job {msg.message_id} completed and deleted.")
                
            if not messages:
                await asyncio.sleep(2) # Polling interval
                
        except Exception as e:
            logger.error(f"Worker Loop Error: {e}", exc_info=True)
            await asyncio.sleep(2)

if __name__ == "__main__":
    # Ensure config is loaded
    try:
        asyncio.run(run_worker())
    except KeyboardInterrupt:
        logger.info("Worker stopped.")
