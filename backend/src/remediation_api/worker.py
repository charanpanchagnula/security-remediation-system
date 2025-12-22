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
            # Offload blocking SQS poll to a thread to keep main loop (and health checks) responsive
            messages = await asyncio.to_thread(queue_service.receive_messages, max_messages=1)
            
            for msg in messages:
                logger.info(f"Received job {msg.message_id}")
                
                # Process
                start_time = time.time()
                logger.info(f"Starting processing for job {msg.message_id}...")
                await orchestrator.process_scan_job(msg.body)
                duration = time.time() - start_time
                logger.info(f"Processing finished for job {msg.message_id} in {duration:.2f}s")
                
                # Delete (also potentially blocking network call)
                await asyncio.to_thread(queue_service.delete_message, msg.receipt_handle)
                logger.info(f"Job {msg.message_id} completed and deleted from queue.")
                
            if not messages:
                # Heartbeat or idle wait
                await asyncio.sleep(2) # Polling interval for empty queue
                
        except Exception as e:
            logger.error(f"Worker Loop Error: {e}", exc_info=True)
            await asyncio.sleep(2)

if __name__ == "__main__":
    # Ensure config is loaded
    try:
        asyncio.run(run_worker())
    except KeyboardInterrupt:
        logger.info("Worker stopped.")
