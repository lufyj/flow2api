"""Durable image generation queue service."""

import asyncio
import json
import shutil
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.config import config
from ..core.logger import debug_logger
from ..core.models import GenerationJob


class ImageGenerationQueueService:
    """Persist non-stream image requests and process them in background workers."""

    def __init__(self, db, generation_handler):
        self.db = db
        self.generation_handler = generation_handler
        self._workers: List[asyncio.Task] = []
        self._stop_event = asyncio.Event()
        self._started = False
        self._worker_count = 0
        self._spool_dir = Path(__file__).parent.parent.parent / "tmp" / "queue_inputs"
        self._spool_dir.mkdir(parents=True, exist_ok=True)

    @property
    def worker_count(self) -> int:
        return self._worker_count

    async def start(self):
        """Start background workers."""
        if self._started:
            return

        active_tokens = await self.db.get_active_tokens()
        configured = int(getattr(config, "image_queue_worker_count", 0) or 0)
        default_workers = max(1, min(len(active_tokens) or 1, 4))
        self._worker_count = configured if configured > 0 else default_workers
        requeued = await self.db.requeue_processing_generation_jobs(task_type="generate_image")
        if requeued > 0:
            debug_logger.log_warning(f"[IMAGE QUEUE] requeued {requeued} interrupted image job(s) on startup")

        self._stop_event.clear()
        self._workers = [
            asyncio.create_task(self._worker_loop(index + 1))
            for index in range(self._worker_count)
        ]
        self._started = True
        debug_logger.log_info(f"[IMAGE QUEUE] started {self._worker_count} worker(s)")

    async def stop(self):
        """Stop background workers."""
        if not self._started:
            return
        self._stop_event.set()
        workers = list(self._workers)
        self._workers.clear()
        for worker in workers:
            worker.cancel()
        for worker in workers:
            try:
                await worker
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                debug_logger.log_error(f"[IMAGE QUEUE] worker stop error: {exc}")
        self._started = False

    async def enqueue(
        self,
        model: str,
        prompt: str,
        images: Optional[List[bytes]] = None,
        base_url_override: Optional[str] = None,
    ) -> GenerationJob:
        """Persist an image request and return the queued job."""
        created_at_ms = int(time.time() * 1000)
        job_id = f"imgq-{created_at_ms}-{uuid.uuid4().hex[:10]}"
        input_assets = await self._spool_inputs(job_id, images or [])
        request_payload = {
            "base_url_override": (base_url_override or "").strip() or None,
            "image_count": len(input_assets),
        }
        request_log_id = await self._create_request_log(
            job_id=job_id,
            model=model,
            prompt=prompt,
            image_count=len(input_assets),
        )
        job = GenerationJob(
            job_id=job_id,
            task_type="generate_image",
            model=model,
            prompt=prompt,
            status="queued",
            progress=0,
            input_assets=input_assets,
            request_payload=request_payload,
            request_log_id=request_log_id,
            max_retries=int(max(0, getattr(config, "image_queue_max_retries", 0) or 0)),
        )
        await self.db.create_generation_job(job)
        debug_logger.log_info(
            f"[IMAGE QUEUE] enqueued job={job_id} model={model} images={len(input_assets)}"
        )
        stored_job = await self.db.get_generation_job(job_id)
        return stored_job or job

    async def get_job(self, job_id: str) -> Optional[GenerationJob]:
        return await self.db.get_generation_job(job_id)

    async def _spool_inputs(self, job_id: str, images: List[bytes]) -> List[Dict[str, Any]]:
        if not images:
            return []
        job_dir = self._spool_dir / job_id
        job_dir.mkdir(parents=True, exist_ok=True)
        assets: List[Dict[str, Any]] = []
        for index, image_bytes in enumerate(images, start=1):
            filename = f"input_{index}.bin"
            file_path = job_dir / filename
            file_path.write_bytes(image_bytes)
            assets.append(
                {
                    "kind": "local_file",
                    "path": str(file_path),
                    "index": index,
                    "size": len(image_bytes),
                }
            )
        return assets

    async def _worker_loop(self, worker_number: int):
        worker_id = f"image-worker-{worker_number}"
        while not self._stop_event.is_set():
            try:
                job = await self.db.claim_next_generation_job("generate_image", worker_id)
                if not job:
                    await asyncio.sleep(0.5)
                    continue
                await self._process_job(job, worker_id)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                debug_logger.log_error(f"[IMAGE QUEUE] {worker_id} loop error: {exc}")
                await asyncio.sleep(1.0)

    async def _process_job(self, job: GenerationJob, worker_id: str):
        debug_logger.log_info(f"[IMAGE QUEUE] {worker_id} processing job={job.job_id}")
        image_bytes = await self._load_job_images(job)
        request_payload = job.request_payload or {}
        base_url_override = (request_payload.get("base_url_override") or "").strip() or None
        final_result: Optional[str] = None
        final_payload: Dict[str, Any] = {}
        error_message: Optional[str] = None
        should_cleanup_inputs = False

        try:
            await self._update_request_log(
                job,
                status_text="processing",
                progress=max(5, int(job.progress or 0)),
                response_payload={
                    "status": "processing",
                    "job_id": job.job_id,
                    "worker_id": worker_id,
                },
            )
            async for chunk in self.generation_handler.handle_generation(
                model=job.model,
                prompt=job.prompt,
                images=image_bytes if image_bytes else None,
                stream=False,
                base_url_override=base_url_override,
                existing_request_log_id=job.request_log_id,
            ):
                final_result = chunk

            if not final_result:
                raise RuntimeError("generation handler returned no response")

            final_payload = self._parse_handler_payload(final_result)
            if "error" in final_payload:
                error_message = self._extract_error_message(final_payload)
                await self.db.update_generation_job(
                    job.job_id,
                    status="failed",
                    progress=100,
                    response_payload=final_payload,
                    error_message=error_message,
                    completed_at=time.time(),
                )
                should_cleanup_inputs = True
                await self._update_request_log(
                    job,
                    status_text="failed",
                    progress=100,
                    response_payload=final_payload,
                    status_code=self._extract_status_code(final_payload, default=400),
                )
                debug_logger.log_warning(
                    f"[IMAGE QUEUE] job={job.job_id} failed: {error_message}"
                )
            else:
                await self.db.update_generation_job(
                    job.job_id,
                    status="completed",
                    progress=100,
                    response_payload=final_payload,
                    completed_at=time.time(),
                )
                should_cleanup_inputs = True
                await self._update_request_log(
                    job,
                    status_text="completed",
                    progress=100,
                    response_payload=final_payload,
                    status_code=self._extract_status_code(final_payload, default=200),
                )
                debug_logger.log_info(f"[IMAGE QUEUE] job={job.job_id} completed")
        except asyncio.CancelledError:
            debug_logger.log_warning(
                f"[IMAGE QUEUE] job={job.job_id} cancelled; preserving spooled inputs for resume"
            )
            raise
        except Exception as exc:
            error_message = self._normalize_error_message(exc)
            await self.db.update_generation_job(
                job.job_id,
                status="failed",
                progress=100,
                error_message=error_message,
                completed_at=time.time(),
            )
            should_cleanup_inputs = True
            await self._update_request_log(
                job,
                status_text="failed",
                progress=100,
                response_payload={"error": {"message": error_message}},
                status_code=500,
            )
            debug_logger.log_error(f"[IMAGE QUEUE] job={job.job_id} crashed: {error_message}")
        finally:
            if should_cleanup_inputs:
                await self._cleanup_job_inputs(job)

    async def _load_job_images(self, job: GenerationJob) -> List[bytes]:
        assets = list(job.input_assets or [])
        images: List[bytes] = []
        for asset in assets:
            if not isinstance(asset, dict):
                continue
            path = (asset.get("path") or "").strip()
            if not path:
                continue
            file_path = Path(path)
            if not file_path.exists():
                raise FileNotFoundError(f"Queued input image missing: {file_path}")
            images.append(file_path.read_bytes())
        return images

    async def _cleanup_job_inputs(self, job: GenerationJob):
        job_dir = self._spool_dir / job.job_id
        if not job_dir.exists():
            return
        try:
            shutil.rmtree(job_dir, ignore_errors=True)
        except Exception as exc:
            debug_logger.log_warning(f"[IMAGE QUEUE] cleanup failed for {job.job_id}: {exc}")

    def _parse_handler_payload(self, raw: str) -> Dict[str, Any]:
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {"result": parsed}
        except Exception:
            return {"result": raw}

    def _extract_error_message(self, payload: Dict[str, Any]) -> str:
        error = payload.get("error")
        if isinstance(error, dict):
            message = str(error.get("message") or "").strip()
            if message:
                return message
        if isinstance(error, str) and error.strip():
            return error.strip()
        return "Generation failed"

    def _normalize_error_message(self, error: Any) -> str:
        text = str(error or "").strip()
        if not text and isinstance(error, BaseException):
            text = type(error).__name__
        return text or "Unknown queue worker error"

    async def _create_request_log(
        self,
        job_id: str,
        model: str,
        prompt: str,
        image_count: int,
    ) -> Optional[int]:
        prompt_for_log = prompt if len(prompt) <= 2000 else f"{prompt[:2000]}...(truncated)"
        request_payload = {
            "job_id": job_id,
            "model": model,
            "prompt": prompt_for_log,
            "has_images": image_count > 0,
            "queued_via": "image_queue",
        }
        response_payload = {
            "status": "queued",
            "job_id": job_id,
            "image_count": image_count,
        }
        try:
            return await self.generation_handler._log_request(
                token_id=None,
                operation="generate_image",
                request_data=request_payload,
                response_data=response_payload,
                status_code=102,
                duration=0.0,
                status_text="queued",
                progress=0,
            )
        except Exception as exc:
            debug_logger.log_warning(f"[IMAGE QUEUE] failed to create request log for {job_id}: {exc}")
            return None

    async def _update_request_log(
        self,
        job: GenerationJob,
        *,
        status_text: str,
        progress: int,
        response_payload: Dict[str, Any],
        status_code: Optional[int] = None,
    ):
        if not job.request_log_id:
            return

        safe_status_code = int(status_code if status_code is not None else (200 if status_text == "completed" else 102))
        try:
            await self.db.update_request_log(
                job.request_log_id,
                status_text=status_text,
                progress=max(0, min(100, int(progress))),
                status_code=safe_status_code,
                response_body=json.dumps(response_payload, ensure_ascii=False),
            )
        except Exception as exc:
            debug_logger.log_warning(f"[IMAGE QUEUE] failed to update request log for {job.job_id}: {exc}")

    def _extract_status_code(self, payload: Dict[str, Any], default: int) -> int:
        error = payload.get("error")
        if isinstance(error, dict):
            value = error.get("status_code")
            if isinstance(value, int):
                return value
            if isinstance(value, str) and value.isdigit():
                return int(value)
        return int(default)
