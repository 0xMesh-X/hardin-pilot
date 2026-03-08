import asyncio
import os
import secrets
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import BackgroundTasks, Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import pyhardin.config
from pyhardin.analyzer import analyze_service, build_prompt
from pyhardin.cli import (
    console,
    execute_pending_remediation,
    execute_service_remediation,
)
from pyhardin.config import (
    get_api_base,
    get_api_key,
    get_model,
    get_output_dir,  # Added
    get_provider,
    set_api_key,
    set_model,
    set_provider,
)
from pyhardin.exceptions import APIRateLimitError  # Added
from pyhardin.scanner import run_full_scan
from pyhardin.state import (
    AnalysisResult,
    ScanState,
    clear_state,
    delete_state,
    load_all_states,
    load_latest_state,
    save_state,
)

pyhardin.config.CURRENT_CONTEXT = "web"

# We define the Jinja templates directory relative to this file
BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

security = HTTPBasic()


def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = secrets.compare_digest(
        credentials.username.encode("utf8"),
        os.environ.get("PYHARDIN_WEB_USER", "admin").encode("utf8")
    )
    correct_password = secrets.compare_digest(
        credentials.password.encode("utf8"),
        os.environ.get("PYHARDIN_WEB_PASS", "admin").encode("utf8")
    )
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


app = FastAPI(title="Pyhardin Dashboard", dependencies=[Depends(verify_credentials)])
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

# Global variables to track background scan progress
_scan_state: ScanState | None = None
_scan_task_running = False  # Renamed from _scan_in_progress
_scan_progress_msg = ""
_scan_completed_count = 0
_scan_total_count = 0


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Render the main index page."""
    global _scan_state
    # Load state from disk just in case we have a previous run
    states = load_all_states()

    # Check if a scan is currently running in background
    scan_in_progress = _scan_task_running and _scan_state and not _scan_state.is_complete

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "has_api_key": bool(get_api_key()),
            "current_provider": get_provider(),
            "current_model": get_model(),
            "current_api_key": get_api_key(),
            "current_api_base": get_api_base(),
            "scan_in_progress": scan_in_progress,
            "states": states,
        },
    )


@app.post("/clear-state")
def clear_state_endpoint(_auth: bool = Depends(verify_credentials)) -> HTMLResponse:
    global _scan_state, _scan_task_running
    clear_state()
    _scan_state = None
    _scan_task_running = False
    return HTMLResponse(
        '<div class="text-center text-gray-500 py-10 border-2 border-dashed '
        'border-gray-300 rounded-lg">\n'
        '    <p class="mb-2 text-lg">No active scan results.</p>\n'
        '    <p class="text-sm">Click the button above to start auditing your system.</p>\n'
        '</div>'
    )


@app.delete("/scan/{scan_id}")
def delete_scan_endpoint(scan_id: str, _auth: bool = Depends(verify_credentials)) -> HTMLResponse:
    if delete_state(scan_id):
        return HTMLResponse("")
    raise HTTPException(status_code=404, detail="Scan not found")


@app.post("/settings", response_class=HTMLResponse)
async def update_settings(
        request: Request,
        api_key: str = Form(""),
        provider: str = Form(""),
        model: str = Form(""),
        api_base: str = Form("")
):
    """Update API settings from the web GUI."""
    if api_key:
        set_api_key(api_key.strip())
    if provider in ["gemini", "openai"]:
        set_provider(provider)
    if model:
        set_model(model.strip())
    if api_base:
        set_api_base(api_base.strip())

    btn_disabled = "disabled" if _scan_task_running else ""
    btn_class = (
        "bg-gray-400 text-white px-6 py-2 rounded-lg font-semibold cursor-not-allowed"
        if _scan_task_running else
        "bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded-lg font-semibold "
        "transition-colors shadow-sm"
    )

    return HTMLResponse(
        '<div class="bg-green-100 border-l-4 border-green-500 '
        'text-green-700 p-4 mb-6" role="alert">'
        '<p class="font-bold">Settings Updated</p>'
        '<p>Your configuration has been saved.</p>'
        '</div>'
        f'<button id="run-scan-btn" hx-swap-oob="true" hx-post="/scan" '
        f'hx-target="#scan-status" {btn_disabled} class="{btn_class}">'
        'Run Security Scan'
        '</button>'
    )


@app.get("/download-pdf", response_class=FileResponse)
async def download_pdf(scan_id: str = None):
    """Download the generated PDF report for a specific scan."""
    target_state = None
    if scan_id:
        states = load_all_states()
        target_state = next((s for s in states if s.scan_id == scan_id), None)
    else:
        target_state = load_latest_state()

    if target_state:
        _generate_scan_pdf(target_state)

    output_dir = get_output_dir()
    if not output_dir.exists():
        return HTMLResponse("No reports directory found.", status_code=404)

    if scan_id:
        pdf_path = output_dir / f"pyhardin_report_{scan_id}.pdf"
        if pdf_path.exists():
            return FileResponse(
                path=pdf_path,
                filename=pdf_path.name,
                media_type="application/pdf"
            )
        return HTMLResponse(f"No PDF reports available for scan {scan_id} (ensure at least one service completed).",
                            status_code=404)

    pdfs = list(output_dir.glob("pyhardin_report_*.pdf"))
    if not pdfs:
        return HTMLResponse("No PDF reports available (at least one service must be completely analyzed).",
                            status_code=404)

    # Sort by modification time to get the latest
    latest_pdf = max(pdfs, key=lambda p: p.stat().st_mtime)

    return FileResponse(
        path=latest_pdf,
        filename=latest_pdf.name,
        media_type="application/pdf"
    )


@app.post("/scan", response_class=HTMLResponse)
async def trigger_scan(
        request: Request,
        background_tasks: BackgroundTasks,
        api_key: str = Form(""),
        provider: str = Form(""),
        model: str = Form(""),
        api_base: str = Form(""),
):
    """Trigger a background scan via HTMX."""
    global _scan_task_running

    if api_key:
        set_api_key(api_key.strip())
    if provider in ["gemini", "openai"]:
        set_provider(provider)
    if model:
        set_model(model.strip())
    if api_base:
        set_api_base(api_base.strip())

    if _scan_task_running:
        return templates.TemplateResponse(
            "partials/status.html",
            {"request": request, "msg": "Scan already in progress...", "is_done": False}
        )

    if not get_api_key():
        return templates.TemplateResponse(
            "partials/status.html",
            {"request": request, "msg": "Error: Configure API key first via CLI.", "is_error": True}
        )

    _scan_task_running = True
    background_tasks.add_task(_run_background_scan)

    return templates.TemplateResponse(
        "partials/status.html",
        {"request": request, "msg": "Scan started...", "is_done": False}
    )


@app.get("/status", response_class=HTMLResponse)
async def get_status(request: Request):
    """Polling endpoint for HTMX to fetch current status."""
    global _scan_task_running, _scan_progress_msg, _scan_state

    if not _scan_task_running:
        # Upon completion or generic pause (e.g. rate limit), tell HTMX to fully reload the page
        # so the standard index.html loop organically reconstructs all tables and states accurately.
        return HTMLResponse(
            '<div class="bg-blue-100 border-l-4 border-blue-500 p-4 mb-6">\n'
            '    <div class="flex items-center">\n'
            '        <strong class="text-blue-700">Scan pipeline finished or paused. '
            'Reloading dashboard...</strong>\n'
            '    </div>\n'
            '</div>\n',
            headers={"HX-Refresh": "true"}
        )

    # Ongoing scan.
    pct = 0
    if _scan_total_count > 0:
        pct = int((_scan_completed_count / _scan_total_count) * 100)

    html = (
        f'<div id="scan-status" hx-get="/status" hx-trigger="every 1s" hx-swap="outerHTML" '
        f'class="bg-blue-50 border-l-4 border-blue-500 p-4">\n'
        f'    <div class="flex items-center mb-2">\n'
        f'        <svg class="animate-spin -ml-1 mr-3 h-5 w-5 text-blue-500" '
        f'xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">\n'
        f'            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" '
        f'stroke-width="4"></circle>\n'
        f'            <path class="opacity-75" fill="currentColor" '
        f'd="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 '
        f'3.042 1.135 5.824 3 7.938l3-2.647z"></path>\n'
        f'        </svg>\n'
        f'        <strong class="text-blue-700">{_scan_progress_msg}</strong>\n'
        f'    </div>\n'
        f'    <div class="w-full bg-gray-200 rounded-full h-2.5 dark:bg-gray-700">\n'
        f'        <div class="bg-blue-600 h-2.5 rounded-full" style="width: {pct}%"></div>\n'
        f'    </div>\n'
        f'    <div class="mt-2 text-sm text-gray-500 font-mono">\n'
        f'        Analyzed <strong>{_scan_completed_count}</strong> of '
        f'<strong>{_scan_total_count}</strong> system targets\n'
        f'    </div>\n'
        f'</div>\n'
    )
    return HTMLResponse(html)


async def _run_background_scan():
    """Execute the full scan logic in the background (Prompt Generation Phase)."""
    global _scan_task_running, _scan_state, _scan_progress_msg
    global _scan_completed_count, _scan_total_count

    try:
        _scan_progress_msg = "Discovering services..."
        console.log(f"[bold cyan]GUI initiated scan:[/bold cyan] {_scan_progress_msg}")
        services = run_full_scan()

        _scan_total_count = len(services)
        _scan_completed_count = 0

        state = ScanState(
            scan_id=str(uuid.uuid4())[:8],
            scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_services=len(services),
            is_complete=False
        )
        _scan_state = state

        for svc in services:
            _scan_progress_msg = f"Building prompt for {svc.service_name}..."
            console.log(f"Generating prompt for [cyan]{svc.service_name}[/cyan]...")

            try:
                # Strictly generate prompt, do not hit LLM
                prompt_str = build_prompt(svc)
                new_result = AnalysisResult(
                    service_name=svc.service_name,
                    prompt=prompt_str,
                    provider=get_provider(),
                    model=get_model(),
                    temperature=0.1,
                    max_tokens=16384 if get_provider() == "gemini" else 4096,
                    status="pending"
                )
                state.results.append(new_result)
                _scan_completed_count += 1
                save_state(state)

            except Exception as e:
                failed_result = AnalysisResult(
                    service_name=svc.service_name,
                    findings=f"Prompt generation failed: {e}",
                    status="failed"
                )
                state.completed_services.append(svc.service_name)
                state.results.append(failed_result)
                console.log(f"[red]✗[/red] Failed to generate {svc.service_name}: {e}")

        save_state(state)

    except Exception as e:
        console.log(f"[red]Fatal error in background prompt generation: {e}[/red]")
    finally:
        _scan_task_running = False


def _generate_scan_pdf(latest: ScanState):
    """Generate and merge PDFs for a completed scan state."""
    try:
        import tempfile
        from pathlib import Path
        from pyhardin.reporter import generate_service_pdf, merge_pdfs

        temp_dir = Path(tempfile.mkdtemp())
        temp_pdfs = []
        for r in latest.results:
            if r.status in ("complete", "applied"):
                pdf = generate_service_pdf(r, temp_dir)
                if pdf and pdf.exists():
                    temp_pdfs.append(pdf)

        if temp_pdfs:
            output_dir = get_output_dir()
            output_dir.mkdir(parents=True, exist_ok=True)
            final_pdf = output_dir / f"pyhardin_report_{latest.scan_id}.pdf"
            merge_pdfs(temp_pdfs, final_pdf)
            console.log(f"[bold green]Report saved to:[/bold green] {final_pdf}")
    except Exception as e:
        console.log(f"[red]Error generating PDF report: {e}[/red]")


@app.post("/analyze-all", response_class=HTMLResponse)
async def trigger_analyze_all(
        request: Request,
        background_tasks: BackgroundTasks,
        api_key: str = Form(""),
        provider: str = Form(""),
        model: str = Form("")
):
    """Trigger background LLM execution for all pending prompts."""
    global _scan_task_running

    if api_key:
        set_api_key(api_key.strip())
    if provider in ["gemini", "openai"]:
        set_provider(provider)
    if model:
        set_model(model.strip())

    if _scan_task_running:
        return templates.TemplateResponse(
            "partials/status.html",
            {"request": request, "msg": "Task already in progress...", "is_done": False}
        )

    _scan_task_running = True
    background_tasks.add_task(_run_background_llm)

    return templates.TemplateResponse(
        "partials/status.html",
        {"request": request, "msg": "Starting AI Execution...", "is_done": False}
    )


async def _run_background_llm():
    """Execute the AI inference on previously generated pending prompts."""
    global _scan_task_running, _scan_state, _scan_progress_msg
    global _scan_completed_count, _scan_total_count

    try:
        latest = load_latest_state()
        if not latest:
            return

        pending = [r for r in latest.results if r.status == "pending"]
        _scan_total_count = len(pending)
        _scan_completed_count = 0

        _scan_progress_msg = "Starting AI execution loops..."

        idx = 0
        while idx < len(pending):
            result_obj = pending[idx]
            _scan_progress_msg = f"Analyzing {result_obj.service_name}..."
            console.log(f"Started analysis on [cyan]{result_obj.service_name}[/cyan]...")

            if idx > 0:
                await asyncio.sleep(2)

            try:
                # Send the entire AnalysisResult containing the prompt
                final_result = await asyncio.to_thread(analyze_service, result_obj)
                final_result.status = "complete"

                latest.completed_services.append(result_obj.service_name)

                # Replace the pending object with the completed object
                update_idx = next(
                    i for i, r in enumerate(latest.results)
                    if r.service_name == result_obj.service_name
                )
                latest.results[update_idx] = final_result

                console.log(f"[green]✓[/green] Successfully analyzed {result_obj.service_name}")

                idx += 1
                _scan_completed_count += 1
                save_state(latest)

            except APIRateLimitError as e:
                msg = f"API Rate Limit Hit! {e}"
                _scan_progress_msg = msg
                console.log(f"[yellow]⚠ {msg} State saved. Re-run to resume.[/yellow]")
                save_state(latest)
                break

            except Exception as e:
                failed_result = AnalysisResult(
                    service_name=result_obj.service_name,
                    findings=f"Analysis failed: {e}",
                    status="failed",
                    prompt=result_obj.prompt
                )
                latest.completed_services.append(result_obj.service_name)

                update_idx = next(
                    i for i, r in enumerate(latest.results)
                    if r.service_name == result_obj.service_name
                )
                latest.results[update_idx] = failed_result

                console.log(f"[red]✗[/red] Failed to analyze {result_obj.service_name}: {e}")

                idx += 1
                _scan_completed_count += 1
                save_state(latest)

        # Check completion
        all_done = all(r.status != "pending" for r in latest.results)
        if all_done and latest.total_services == len(latest.results):
            latest.is_complete = True
            save_state(latest)
            _generate_scan_pdf(latest)

    except Exception as e:
        console.log(f"[red]Fatal error in background LLM task: {e}[/red]")
    finally:
        _scan_task_running = False
        if latest and latest.is_complete:
            console.log("[bold green]GUI scan pipeline completed![/bold green]")
        else:
            console.log("[yellow]GUI scan pipeline paused.[/yellow]")


@app.post("/analyze-service/{service_name}", response_class=HTMLResponse)
async def trigger_analyze_service(
        service_name: str,
        request: Request,
        api_key: str = Form(""),
        provider: str = Form(""),
        model: str = Form("")
):
    """Trigger the LLM strictly for one specific pending service via HTMX from the UI."""
    global _scan_task_running

    if api_key:
        set_api_key(api_key.strip())
    if provider in ["gemini", "openai"]:
        set_provider(provider)
    if model:
        set_model(model.strip())

    if _scan_task_running:
        return HTMLResponse(
            f'<div class="text-sm text-yellow-600 bg-yellow-50 p-2 rounded '
            f'mb-2 border border-yellow-200">\n'
            f'  Cannot analyze {service_name} while a scan is already running.\n'
            f'</div>',
            status_code=409
        )

    # In a full-blown production environment, this would spawn an async background task
    # and return a loading skeleton. Given this blocks the UI for only 3-5 seconds locally,
    # doing it synchronously in the threadpool before returning the result fragment is acceptable.
    latest = load_latest_state()
    if not latest:
        return HTMLResponse("No state available to analyze.", status_code=404)

    target_idx = next(
        (i for i, r in enumerate(latest.results) if r.service_name == service_name), None
    )
    if target_idx is None:
        return HTMLResponse(f"Service {service_name} not found in state.", status_code=404)

    result_obj = latest.results[target_idx]
    if result_obj.status != "pending":
        return HTMLResponse(f"Service {service_name} is already processed.", status_code=400)

    try:
        final_result = await asyncio.to_thread(analyze_service, result_obj)
        final_result.status = "complete"

        latest.completed_services.append(service_name)
        latest.results[target_idx] = final_result

        all_done = all(r.status != "pending" for r in latest.results)
        if all_done and latest.total_services == len(latest.results):
            latest.is_complete = True
            save_state(latest)
            _generate_scan_pdf(latest)
        else:
            save_state(latest)
        console.log(f"[green]✓[/green] Successfully analyzed {service_name} individually.")

        # Trigger a full page refresh via header so the HTMX handles collapsing correctly.
        return HTMLResponse(
            "",
            headers={"HX-Refresh": "true"}
        )

    except APIRateLimitError:
        return HTMLResponse(
            f'<div class="text-sm text-red-600 bg-red-50 p-2 rounded">\n'
            f'  API Rate Limit Hit analyzing {service_name}. Please try again later.\n'
            f'</div>',
            status_code=429
        )
    except Exception as e:
        failed_result = AnalysisResult(
            service_name=service_name,
            findings=f"Individual Analysis failed: {e}",
            status="failed",
            prompt=result_obj.prompt
        )
        latest.completed_services.append(service_name)
        latest.results[target_idx] = failed_result
        save_state(latest)

        return HTMLResponse(
            f'<div class="text-sm text-red-600 bg-red-50 p-2 rounded">\n'
            f'  Error: {e}\n'
            f'</div>',
            status_code=500
        )


@app.post("/apply", response_class=HTMLResponse)
async def apply_remediation(request: Request):
    """Executes the pending remediation bash script generated by the last scan."""
    try:
        # Run the exact same CLI command function to apply fixes.
        # We run it synchronously by offloading it to a thread so it doesn't block the async loop.
        await asyncio.to_thread(execute_pending_remediation)

        # Execution success (or handled correctly by the function).
        return HTMLResponse(
            '<div class="mt-4 p-4 bg-green-100 border border-green-400 text-green-700 rounded">\n'
            '    <strong>✓ Fixes Applied Successfully!</strong> The remediation script '
            'was executed and marked in state.\n'
            '</div>'
        )
    except Exception as e:
        return HTMLResponse(
            f'<div class="mt-4 p-4 bg-red-100 border border-red-400 text-red-700 rounded">\n'
            f'    <strong>Error applying fixes:</strong> {e}\n'
            f'</div>'
        )


@app.post("/apply-service/{service_name}", response_class=HTMLResponse)
async def apply_service_remediation(service_name: str, request: Request):
    """Executes remediation only for a specific service."""
    try:
        # Offload synchronous subprocess execution to a thread.
        await asyncio.to_thread(execute_service_remediation, service_name)

        # Return a success message or trigger a refresh.
        return HTMLResponse(
            "",
            headers={"HX-Refresh": "true"}
        )
    except Exception as e:
        return HTMLResponse(
            f'<div class="text-sm text-red-600 bg-red-50 p-2 rounded mt-2 border border-red-200">\n'
            f'  <strong>Error applying fix for {service_name}:</strong> {e}\n'
            f'</div>'
        )
