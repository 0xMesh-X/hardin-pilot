import argparse
import subprocess
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.prompt import IntPrompt, Prompt
from rich.table import Table

from pyhardin.analyzer import analyze_service, build_prompt
from pyhardin.config import (
    get_model,
    get_output_dir,
    get_provider,
    reset_config,
    set_api_base,
    set_api_key,
    set_model,
    set_provider,
)
from pyhardin.exceptions import AnalyzerError, APIRateLimitError, PyhardinError
from pyhardin.reporter import (
    build_remediation_script,
    cleanup_temp_pdfs,
    generate_service_pdf,
    merge_pdfs,
)
from pyhardin.scanner import ServiceConfig, list_all_services, run_full_scan
from pyhardin.state import (
    AnalysisResult,
    ScanState,
    clear_state,
    delete_state,
    is_service_completed,
    load_all_states,
    load_latest_state,
    mark_service_complete,
    save_state,
)

console = Console()

BANNER = """
[bold red]
  ██╗  ██╗ █████╗ ██████╗ ██████╗ ██╗███╗   ██╗
  ██║  ██║██╔══██╗██╔══██╗██╔══██╗██║████╗  ██║
  ███████║███████║██████╔╝██║  ██║██║██╔██╗ ██║
  ██╔══██║██╔══██║██╔══██╗██║  ██║██║██║╚██╗██║
  ██║  ██║██║  ██║██║  ██║██████╔╝██║██║ ╚████║
  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═══╝
[/bold red]
[dim]  AI-Powered Linux Security Auditor v2.0.0[/dim]
"""


def _prompt_api_key() -> str:
    console.print(Panel(
        "[yellow]Welcome to Pyhardin - First-Time Setup[/yellow]\n\n"
        "Pyhardin requires an AI provider to perform security analysis.\n"
        "Please select your preferred AI provider below:",
        title="[bold]AI Configuration[/bold]",
        border_style="yellow",
    ))

    console.print("  [1] [cyan]Google Gemini[/cyan] (Default, Free Tier Available)")
    console.print("  [2] [white]OpenAI[/white] (ChatGPT)")
    console.print("  [3] [green]Local / Custom API[/green] (LMStudio, Ollama, DeepSeek, Groq, etc)")

    choice = IntPrompt.ask("\n[bold]Select an option[/bold]", choices=["1", "2", "3"], default=1)

    if choice == 1:
        provider = "gemini"

        console.print("\n[bold]Select a Gemini Model:[/bold]")
        console.print("  [1] [cyan]gemini-3.1-pro[/cyan] (Future-proof, most advanced)")
        console.print("  [2] [cyan]gemini-3.1-flash[/cyan] (Future-proof, fast)")
        console.print("  [3] [white]gemini-2.5-pro[/white] (High intelligence)")
        console.print("  [4] [white]gemini-2.5-flash[/white] (Default, very fast)")
        console.print("  [5] [green]gemini-2.0-pro-exp[/green] (Experimental Pro)")
        console.print("  [6] [green]gemini-2.0-flash[/green] (Standard Flash)")
        console.print("  [7] [green]gemini-2.0-flash-thinking-exp[/green] (Advanced reasoning)")
        console.print("  [8] [yellow]gemini-1.5-pro[/yellow] (Legacy Pro)")
        console.print("  [9] [yellow]gemini-1.5-flash[/yellow] (Legacy Flash)")

        model_choice = IntPrompt.ask(
            "\n[bold]Enter model number[/bold]", choices=[str(i) for i in range(1, 10)], default=4
        )
        mod_map = {
            1: "gemini-3.1-pro",
            2: "gemini-3.1-flash",
            3: "gemini-2.5-pro",
            4: "gemini-2.5-flash",
            5: "gemini-2.0-pro-exp",
            6: "gemini-2.0-flash",
            7: "gemini-2.0-flash-thinking-exp",
            8: "gemini-1.5-pro",
            9: "gemini-1.5-flash",
        }
        model = mod_map.get(model_choice, "gemini-2.5-flash")

        api_base = ""
        url_hint = "https://aistudio.google.com/apikey"

    elif choice == 2:
        provider = "openai"

        console.print("\n[bold]Select an OpenAI Model:[/bold]")
        console.print("  [1] [cyan]gpt-5[/cyan] (Future-proof, most advanced)")
        console.print("  [2] [cyan]gpt-4.5-preview[/cyan] (Experimental advanced)")
        console.print("  [3] [white]gpt-4o[/white] (Default)")
        console.print("  [4] [white]gpt-4o-mini[/cyan] (Fast, cheap)")
        console.print("  [5] [green]o3-mini[/green] (Advanced fast reasoning)")
        console.print("  [6] [green]o1[/green] (Heavy reasoning)")
        console.print("  [7] [green]o1-mini[/green] (Fast reasoning)")
        console.print("  [8] [yellow]gpt-4-turbo[/yellow] (Legacy Turbo)")
        console.print("  [9] [yellow]gpt-4[/yellow] (Legacy GPT-4)")

        model_choice = IntPrompt.ask(
            "\n[bold]Enter model number[/bold]", choices=[str(i) for i in range(1, 10)], default=3
        )
        mod_map = {
            1: "gpt-5",
            2: "gpt-4.5-preview",
            3: "gpt-4o",
            4: "gpt-4o-mini",
            5: "o3-mini",
            6: "o1",
            7: "o1-mini",
            8: "gpt-4-turbo",
            9: "gpt-4"
        }
        model = mod_map.get(model_choice, "gpt-4o")

        api_base = ""
        url_hint = "https://platform.openai.com/api-keys"

    else:
        provider = "openai"  # Custom endpoints use the OpenAI python library
        console.print("\n[dim]For Local AI (like LMStudio), the base URL is usually http://localhost:1234/v1[/dim]")
        api_base = console.input("[bold cyan]Enter Custom API Base URL:[/bold cyan] ").strip()
        model = console.input("[bold cyan]Enter model name:[/bold cyan] ").strip() or "local-model"
        url_hint = "your local/custom provider dashboard (or set to 'local' for offline LLMs)"

    console.print(f"\n[dim]Get your API key at: {url_hint}[/dim]")
    key = console.input("[bold cyan]Enter your API Key:[/bold cyan] ").strip()

    if not key:
        if choice == 3 and "localhost" in api_base:
            console.print("[dim]No key provided. Defaulting to 'local' for local endpoint.[/dim]")
            key = "local"
        else:
            console.print("[red]No key provided. Exiting.[/red]")
            sys.exit(1)

    set_provider(provider)
    set_model(model)
    set_api_base(api_base)
    set_api_key(key)

    console.print("\n[green]✓ Configuration saved. Pyhardin is ready![/green]\n")
    return key


def _show_services(services: list[ServiceConfig]) -> None:
    table = Table(title="Discovered Services", border_style="bright_black")
    table.add_column("Service", style="cyan", no_wrap=True)
    table.add_column("Files", justify="right", style="green")
    table.add_column("Total Size", justify="right", style="yellow")

    for svc in services:
        total_size = sum(len(c) for c in svc.contents.values())
        size_str = f"{total_size / 1024:.1f} KB" if total_size > 1024 else f"{total_size} B"
        table.add_row(svc.service_name, str(len(svc.files)), size_str)

    console.print(table)


def execute_pending_remediation() -> None:
    """Executes the saved bash script and marks all services as applied."""
    script_path = get_output_dir().parent / ".pyhardin" / "last_remediation.sh"

    # We also want to support marking the state as applied even if used via the script path
    state = load_latest_state()

    if not script_path.exists():
        console.print(
            "[yellow]No pending remediation script found. Please run a full scan first.[/yellow]"
        )
        return

    console.print(Panel(
        f"[bold yellow]Executing pending auto-remediation from previous scan...[/bold yellow]\n\n"
        f"[dim]Reading: {script_path}[/dim]",
        title="[bold red]⚡ Applying All Fixes[/bold red]",
        border_style="red",
        padding=(1, 2),
    ))

    try:
        subprocess.run(str(script_path), shell=True, check=True, executable='/bin/bash')
        console.print("\n[green bold]✓ Auto-remediation executed successfully![/green bold]")

        # Success, delete the script so we don't accidentally run it again
        script_path.unlink()

        if state:
            for r in state.results:
                if r.remediation_commands:
                    r.remediation_applied = True
            save_state(state)

    except subprocess.CalledProcessError as e:
        console.print(
            f"\n[red bold]✗ Remediation command failed with exit code {e.returncode}[/red bold]"
        )


def execute_service_remediation(service_name: str) -> None:
    """Executes remediation only for a specific service."""
    state = load_latest_state()
    if not state:
        console.print("[red]No scan state found. Run a scan first.[/red]")
        return

    result = next((r for r in state.results if r.service_name.lower() == service_name.lower()), None)
    if not result:
        console.print(f"[red]Service '{service_name}' not found in the latest scan.[/red]")
        return

    if not result.remediation_commands:
        console.print(f"[yellow]No remediation commands available for {service_name}.[/yellow]")
        return

    if result.remediation_applied:
        console.print(f"[yellow]Remediation already applied for {service_name}.[/yellow]")
        return

    console.print(Panel(
        f"[bold yellow]Executing auto-remediation for {service_name}...[/bold yellow]\n\n"
        f"[dim]Commands: {', '.join(result.remediation_commands)}[/dim]",
        title=f"[bold red]⚡ Applying {service_name} Fixes[/bold red]",
        border_style="red",
        padding=(1, 2),
    ))

    try:
        for cmd in result.remediation_commands:
            subprocess.run(cmd, shell=True, check=True, executable='/bin/bash')

        console.print(f"\n[green bold]✓ {service_name} remediation executed successfully![/green bold]")
        result.remediation_applied = True
        save_state(state)
    except subprocess.CalledProcessError as e:
        console.print(
            f"\n[red bold]✗ Remediation failed for {service_name} with exit code {e.returncode}[/red bold]"
        )


def _run_scan(extra_paths: list[str] | None = None, resume_id: str | None = None, resume: bool = True) -> None:
    console.print(BANNER)

    services = run_full_scan(extra_paths)
    if not services:
        console.print("[yellow]No supported configurations found to scan.[/yellow]")
        return

    _show_services(services)

    state: ScanState | None = None
    if resume_id:
        states = load_all_states()
        state = next((s for s in states if s.scan_id.startswith(resume_id)), None)
        if not state:
            console.print(f"[red]Scan ID '{resume_id}' not found. Cannot resume.[/red]")
            return
    elif resume:
        state = load_latest_state()

    if state and not state.is_complete:
        console.print(
            f"[yellow]Resuming incomplete scan ({state.scan_id}) "
            f"from {state.scan_date}[/yellow]\n"
        )
    else:
        state = ScanState(
            scan_id=str(uuid.uuid4())[:8],
            scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_services=len(services),
        )
        save_state(state)
        console.print(
            f"Scan ID: [cyan]{state.scan_id}[/cyan] | "
            f"Started: [cyan]{state.scan_date}[/cyan]\n"
        )

    output_dir = get_output_dir()
    temp_dir = output_dir / "temp"
    temp_dir.mkdir(parents=True, exist_ok=True)
    temp_pdfs: list[Path] = []

    # PASS 1: Generate Prompts for all uncompleted services
    pending_to_add: int = 0
    with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console,
    ) as progress:
        task = progress.add_task("Generating prompts...", total=len(services))
        for svc in services:
            if is_service_completed(state, svc.service_name):
                # We already analyzed this service fully, grab existing PDFs
                existing = [r for r in state.results if r.service_name == svc.service_name]
                if existing:
                    pdf = temp_dir / f"pyhardin_{svc.service_name}.pdf"
                    if not pdf.exists():
                        generate_service_pdf(existing[0], temp_dir)
                    temp_pdfs.append(pdf)
                progress.advance(task)
                continue

            # Check if we already have a 'pending' prompt for this service in state
            existing_pending = [
                r for r in state.results
                if r.service_name == svc.service_name and r.status == "pending"
            ]
            if not existing_pending:
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
                pending_to_add += 1
                save_state(state)

            progress.advance(task)

    pending_results = [r for r in state.results if r.status == "pending"]
    if not pending_results:
        console.print("[green]No new prompts to review! All services are fully analyzed.[/green]")
        scan_completed = True
    else:
        console.print(
            f"\n[cyan]{len(pending_results)}[/cyan] prompts generated and awaiting review."
        )
        scan_completed = False

        mode = "interactive"
        # PASS 2: Interactive LLM Execution
        for idx, result in enumerate(pending_results):
            if mode != "all":
                console.print(
                    f"\n[bold magenta]Service:[/bold magenta] {result.service_name.upper()}"
                )
                console.print("[dim]Prompt Preview (first 100 chars)...[/dim]")
                preview = result.prompt[:100].replace('\n', ' ') + "..."
                console.print(f"  {preview}\n")

                choice = Prompt.ask(
                    f"Send ({idx + 1}/{len(pending_results)})?",
                    choices=["y", "n", "all", "q"],
                    default="y"
                )

                if choice == "q":
                    console.print("[yellow]Scan paused. Run pyhardin later to resume.[/yellow]")
                    break
                elif choice == "n":
                    console.print(f"[dim]Skipping {result.service_name}...[/dim]")
                    continue
                elif choice == "all":
                    mode = "all"

            console.print(f"Analyzing [cyan]{result.service_name}[/cyan]...")
            if idx > 0 and mode == "all":
                time.sleep(2)  # Throttle burst requests

            try:
                # analyze_service now accepts an AnalysisResult and replaces it with `complete` data
                final_result = analyze_service(result)
                mark_service_complete(state, result.service_name, final_result)

                pdf = generate_service_pdf(final_result, temp_dir)
                temp_pdfs.append(pdf)
                console.print(f"[green]✓[/green] Successfully analyzed {result.service_name}")

                if final_result.status == "failed":
                    console.print(f"[red]Error analyzing {result.service_name}[/red]")
                else:
                    if final_result.summary:
                        console.print(f"[dim]{final_result.summary}[/dim]")

                    if isinstance(final_result.findings, list):
                        issues = [
                            f for f in final_result.findings
                            if f.severity in ("HIGH", "CRITICAL")
                        ]
                        if issues:
                            console.print(f"[red]Found {len(issues)} critical/high issues.[/red]")
                        elif final_result.findings:
                            console.print(
                                f"[yellow]Found {len(final_result.findings)} "
                                f"total issues.[/yellow]"
                            )
                        else:
                            console.print("[green]Secure.[/green]")
                    else:
                        if final_result.remediation_commands:
                            console.print(
                                f"[yellow]Found issues in {result.service_name}.[/yellow]"
                            )
                        else:
                            console.print(f"[green]{result.service_name} is secure.[/green]")

            except APIRateLimitError as e:
                console.log(
                    f"[yellow]⚠ API Rate Limit Hit! {e}[/yellow]\n"
                    "[yellow]State saved. Re-run to resume.[/yellow]"
                )
                save_state(state)
                break
            except AnalyzerError as e:
                console.print(f"  [red]✗ {result.service_name}: {e}[/red]")
                failed_result = AnalysisResult(
                    service_name=result.service_name,
                    findings=f"Analysis failed: {e}",
                    status="failed",
                    prompt=result.prompt
                )
                mark_service_complete(state, result.service_name, failed_result)
            except Exception as e:
                console.print(f"  [red]✗ Unexpected error on {result.service_name}: {e}[/red]")
                save_state(state)

        # Check if all targeted services in `state.results` are complete
        all_done = all(r.status != "pending" for r in state.results)
        if all_done and len(state.results) == len(services):
            scan_completed = True
        else:
            scan_completed = False

    console.print()

    if temp_pdfs:
        now = datetime.now().strftime("%Y%m%d_%H%M%S")
        final_pdf = output_dir / f"pyhardin_report_{now}.pdf"
        console.print("[bold]Generating final report...[/bold]")
        merge_pdfs(temp_pdfs, final_pdf)
        cleanup_temp_pdfs(temp_pdfs)

        try:
            import shutil
            if (temp_dir).exists():
                shutil.rmtree(temp_dir)
        except OSError:
            pass

        console.print(Panel(
            f"[green bold]Report saved to:[/green bold] {final_pdf}",
            title="[bold]Report Complete[/bold]",
            border_style="green",
        ))

    all_results = state.results
    remediation_script = build_remediation_script(all_results)

    if remediation_script:
        console.print()
        console.print(Panel(
            "[bold yellow]Security issues were found during the scan.[/bold yellow]\n\n"
            "Review the detailed PDF report for more information. To automatically apply all "
            "AI-recommended fixes safely, run:\n\n"
            "    [bold cyan]pyhardin --apply[/bold cyan]",
            title="[bold red]⚡ Auto-Remediation Ready[/bold red]",
            border_style="red",
            padding=(1, 2),
        ))
    elif scan_completed:
        # Only print the success message if we actually finished scanning everything
        console.print(
            "\n[green bold]No remediation needed. Your system looks secure! 🎉[/green bold]"
        )

    if scan_completed:
        state.is_complete = True
        save_state(state)
    else:
        console.print(
            "\n[dim]Scan paused. Run 'pyhardin' again later to resume remaining services.[/dim]"
        )


def _list_services() -> None:
    console.print(BANNER)
    available = list_all_services()
    if not available:
        console.print("[yellow]No known services detected on this system.[/yellow]")
        return

    table = Table(title="Available Services", border_style="bright_black")
    table.add_column("#", style="dim", width=4)
    table.add_column("Service", style="cyan")

    for i, svc in enumerate(available, 1):
        table.add_row(str(i), svc)

    console.print(table)
    console.print(f"\n[dim]Total: {len(available)} services detected[/dim]")


def _show_history() -> None:
    console.print(BANNER)
    states = load_all_states()
    if not states:
        console.print("[yellow]No scan history found.[/yellow]")
        return

    table = Table(title="Scan History", border_style="bright_black")
    table.add_column("Scan ID", style="cyan", justify="center")
    table.add_column("Date", style="dim")
    table.add_column("Services Scanned", justify="right")
    table.add_column("Status", justify="center")

    for state in states:
        status_text = (
            "[green]Complete[/green]" if state.is_complete else "[yellow]Incomplete[/yellow]"
        )
        table.add_row(
            state.scan_id,
            state.scan_date,
            str(len(state.results)),
            status_text
        )

    console.print(table)


def _show_scan(scan_id: str) -> None:
    states = load_all_states()
    state = next((s for s in states if s.scan_id.startswith(scan_id)), None)

    if not state:
        console.print(f"[red]Scan ID '{scan_id}' not found.[/red]")
        return

    console.print(
        f"\n[bold]Report for Scan ID:[/bold] [cyan]{state.scan_id}[/cyan] "
        f"({state.scan_date})\n"
    )

    show_prompts = getattr(main, "show_prompts", False)

    for result in state.results:
        console.print(f"[bold]{result.service_name.upper()}[/bold]")

        if show_prompts and result.prompt:
            table = Table(show_header=True, header_style="bold magenta", border_style="dim")
            table.add_column("Property", style="bold cyan")
            table.add_column("Value")

            table.add_row("Provider", result.provider.upper() if result.provider else "Unknown")
            table.add_row("Model", result.model or "Unknown")
            table.add_row(
                "Parameters",
                f"Temp: {result.temperature} / Max Tokens: {result.max_tokens}"
            )

            os_info = "Unknown"
            if "Server OS Context:\n" in result.prompt:
                os_info = result.prompt.split('Server OS Context:\n')[1].split('\n\n')[0]
            table.add_row("OS Context", os_info)

            files = [line[10:-4] for line in result.prompt.split('\n') if line.startswith('--- FILE: ')]
            table.add_row("Attached Files", "\n".join(files) if files else "None")

            console.print(table)
            console.print()

        if result.status == "failed":
            console.print(f"  [red]Error: {result.findings}[/red]\n")
            continue

        if result.status == "pending":
            console.print("  [yellow]Pending Analysis (Not sent to LLM yet)[/yellow]\n")
            continue

        if isinstance(result.findings, list):
            if not result.findings:
                console.print("  [green]✓ Secure. No issues detected.[/green]\n")
            else:
                table = Table(show_header=True, header_style="bold magenta", border_style="dim")
                table.add_column("Severity")
                table.add_column("Issue")
                table.add_column("Current")
                table.add_column("Recommended")

                for f in result.findings:
                    sev = getattr(f, "severity", "INFO")
                    sev_color = (
                        "red" if sev == "CRITICAL" else "yellow" if sev == "HIGH" else "blue"
                    )
                    table.add_row(
                        f"[{sev_color}]{sev}[/{sev_color}]",
                        getattr(f, 'title', ''),
                        getattr(f, 'current_value', ''),
                        f"[green]{getattr(f, 'recommended_value', '')}[/green]"
                    )
                console.print(table)
                console.print()
        else:
            console.print(f"  {result.findings}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="pyhardin",
        description="Pyhardin - AI-Powered Linux Security Configuration Auditor",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all detectable services on this system",
    )
    parser.add_argument(
        "--history",
        action="store_true",
        help="List all previous scans and their exact IDs",
    )
    parser.add_argument(
        "--show",
        metavar="SCAN_ID",
        help="Show the full table report of a specific scan ID",
    )
    parser.add_argument(
        "--clear",
        action="store_true",
        help="Clear all scan state history tracking",
    )
    parser.add_argument(
        "--delete",
        metavar="SCAN_ID",
        help="Delete a specific scan by its ID",
    )
    parser.add_argument(
        "--show-prompts",
        action="store_true",
        help="Include structured prompt details in reports",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Start the Pyhardin web dashboard",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host interface for the web dashboard (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port for the web dashboard (default: 8000)",
    )
    parser.add_argument(
        "--scan",
        nargs="*",
        metavar="PATH",
        help="Additional paths to scan for configuration files",
    )
    parser.add_argument(
        "--no-resume",
        action="store_true",
        help="Start a fresh scan, ignoring any saved progress",
    )
    parser.add_argument(
        "--resume-id",
        metavar="SCAN_ID",
        help="Resume a specific incomplete scan by its ID",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Execute the pending remediation script generated by the last scan",
    )
    parser.add_argument(
        "--apply-service",
        metavar="SERVICE",
        help="Execute remediation only for a specific service (e.g., --apply-service ssh)",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Wipe all API keys, model configurations, and tracking state, "
             "then restart the setup wizard",
    )
    parser.add_argument(
        "--set-key",
        metavar="KEY",
        help="Set or update the API key",
    )
    parser.add_argument(
        "--set-provider",
        choices=["gemini", "openai"],
        help="Set the API provider (gemini or openai)",
    )
    parser.add_argument(
        "--set-model",
        metavar="MODEL",
        help="Set the model to use (e.g., gemini-2.5-flash, o3-mini)",
    )
    parser.add_argument(
        "--set-api-base",
        metavar="URL",
        help="Set a custom API base URL for OpenAI-compatible endpoints",
    )

    args = parser.parse_args()

    try:
        updated = False
        if args.set_key:
            set_api_key(args.set_key)
            console.print("[green]✓ API key updated.[/green]")
            updated = True
        if args.set_provider:
            set_provider(args.set_provider)
            console.print(f"[green]✓ Provider updated to {args.set_provider}.[/green]")
            updated = True
        if args.set_model:
            set_model(args.set_model)
            console.print(f"[green]✓ Model updated to {args.set_model}.[/green]")
            updated = True
        if args.set_api_base is not None:
            # allow empty string to clear the base URL
            set_api_base(args.set_api_base)
            console.print(f"[green]✓ API Base URL updated to '{args.set_api_base}'.[/green]")
            updated = True

        if args.reset:
            reset_config()
            console.print("[green]✓ All configuration and tracking state has been wiped.[/green]")
            updated = True

        if updated and not (
                args.list or args.gui or args.scan is not None or args.no_resume or args.apply
        ):
            return

        if args.gui:
            console.print("\n[bold yellow]Secure Web Dashboard Component[/bold yellow]")
            import getpass
            import os
            import urllib.request

            from rich.prompt import Prompt

            web_user = Prompt.ask("Enter a username for Web GUI login", default="admin")
            web_pass = getpass.getpass("Enter a password for Web GUI login: ")

            os.environ["PYHARDIN_WEB_USER"] = web_user
            os.environ["PYHARDIN_WEB_PASS"] = web_pass

            public_ip = "127.0.0.1"
            try:
                headers = {'User-Agent': 'Mozilla/5.0'}
                req = urllib.request.Request("https://api.ipify.org", headers=headers)
                import ssl

                import certifi
                context = ssl.create_default_context(cafile=certifi.where())
                with urllib.request.urlopen(req, timeout=3, context=context) as response:
                    public_ip = response.read().decode('utf-8').strip()
            except Exception:
                console.print("[yellow]Could not determine public IP, using local host.[/yellow]")

            host_bind = "0.0.0.0" if args.host == "127.0.0.1" else args.host

            console.print(
                "\n[bold green]Dashboard securely hosted at: "
                f"http://{public_ip}:{args.port}[/bold green]"
            )
            console.print(f"[dim]Binding to internal interface {host_bind}:{args.port}[/dim]\n")

            try:
                import uvicorn
            except ImportError:
                console.print("\n[red]The GUI dependencies are not installed.[/red]")
                console.print("[dim]To launch the Web Dashboard, please install the GUI extension by running:[/dim]")
                console.print("[bold cyan]pip install \"pyhardin[gui]\"[/bold cyan]\n")
                return

            uvicorn.run("pyhardin.web:app", host=host_bind, port=args.port)
            return

        if args.list:
            _list_services()
            return

        if args.apply:
            execute_pending_remediation()
            return

        if args.apply_service:
            execute_service_remediation(args.apply_service)
            return

        if args.clear:
            clear_state()
            console.print("[green]✓ All scan history has been securely cleared.[/green]")
            return

        if args.history:
            _show_history()
            return

        if args.show:
            main.show_prompts = args.show_prompts
            _show_scan(args.show)
            return

        if args.delete:
            if delete_state(args.delete):
                console.print(f"[green]✓ Scan '{args.delete}' deleted successfully.[/green]")
            else:
                console.print(f"[red]Scan '{args.delete}' not found.[/red]")
            return

        _run_scan(
            extra_paths=args.scan,
            resume_id=args.resume_id,
            resume=not args.no_resume,
        )

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted. Progress saved. Re-run to resume.[/yellow]")
        sys.exit(130)
    except PyhardinError as e:
        console.print(f"\n[red bold]Error:[/red bold] {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red bold]Unexpected error:[/red bold] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
