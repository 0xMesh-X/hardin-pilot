import argparse
import subprocess
import sys
import uuid
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from hardin.analyzer import analyze_service
from hardin.config import (
    get_api_key,
    get_output_dir,
    set_api_base,
    set_api_key,
    set_model,
    set_provider,
)
from hardin.exceptions import AnalyzerError, APIRateLimitError, HardinError
from hardin.reporter import (
    build_remediation_script,
    cleanup_temp_pdfs,
    generate_service_pdf,
    merge_pdfs,
)
from hardin.scanner import ServiceConfig, list_all_services, run_full_scan
from hardin.state import (
    AnalysisResult,
    ScanState,
    clear_state,
    is_service_completed,
    load_state,
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
[dim]  AI-Powered Linux Security Auditor v1.0.0[/dim]
"""


from rich.prompt import IntPrompt


def _prompt_api_key() -> str:
    console.print(Panel(
        "[yellow]Welcome to Hardin - First-Time Setup[/yellow]\n\n"
        "Hardin requires an AI provider to perform security analysis.\n"
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
        model = console.input("[bold cyan]Enter model name[/bold cyan] [dim](Default: gemini-2.5-flash)[/dim]: ").strip() or "gemini-2.5-flash"
        api_base = ""
        url_hint = "https://aistudio.google.com/apikey"

    elif choice == 2:
        provider = "openai"
        model = console.input("[bold cyan]Enter model name[/bold cyan] [dim](Default: gpt-4o)[/dim]: ").strip() or "gpt-4o"
        api_base = ""
        url_hint = "https://platform.openai.com/api-keys"

    else:
        provider = "openai" # Custom endpoints use the OpenAI python library
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

    console.print("\n[green]✓ Configuration saved. Hardin is ready![/green]\n")
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
    '''Executes the saved bash script from the previous scan.'''
    script_path = get_output_dir().parent / ".hardin" / "last_remediation.sh"

    if not script_path.exists():
        console.print("[yellow]No pending remediation script found. Please run a full scan first.[/yellow]")
        return

    console.print(Panel(
        f"[bold yellow]Executing pending auto-remediation from previous scan...[/bold yellow]\n\n"
        f"[dim]Reading: {script_path}[/dim]",
        title="[bold red]⚡ Applying Fixes[/bold red]",
        border_style="red",
        padding=(1, 2),
    ))

    try:
        subprocess.run(str(script_path), shell=True, check=True, executable='/bin/bash')
        console.print("\n[green bold]✓ Auto-remediation executed successfully![/green bold]")
        # Success, delete the script so we don't accidentally run it again
        script_path.unlink()
    except subprocess.CalledProcessError as e:
        console.print(f"\n[red bold]✗ Remediation command failed with exit code {e.returncode}[/red bold]")


def _run_scan(extra_paths: list[str] | None = None, resume: bool = True) -> None:
    api_key = get_api_key()
    if not api_key:
        api_key = _prompt_api_key()

    console.print(BANNER)
    console.print("[bold]Scanning system configurations...[/bold]\n")

    services = run_full_scan(extra_paths)
    if not services:
        console.print("[yellow]No configuration files found to analyze.[/yellow]")
        return

    _show_services(services)

    state = load_state() if resume else None
    if state and not state.is_complete:
        remaining = len(services) - len(state.completed_services)
        console.print(f"[cyan]Resuming previous scan. {len(state.completed_services)} services already analyzed, {remaining} remaining.[/cyan]\n")
    else:
        state = ScanState(
            scan_id=str(uuid.uuid4())[:8],
            total_services=len(services),
        )
        save_state(state)

    output_dir = get_output_dir()
    temp_dir = output_dir / "temp"
    temp_dir.mkdir(parents=True, exist_ok=True)
    temp_pdfs: list[Path] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("Analyzing services...", total=len(services))
        scan_completed = True

        for svc in services:
            if is_service_completed(state, svc.service_name):
                existing = [r for r in state.results if r.service_name == svc.service_name]
                if existing:
                    pdf = temp_dir / f"hardin_{svc.service_name}.pdf"
                    if not pdf.exists():
                        generate_service_pdf(existing[0], temp_dir)
                    temp_pdfs.append(pdf)
                progress.advance(task)
                continue

            progress.update(task, description=f"Analyzing [cyan]{svc.service_name}[/cyan]...")

            try:
                result = analyze_service(svc)
                mark_service_complete(state, svc.service_name, result)
                pdf = generate_service_pdf(result, temp_dir)
                temp_pdfs.append(pdf)
                console.print(f"  [green]✓[/green] {svc.service_name}")
            except APIRateLimitError:
                console.print(f"  [yellow]⚠ Rate limited on {svc.service_name}. State saved. Re-run to resume.[/yellow]")
                save_state(state)
                scan_completed = False
                break
            except AnalyzerError as e:
                console.print(f"  [red]✗ {svc.service_name}: {e}[/red]")
                failed_result = AnalysisResult(
                    service_name=svc.service_name,
                    findings=f"Analysis failed: {e}",
                    status="failed",
                )
                mark_service_complete(state, svc.service_name, failed_result)
            except Exception as e:
                console.print(f"  [red]✗ Unexpected error on {svc.service_name}: {e}[/red]")
                save_state(state)

            progress.advance(task)

    console.print()

    if temp_pdfs:
        now = datetime.now().strftime("%Y%m%d_%H%M%S")
        final_pdf = output_dir / f"hardin_report_{now}.pdf"
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
            f"[bold yellow]Copy and paste the following command to fix all issues[/bold yellow] (or run `hardin --apply`):\n\n"
            f"[white]{remediation_script}[/white]",
            title="[bold red]⚡ Auto-Remediation Command[/bold red]",
            border_style="red",
            padding=(1, 2),
        ))
    elif scan_completed:
        # Only print the success message if we actually finished scanning everything
        console.print("\n[green bold]No remediation needed. Your system looks secure! 🎉[/green bold]")

    if scan_completed:
        state.is_complete = True
        save_state(state)
        clear_state()
    else:
        console.print("\n[dim]Scan paused. Run 'hardin' again later to resume remaining services.[/dim]")


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


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="hardin",
        description="Hardin Pilot - AI-Powered Linux Security Configuration Auditor",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all detectable services on this system",
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
        "--apply",
        action="store_true",
        help="Execute the pending remediation script generated by the last scan",
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

        if updated and not (args.list or args.scan is not None or args.no_resume):
            return

        if args.list:
            _list_services()
            return

        if args.apply:
            execute_pending_remediation()
            return

        _run_scan(
            extra_paths=args.scan,
            resume=not args.no_resume,
        )

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted. Progress saved. Re-run to resume.[/yellow]")
        sys.exit(130)
    except HardinError as e:
        console.print(f"\n[red bold]Error:[/red bold] {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red bold]Unexpected error:[/red bold] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
