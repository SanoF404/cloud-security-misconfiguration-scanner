import argparse
import json
from collections import Counter
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from cloud_scanner.reporting import export_findings_to_csv
from cloud_scanner.scanner import scan_config


console = Console()

SEVERITY_STYLES = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "bold cyan",
    "INFO": "bold blue",
    "UNKNOWN": "white",
}


def display_banner():
    banner = Text()
    banner.append("CLOUD ", style="bold bright_cyan")
    banner.append("SECURITY ", style="bold white")
    banner.append("SCANNER", style="bold bright_green")
    banner.append("\nDefensive configuration analysis", style="dim")

    console.print()
    console.print(
        Panel(
            banner,
            border_style="bright_cyan",
            box=box.DOUBLE,
            padding=(1, 2),
        )
    )


def display_risk_summary(findings):
    counts = Counter(
        str(finding.get("severity", "UNKNOWN")).upper()
        for finding in findings
    )

    summary = Table(
        title="SECURITY RISK SUMMARY",
        box=box.ROUNDED,
        border_style="bright_cyan",
        expand=True,
    )
    summary.add_column("Severity", style="bold")
    summary.add_column("Findings", justify="right")

    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"):
        summary.add_row(
            Text(severity, style=SEVERITY_STYLES[severity]),
            str(counts[severity]),
        )

    console.print()
    console.print(summary)

    critical_count = counts["CRITICAL"]
    high_count = counts["HIGH"]

    if critical_count:
        risk_message = (
            f"[bold red]Immediate review recommended:[/] "
            f"{critical_count} critical finding(s) detected."
        )
        border_style = "red"
    elif high_count:
        risk_message = (
            f"[bold yellow]High-priority review recommended:[/] "
            f"{high_count} high-severity finding(s) detected."
        )
        border_style = "yellow"
    else:
        risk_message = (
            "[bold green]No critical or high-severity findings detected.[/]"
        )
        border_style = "green"

    console.print(
        Panel(
            risk_message
            + "\n[dim]This priority reflects detected findings only; "
            "it is not an overall cloud security score.[/]",
            title="RECOMMENDED REVIEW PRIORITY",
            border_style=border_style,
            box=box.ROUNDED,
            expand=True,
        )
    )


def display_findings(findings, config_path, csv_path=None):
    console.print(
        f"\n[dim]Configuration:[/] [bright_cyan]{config_path}[/]"
    )
    console.print(
        f"[dim]Findings detected:[/] [bold]{len(findings)}[/]"
    )

    if csv_path:
        console.print(
            f"[dim]CSV report:[/] [bright_green]{csv_path}[/]"
        )

    display_risk_summary(findings)

    if not findings:
        console.print(
            Panel(
                "[bold bright_green]No security issues detected.[/]\n"
                "[dim]No findings were reported by the configured rules.[/]",
                title="SCAN RESULT",
                border_style="bright_green",
                box=box.ROUNDED,
            )
        )
        return

    table = Table(
        title="DETECTED SECURITY FINDINGS",
        box=box.ROUNDED,
        border_style="bright_cyan",
        header_style="bold bright_cyan",
        show_lines=True,
        expand=True,
    )
    table.add_column("#", justify="right", width=3)
    table.add_column("Severity", width=10)
    table.add_column("Rule", width=12)
    table.add_column("Resource", ratio=1)
    table.add_column("Finding", ratio=2)

    for index, finding in enumerate(findings, start=1):
        severity = str(finding.get("severity", "UNKNOWN")).upper()
        style = SEVERITY_STYLES.get(severity, "white")

        table.add_row(
            str(index),
            Text(severity, style=style),
            str(finding.get("rule_id", "N/A")),
            str(finding.get("resource_name", "Unknown")),
            str(finding.get("title", "Untitled finding")),
        )

    console.print()
    console.print(table)

    for index, finding in enumerate(findings, start=1):
        severity = str(finding.get("severity", "UNKNOWN")).upper()
        style = SEVERITY_STYLES.get(severity, "white")

        details = (
            f"[bold]Resource ID:[/] {finding.get('resource_id', 'N/A')}\n"
            f"[bold]Resource name:[/] "
            f"{finding.get('resource_name', 'Unknown')}\n\n"
            f"[bold]Recommendation:[/] "
            f"{finding.get('recommendation', 'No recommendation')}"
        )

        console.print(
            Panel(
                details,
                title=f"[{style}]Finding {index} - {severity}[/]",
                border_style=style,
                box=box.ROUNDED,
                expand=True,
            )
        )

    console.print(
        "\n[dim]Review each recommendation before making configuration changes.[/]"
    )


def main():
    parser = argparse.ArgumentParser(
        description="Scan cloud configurations for security issues."
    )
    parser.add_argument(
        "config_file",
        nargs="?",
        default="examples/cloud_config.json",
        help="Path to the JSON configuration file.",
    )
    parser.add_argument(
        "--csv",
        dest="csv_path",
        help="Export findings to a CSV file.",
    )
    args = parser.parse_args()

    config_path = Path(args.config_file)

    display_banner()

    try:
        with config_path.open("r", encoding="utf-8-sig") as file:
            config = json.load(file)

        resources = (
            config.get("resources")
            if isinstance(config, dict)
            else None
        )

        if isinstance(resources, list) and resources:
            with Progress(
                TextColumn("[bold cyan]Scanning resources"),
                BarColumn(),
                TextColumn("{task.completed}/{task.total}"),
                TextColumn("resources"),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task_id = progress.add_task(
                    "scan",
                    total=len(resources),
                )

                findings = scan_config(
                    config,
                    progress_callback=lambda: progress.advance(task_id),
                )
        else:
            if isinstance(resources, list) and not resources:
                console.print("[dim]No resources to scan.[/]")
            findings = scan_config(config)

        if args.csv_path:
            export_findings_to_csv(findings, args.csv_path)

    except FileNotFoundError:
        console.print(
            f"[bold red]Error:[/] file not found: {config_path}"
        )
        return 1
    except json.JSONDecodeError as error:
        console.print(f"[bold red]Error:[/] invalid JSON: {error}")
        return 1
    except ValueError as error:
        console.print(
            f"[bold red]Error:[/] invalid configuration: {error}"
        )
        return 1
    except OSError as error:
        console.print(
            f"[bold red]Error:[/] could not read or write a file: {error}"
        )
        return 1

    display_findings(findings, config_path, args.csv_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
