#!/usr/bin/env python3

import sys
import argparse
from collections import defaultdict

from rich.console import Console
from rich.table import Table

import logs_parser
import detection
from pretty_log import PrettyLog
from config import ATTACKS


def parse_and_analyze_logs(log_file_path):

    console = Console()

    with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as file:
        log_lines = file.readlines()
        log_entries = logs_parser.parse_apache_logs(log_lines)

        # Run attack detection on each log entry
        for entry in log_entries:
            url = entry.get('url', '')
            user_agent = entry.get('user_agent', '')
            referer = entry.get('referer', '')

            # Detect various attack types
            entry['jwt'] = detection.detect_jwt(url, user_agent, referer)
            entry['lfi'] = detection.detect_lfi(url, user_agent, referer)
            entry['sql'] = detection.detect_sql(url, user_agent, referer)
            entry['xss'] = detection.detect_xss(url, user_agent, referer)
            entry['cmd_inj'] = detection.detect_command_injection(url, user_agent, referer)
            entry['xxe'] = detection.detect_xxe(url, user_agent, referer)
            entry['ldap'] = detection.detect_ldap_injection(url, user_agent, referer)
            entry['ssrf'] = detection.detect_ssrf(url, user_agent, referer)
            entry['template'] = detection.detect_template_injection(url, user_agent, referer)
            entry['open_redirect'] = detection.detect_open_redirect(url)
            entry['scanner'] = detection.detect_scanner(user_agent)

        return log_entries


def display_summary(log_entries):

    attack_counts = defaultdict(int)
    total_entries = len(log_entries)

    # Count attacks by type
    for entry in log_entries:
        for attack_type in ATTACKS.keys():
            if entry.get(attack_type):
                attack_counts[attack_type] += 1

    # Create Rich table
    console = Console()
    table = Table(
        title="Statistiques par type d'attaque",
        title_style="bold magenta",
        header_style="bold cyan",
        show_lines=True
    )

    table.add_column("Type d'attaque", style="yellow", justify="left")
    table.add_column("Occurrences", style="green", justify="center")
    table.add_column("Pourcentage", style="bold white", justify="center")
    table.add_column("Voir détail", style="blue", justify="center")

    # Add rows sorted by count (descending)
    for attack_type, count in sorted(attack_counts.items(), key=lambda item: item[1], reverse=True):
        label = ATTACKS.get(attack_type, attack_type)
        percentage = (count / total_entries * 100) if total_entries else 0.0
        table.add_row(label, str(count), f"{percentage:.2f}%", attack_type)

    console.print(table)



def build_argument_parser(program_name):

    parser = argparse.ArgumentParser(
        description="Web log security analyzer - Detect attack patterns in Apache logs",
        epilog=f"Example: python {program_name} apache-access-log.txt"
    )
    parser.add_argument(
        "log_file",
        help="Path to Apache log file to analyze"
    )
    return parser


def run_interactive_explorer(log_entries):

    console = Console()
    pretty_log = PrettyLog()

    console.print("\n[bold cyan]Mode interactif - Exploration des détections[/bold cyan]")
    console.print("[dim]Saisissez le type de faille pour voir les détails (ou 'q' pour quitter)[/dim]\n")

    # Display available attack types
    console.print("[yellow]Types de failles disponibles :[/yellow]")
    for attack_type, label in ATTACKS.items():
        console.print(f"  • [cyan]{attack_type}[/cyan] : {label}")
    console.print()

    # Interactive loop
    while True:
        user_input = input("Type de faille à afficher (ou 'q' pour quitter) : ").strip().lower()

        # Check for quit command
        if user_input in ['q', 'quit', 'exit']:
            console.print("[green]Au revoir ![/green]")
            break

        # Validate attack type
        if user_input not in ATTACKS:
            console.print(f"[red]Type de faille inconnu : '{user_input}'[/red]")
            console.print(f"[dim]Types valides : {', '.join(ATTACKS.keys())}[/dim]\n")
            continue

        # Display filtered logs for this attack type
        pretty_log.display_filtered_logs(log_entries, user_input)
        console.print()


if __name__ == "__main__":
    # Parse command-line arguments
    parser = build_argument_parser(sys.argv[0])
    args = parser.parse_args()

    # Parse and analyze logs (done once)
    log_entries = parse_and_analyze_logs(args.log_file)

    # Display summary statistics
    display_summary(log_entries)

    # Launch interactive mode to explore detections
    run_interactive_explorer(log_entries)
