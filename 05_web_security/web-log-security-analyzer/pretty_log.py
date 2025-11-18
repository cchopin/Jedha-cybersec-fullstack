#!/usr/bin/env python3
"""Pretty log display utilities for security analysis results"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from config import ATTACKS


class PrettyLog:

    def __init__(self, title="Résumé des détections"):

        self.console = Console()
        self.title = title

    def display_summary(self, attack_counts, total_entries):

        self.console.print(
            Panel.fit(
                f"[bold blue]{self.title}[/bold blue]\n"
                f"Total lignes analysées : [bold]{total_entries}[/bold]",
                style="bold blue"
            )
        )

        table = Table(
            title="Statistiques par type d'attaque",
            header_style="bold cyan",
            show_lines=True
        )
        table.add_column("Type d'attaque", style="yellow")
        table.add_column("Occurrences", style="green", justify="center")
        table.add_column("Pourcentage", style="bold white", justify="center")

        for attack_type, count in sorted(attack_counts.items(), key=lambda item: item[1], reverse=True):
            label = ATTACKS.get(attack_type, attack_type)
            percentage = (count / total_entries * 100) if total_entries else 0.0
            table.add_row(label, str(count), f"{percentage:.2f}%")

        self.console.print(table)

    def display_filtered_logs(self, log_entries, attack_type):

        # Filter logs for this attack type
        filtered_entries = [
            entry for entry in log_entries
            if entry.get(attack_type, False)
        ]

        # Check if any entries were found
        if not filtered_entries:
            attack_label = ATTACKS.get(attack_type, attack_type)
            self.console.print(
                f"[yellow]Aucune détection de type '{attack_label}'[/yellow]"
            )
            return

        # Create display table
        attack_label = ATTACKS.get(attack_type, attack_type)
        table = Table(
            title=f"Détections de type : {attack_label} ({len(filtered_entries)} entrées)",
            header_style="bold magenta",
            show_lines=True
        )

        table.add_column("IP", style="cyan", overflow="fold")
        table.add_column("Date", style="dim", overflow="fold")
        table.add_column("Méthode", style="yellow")
        table.add_column("Chemin/URL", style="white", overflow="fold", width=50)
        table.add_column("Code", style="green")
        table.add_column("User Agent", style="dim", overflow="fold", width=30)

        # Add filtered entries to table
        for entry in filtered_entries:
            ip_address = str(entry.get("ip", ""))
            datetime = str(entry.get("datetime", ""))
            method = str(entry.get("method", ""))
            url_path = str(entry.get("path", entry.get("url", "")))
            status_code = str(entry.get("status", ""))
            user_agent = str(entry.get("user_agent", ""))

            table.add_row(ip_address, datetime, method, url_path, status_code, user_agent)

        self.console.print(table)
