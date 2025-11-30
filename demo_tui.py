#!/usr/bin/env python3
"""
Demo script to showcase TUI features non-interactively
"""

import sys
import os

# Add pf-runner to path
sys.path.insert(0, '/home/runner/work/pf-web-poly-compile-helper-runner/pf-web-poly-compile-helper-runner/pf-runner')

from pf_tui import PfTUI
from rich.console import Console

def demo_tui():
    """Demonstrate TUI capabilities"""
    console = Console()
    
    console.print("\n[bold cyan]═══════════════════════════════════════════════════════[/bold cyan]")
    console.print("[bold cyan]           pf TUI Demo - Non-Interactive Mode           [/bold cyan]")
    console.print("[bold cyan]═══════════════════════════════════════════════════════[/bold cyan]\n")
    
    # Initialize TUI
    tui = PfTUI()
    
    # Show header
    console.print("[bold]1. Header Display:[/bold]")
    tui.show_header()
    
    # Load and categorize tasks
    console.print("\n[bold]2. Loading Tasks:[/bold]")
    if tui.load_tasks():
        console.print(f"[green]✓ Successfully loaded {len(tui.tasks)} tasks[/green]")
    else:
        console.print("[red]✗ Failed to load tasks[/red]")
        return
    
    console.print("\n[bold]3. Categorizing Tasks:[/bold]")
    tui.categorize_tasks()
    console.print(f"[green]✓ Organized into {len(tui.categories)} categories[/green]")
    
    # Show categories summary
    console.print("\n[bold]4. Category Summary:[/bold]")
    for category in tui.categories:
        console.print(f"  • [cyan]{category.name}[/cyan]: {len(category.tasks)} tasks")
    
    # Show debugging tools
    console.print("\n[bold]5. Debugging Tools View:[/bold]")
    tui.show_debugging_tools()
    
    console.print("\n[bold cyan]═══════════════════════════════════════════════════════[/bold cyan]")
    console.print("[bold green]✓ Demo completed successfully![/bold green]")
    console.print("[bold cyan]═══════════════════════════════════════════════════════[/bold cyan]\n")
    
    console.print("[dim]To run the full interactive TUI, use: pf tui[/dim]\n")

if __name__ == "__main__":
    demo_tui()
