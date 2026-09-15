import typer
from rich.console import Console
from rich.table import Table
from engine.rules import is_suspicious_heuristic
from engine.ai_eval import evaluate_with_ai

app = typer.Typer(help="Fast AI Breach Detection Tool")
console = Console()

@app.command()
def scan(
    logfile: str = typer.Argument(..., help="Path to log file"),
    min_confidence: float = typer.Option(0.7, help="Minimum confidence threshold (0.0 - 1.0)"),
    context: str = typer.Option("Production Ubuntu 22.04 Web Server", help="System environment context")
):
    console.print(f"[bold blue]Scanning {logfile} using hybrid heuristic + AI mode...[/bold blue]\n")
    
    table = Table(title="Detected True Positive Security Threats")
    table.add_column("Confidence", style="magenta")
    table.add_column("Type", style="red")
    table.add_column("Explanation", style="cyan")

    with open(logfile, 'r') as f:
        for line in f:
            line = line.strip()
            # Fast-path filtering
            if is_suspicious_heuristic(line):
                # AI triage pass
                result = evaluate_with_ai(line, system_context=context)
                
                if result.is_true_positive and result.confidence_score >= min_confidence:
                    table.add_row(
                        f"{result.confidence_score:.2f}",
                        result.attack_type,
                        result.explanation
                    )

    console.print(table)

if __name__ == "__main__":
    app()
