"""CSV export of untrusted network metadata for spreadsheet-safe inspection."""
import pandas as pd


def flow_csv_bytes(frame):
    """Quote CSV normally and neutralize cells that spreadsheets treat as formulas."""
    export = frame.copy()
    for column in export.select_dtypes(include=["object", "string"]).columns:
        export[column] = export[column].map(
            lambda value: "'" + value if isinstance(value, str) and
            value.lstrip().startswith(("=", "+", "-", "@")) else value
        )
    return export.to_csv(index=False).encode("utf-8-sig")
