"""
Report Service — Generates HTML pentest reports with AI-powered mitigations.

Runs report generation in the background using asyncio.create_task.
Calls Claude to generate mitigation recommendations per finding category.
"""
from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import anthropic

from config import Config
from database.db import async_session
from database.models import Report, gen_uuid
from services.findings_service import findings_service, CATEGORY_SEVERITY

REPORTS_DIR = Path(__file__).parent.parent / "reports"


class ReportService:
    def __init__(self):
        self._sio = None

    async def start_generation(self, sio=None, agent_filter: str = "all") -> dict:
        """Start background report generation. Returns report record."""
        REPORTS_DIR.mkdir(exist_ok=True)
        self._sio = sio

        report_id = gen_uuid()
        title_suffix = f" ({agent_filter})" if agent_filter != "all" else ""
        async with async_session() as db:
            report = Report(
                id=report_id,
                status="processing",
                title=f"RedNerve Assessment Report{title_suffix} — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')}",
            )
            db.add(report)
            await db.commit()

        asyncio.create_task(self._generate(report_id, agent_filter))

        return {"id": report_id, "status": "processing"}

    async def _generate(self, report_id: str, agent_filter: str = "all"):
        """Background: gather findings, get AI mitigations, build HTML."""
        try:
            await self._emit_status(report_id, "processing", "Gathering findings...")

            findings = await findings_service.get_all_findings_flat()
            if agent_filter and agent_filter != "all":
                findings = [f for f in findings if f["source_agent"] == agent_filter]
            if not findings:
                await self._mark_failed(report_id, "No findings to report")
                return

            await self._emit_status(report_id, "processing",
                                    f"Found {len(findings)} findings. Generating report...")

            # Group by category
            by_category: dict[str, list[dict]] = {}
            for f in findings:
                cat = f["category"]
                if cat not in by_category:
                    by_category[cat] = []
                by_category[cat].append(f)

            # Get AI-generated finding rows per category
            report_findings: list[dict] = []
            for cat, items in by_category.items():
                await self._emit_status(report_id, "processing",
                                        f"Analyzing: {cat} ({len(items)} items)...")
                rows = await self._get_mitigations_for_findings(cat, items)
                for row in rows:
                    row["category"] = cat
                    row["severity"] = CATEGORY_SEVERITY.get(cat, "info")
                report_findings.extend(rows)
                await asyncio.sleep(0.5)

            await self._emit_status(report_id, "processing", "Building report...")

            # Build HTML report
            html = self._build_html_report(findings, report_findings)

            # Save file
            filename = f"report_{report_id[:8]}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.html"
            filepath = REPORTS_DIR / filename
            filepath.write_text(html, encoding="utf-8")

            # Update DB
            async with async_session() as db:
                report = await db.get(Report, report_id)
                if report:
                    report.status = "ready"
                    report.file_path = str(filepath)
                    report.finding_count = len(findings)
                    report.completed_at = datetime.now(timezone.utc)
                    await db.commit()

            await self._emit_status(report_id, "ready", "Report ready for download")

        except Exception as e:
            await self._mark_failed(report_id, str(e))

    async def _get_mitigations_for_findings(self, category: str, items: list[dict]) -> list[dict]:
        """Call Claude to get a title, short description, evidence, and mitigation per finding group."""
        if not Config.ANTHROPIC_API_KEY:
            return [{
                "title": item.get("key", "Unknown"),
                "description": "N/A",
                "evidence": "N/A",
                "mitigation": "No API key — unable to generate.",
            } for item in items[:30]]

        try:
            client = anthropic.Anthropic(api_key=Config.ANTHROPIC_API_KEY)

            # Build compact summary
            summary_items = []
            for item in items[:30]:
                data_str = json.dumps(item.get("data", {}), default=str)
                if len(data_str) > 300:
                    data_str = data_str[:300] + "..."
                summary_items.append(f"- Key: {item['key']}, Agent: {item.get('source_agent','')}, Data: {data_str}")
            items_text = "\n".join(summary_items)

            response = client.messages.create(
                model=Config.ANTHROPIC_MODEL,
                max_tokens=2048,
                messages=[{
                    "role": "user",
                    "content": (
                        f"You are writing a pentest report for the '{category}' category.\n"
                        f"For each finding below, return a JSON array. Each element:\n"
                        f'{{"title":"<short name>","description":"<1 sentence what it means>","evidence":"<1-2 short commands or data that prove it>","mitigation":"<1-2 sentence fix>"}}\n\n'
                        f"Group similar items into one finding where possible (e.g. 50 services → 1 finding 'Service Enumeration').\n"
                        f"Keep everything SHORT. Return ONLY the JSON array, no markdown.\n\n"
                        f"Findings:\n{items_text}"
                    ),
                }],
            )

            text = response.content[0].text.strip() if response.content else "[]"
            # Parse JSON — handle markdown code fences
            if text.startswith("```"):
                text = text.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
            return json.loads(text)

        except Exception as e:
            return [{
                "title": f"{category} findings ({len(items)})",
                "description": f"Found {len(items)} items in {category}.",
                "evidence": items[0].get("key", "N/A") if items else "N/A",
                "mitigation": f"AI generation failed: {str(e)}",
            }]

    def _build_html_report(self, raw_findings: list[dict],
                           report_findings: list[dict]) -> str:
        """Build a clean HTML report: title, description, evidence, mitigation."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        total_raw = len(raw_findings)

        # Severity breakdown from raw findings
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in raw_findings:
            sev = CATEGORY_SEVERITY.get(f["category"], "info")
            sev_counts[sev] += 1

        # Risk score
        risk_score = (
            sev_counts["critical"] * 10 +
            sev_counts["high"] * 7 +
            sev_counts["medium"] * 4 +
            sev_counts["low"] * 1
        )
        max_score = total_raw * 10 if total_raw else 1
        risk_pct = min(100, int((risk_score / max_score) * 100))
        risk_level = "Critical" if risk_pct > 75 else "High" if risk_pct > 50 else "Medium" if risk_pct > 25 else "Low"

        sev_colors = {
            "critical": "#ff4757", "high": "#ffa502",
            "medium": "#3b82f6", "low": "#2ed573", "info": "#a0a0a0",
        }

        # Sort findings by severity
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        report_findings.sort(key=lambda f: sev_order.get(f.get("severity", "info"), 4))

        # Severity bars
        sev_bars = ""
        for sev_name in ["critical", "high", "medium", "low", "info"]:
            count = sev_counts[sev_name]
            width = int((count / max(total_raw, 1)) * 100)
            color = sev_colors[sev_name]
            sev_bars += f"""
                <div style="display:flex;align-items:center;gap:10px;margin:4px 0;">
                    <span style="width:70px;text-transform:uppercase;font-size:11px;font-weight:bold;color:{color};">{sev_name}</span>
                    <div style="flex:1;background:#1a1a1a;border-radius:4px;height:20px;overflow:hidden;">
                        <div style="width:{width}%;background:{color};height:100%;border-radius:4px;"></div>
                    </div>
                    <span style="width:30px;text-align:right;color:#888;font-size:12px;">{count}</span>
                </div>"""

        # Findings table rows
        finding_rows = ""
        for f in report_findings:
            sev = f.get("severity", "info")
            color = sev_colors.get(sev, "#a0a0a0")
            finding_rows += f"""
                <tr>
                    <td><span style="color:{color};font-weight:bold;text-transform:uppercase;">{_esc(sev)}</span></td>
                    <td style="font-weight:bold;color:#e0e0e0;">{_esc(f.get('title', 'N/A'))}</td>
                    <td>{_esc(f.get('description', 'N/A'))}</td>
                    <td><code style="background:#111;padding:2px 6px;border-radius:3px;font-size:11px;color:#ccc;">{_esc(f.get('evidence', 'N/A'))}</code></td>
                    <td style="color:#8bc34a;">{_esc(f.get('mitigation', 'N/A'))}</td>
                </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RedNerve Assessment Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ background: #0d0d0d; color: #e0e0e0; font-family: 'Segoe UI', -apple-system, sans-serif; line-height: 1.6; }}
        .container {{ max-width: 1100px; margin: 0 auto; padding: 40px 20px; }}
        .header {{ text-align: center; margin-bottom: 40px; padding-bottom: 24px; border-bottom: 2px solid #b00020; }}
        .logo {{ font-size: 28px; font-weight: bold; letter-spacing: 4px; color: #ff4757; }}
        .logo span {{ color: #888; font-weight: normal; }}
        .subtitle {{ color: #888; font-size: 13px; margin-top: 8px; }}
        .exec-summary {{ background: #141414; border: 1px solid #333; border-radius: 8px; padding: 24px; margin-bottom: 32px; }}
        .exec-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-top: 16px; }}
        .exec-card {{ background: #1a1a1a; border-radius: 6px; padding: 16px; text-align: center; }}
        .exec-card .value {{ font-size: 28px; font-weight: bold; }}
        .exec-card .label {{ font-size: 11px; color: #888; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }}
        h2 {{ font-size: 16px; text-transform: uppercase; letter-spacing: 2px; color: #ff4757; margin: 32px 0 16px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 12px 0; }}
        th {{ text-align: left; padding: 10px 12px; border-bottom: 2px solid #333; color: #888; text-transform: uppercase; font-size: 10px; letter-spacing: 1px; }}
        td {{ padding: 10px 12px; border-bottom: 1px solid #222; font-size: 13px; vertical-align: top; }}
        tr:hover td {{ background: rgba(176,0,32,0.05); }}
        code {{ word-break: break-all; }}
        .footer {{ text-align: center; margin-top: 48px; padding-top: 24px; border-top: 1px solid #333; color: #555; font-size: 11px; }}
        @media print {{ body {{ background: #fff; color: #000; }} .container {{ max-width: 100%; }} }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">RED<span>NERVE</span></div>
            <div class="subtitle">Penetration Testing Assessment Report | Generated: {now}</div>
        </div>

        <div class="exec-summary">
            <h2 style="margin-top:0;">Executive Summary</h2>
            <div class="exec-grid">
                <div class="exec-card">
                    <div class="value" style="color:{'#ff4757' if risk_pct > 50 else '#ffa502' if risk_pct > 25 else '#2ed573'};">{risk_level}</div>
                    <div class="label">Overall Risk</div>
                </div>
                <div class="exec-card">
                    <div class="value" style="color:#ff4757;">{risk_pct}%</div>
                    <div class="label">Risk Score</div>
                </div>
                <div class="exec-card">
                    <div class="value">{total_raw}</div>
                    <div class="label">Total Findings</div>
                </div>
            </div>
        </div>

        <h2>Severity Breakdown</h2>
        <div style="background:#141414;border:1px solid #333;border-radius:8px;padding:16px;margin-bottom:32px;">
            {sev_bars}
        </div>

        <h2>Findings</h2>
        <table>
            <thead>
                <tr>
                    <th style="width:90px;">Severity</th>
                    <th style="width:180px;">Finding</th>
                    <th>Description</th>
                    <th style="width:200px;">Evidence</th>
                    <th style="width:200px;">Mitigation</th>
                </tr>
            </thead>
            <tbody>{finding_rows}</tbody>
        </table>

        <div class="footer">
            REDNERVE &mdash; AI-Powered Red Team Platform | Auto-generated with AI-assisted mitigations | {now}
        </div>
    </div>
</body>
</html>"""

        return html

    async def _mark_failed(self, report_id: str, error: str):
        async with async_session() as db:
            report = await db.get(Report, report_id)
            if report:
                report.status = "failed"
                report.error_message = error
                report.completed_at = datetime.now(timezone.utc)
                await db.commit()
        await self._emit_status(report_id, "failed", error)

    async def _emit_status(self, report_id: str, status: str, message: str = ""):
        if self._sio:
            try:
                await self._sio.emit("report_status", {
                    "id": report_id,
                    "status": status,
                    "message": message,
                })
            except Exception:
                pass

    async def list_reports(self) -> list[dict]:
        async with async_session() as db:
            from sqlalchemy import select
            result = await db.execute(
                select(Report).order_by(Report.created_at.desc())
            )
            reports = result.scalars().all()
            return [{
                "id": r.id,
                "status": r.status,
                "title": r.title,
                "finding_count": r.finding_count,
                "error_message": r.error_message,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            } for r in reports]

    async def get_report_file_path(self, report_id: str) -> str | None:
        async with async_session() as db:
            report = await db.get(Report, report_id)
            if report and report.file_path and os.path.exists(report.file_path):
                return report.file_path
            return None


def _esc(text: str) -> str:
    """HTML-escape a string."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


report_service = ReportService()
