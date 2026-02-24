#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CHOMBEZA - Professional VAPT/Bug Bounty Report Generator
- Generates ONE consolidated Acunetix-style report per scan (HTML + PDF + JSON + CSV)
- Colorful but professional template
- Includes CVSS, Impact, Remediation, Evidence/PoC, Request/Response, screenshots
- WeasyPrint PDF (preferred) with ReportLab fallback (always readable)

Note: To ensure only ONE report per scan, Scanner should call finalize_report() once at scan end
with a stable report_id. This module only generates one report per report_id call.
"""

import os
import csv
import json
import time
import base64
import logging
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger("CHOMBEZA.Report")

# ---- Optional WeasyPrint (best PDF quality) ----
try:
    import weasyprint  # type: ignore
    HAS_WEASYPRINT = True
except Exception:
    weasyprint = None
    HAS_WEASYPRINT = False

# ---- ReportLab fallback (always works, FOSS) ----
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import cm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, PageBreak,
        Table, TableStyle
    )
    HAS_REPORTLAB = True
except Exception:
    HAS_REPORTLAB = False


DEFAULT_AUTHOR = "@arch_nexus707"
DEFAULT_CLASSIFICATION = "CONFIDENTIAL"
DEFAULT_TEMPLATE_NAME = "report_vapt_pro.html"


def _now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except Exception:
        return default


def _norm_sev(sev: str) -> str:
    s = (sev or "info").strip().lower()
    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
    }
    return mapping.get(s, "info")


def _guess_category(name: str) -> str:
    n = (name or "").lower()
    rules = [
        ("Injection", ["sqli", "sql injection", "ssti", "template injection", "command injection", "rce", "os command"]),
        ("XSS", ["xss", "cross-site scripting", "dom xss"]),
        ("Auth & Session", ["auth", "session", "jwt", "token", "oauth", "mfa", "password", "login", "bruteforce"]),
        ("File / Path", ["lfi", "rfi", "path traversal", "directory traversal", "file inclusion"]),
        ("SSRF / XXE", ["ssrf", "xxe"]),
        ("Access Control", ["idor", "access control", "privilege", "authorization", "bypass"]),
        ("Misconfiguration", ["misconfig", "config", "debug", "cors", "headers", "tls", "ssl"]),
        ("Info Disclosure", ["info disclosure", "disclosure", "leak", "sensitive", "exposed"]),
        ("CSRF", ["csrf", "xsrf"]),
        ("Business Logic", ["business logic", "workflow", "race condition"]),
        ("Other", []),
    ]
    for cat, keys in rules:
        for k in keys:
            if k in n:
                return cat
    return "Other"


def _estimate_cvss(sev: str, name: str = "") -> Tuple[float, str]:
    """
    Free heuristic. If you later add real CVSS vectoring, plug it here.
    """
    s = _norm_sev(sev)
    n = (name or "").lower()

    if any(k in n for k in ["rce", "remote code", "command injection", "deserialization"]):
        return 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    if any(k in n for k in ["sql injection", "sqli"]):
        return 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L"
    if "ssrf" in n:
        return 8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
    if any(k in n for k in ["xss", "cross-site scripting", "dom xss"]):
        return 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    if any(k in n for k in ["lfi", "path traversal", "directory traversal"]):
        return 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"

    if s == "critical":
        return 9.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    if s == "high":
        return 8.0, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L"
    if s == "medium":
        return 6.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N"
    if s == "low":
        return 3.7, "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"
    return 0.0, "N/A"


def _default_impact(sev: str) -> str:
    s = _norm_sev(sev)
    if s == "critical":
        return "Critical risk: may enable full compromise, data breach, or service disruption."
    if s == "high":
        return "High risk: may enable unauthorized access, sensitive data exposure, or account compromise."
    if s == "medium":
        return "Moderate risk: may support targeted attacks or vulnerability chaining under certain conditions."
    if s == "low":
        return "Low risk: limited direct impact but could assist attackers in reconnaissance or chaining."
    return "Informational: improves security posture when addressed."


def _default_remediation(name: str) -> str:
    n = (name or "").lower()
    if "xss" in n:
        return "Apply output encoding, validate/normalize input, and enforce strict CSP."
    if "sql" in n or "sqli" in n:
        return "Use parameterized queries/prepared statements, validate inputs, and least-privilege DB access."
    if "ssti" in n or "template injection" in n:
        return "Avoid rendering untrusted templates, use safe templating APIs, and validate template inputs."
    if "lfi" in n or "path traversal" in n:
        return "Normalize/validate file paths, use allowlists, and avoid user input in filesystem operations."
    if "rce" in n or "command injection" in n:
        return "Remove shell invocation with user input, use safe APIs, validate inputs, sandbox where required."
    if "ssrf" in n:
        return "Block internal ranges, enforce allowlists for outbound requests, validate/normalize URLs."
    if "csrf" in n:
        return "Use anti-CSRF tokens, SameSite cookies, and validate origin/referrer."
    return "Apply input validation, output encoding, least privilege, and defense-in-depth."


def _risk_score(stats: Dict[str, int]) -> Tuple[int, str]:
    c = _safe_int(stats.get("critical", 0))
    h = _safe_int(stats.get("high", 0))
    m = _safe_int(stats.get("medium", 0))
    l = _safe_int(stats.get("low", 0))
    i = _safe_int(stats.get("info", 0))

    raw = c * 10 + h * 7 + m * 4 + l * 2 + i * 1
    score = min(100, int(round(raw * 2)))
    if score >= 85:
        label = "CRITICAL"
    elif score >= 65:
        label = "HIGH"
    elif score >= 40:
        label = "MEDIUM"
    elif score >= 15:
        label = "LOW"
    else:
        label = "INFO"
    return score, label


def _mime_from_path(path: str) -> str:
    p = path.lower()
    if p.endswith(".png"):
        return "image/png"
    if p.endswith(".jpg") or p.endswith(".jpeg"):
        return "image/jpeg"
    if p.endswith(".webp"):
        return "image/webp"
    return "application/octet-stream"


def _read_b64_data_uri(file_path: str) -> Optional[str]:
    try:
        f = Path(file_path)
        if not f.exists() or not f.is_file():
            return None
        mime = _mime_from_path(str(f))
        data = f.read_bytes()
        b64 = base64.b64encode(data).decode("ascii")
        return f"data:{mime};base64,{b64}"
    except Exception:
        return None


class ReportGenerator:
    def __init__(self, output_dir: str = "reports", template_dir: str = "templates"):
        self.output_dir = Path(output_dir)
        self.template_dir = Path(template_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.template_dir.mkdir(parents=True, exist_ok=True)
        self._setup_templates()

        self.env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=select_autoescape(["html", "xml"])
        )

    def _setup_templates(self) -> None:
        tmpl_path = self.template_dir / DEFAULT_TEMPLATE_NAME
        if tmpl_path.exists():
            return
        tmpl_path.write_text(
            "<html><body><h1>CHOMBEZA Report</h1><p>Template missing.</p></body></html>",
            encoding="utf-8"
        )

    def _report_basename(self, report_id: Optional[Any] = None) -> str:
        rid = report_id if report_id is not None else int(time.time())
        return f"CHOMBEZA_Report_{rid}"

    def _enrich(self, data: Dict[str, Any]) -> Dict[str, Any]:
        d = dict(data or {})
        d.setdefault("generated_at", _now_str())
        d.setdefault("author", DEFAULT_AUTHOR)
        d.setdefault("classification", DEFAULT_CLASSIFICATION)
        d.setdefault("scope", d.get("target", "") or "N/A")
        d.setdefault("assessor", "CHOMBEZA Security Team")
        d.setdefault("methodology", "Automated security testing with CHOMBEZA. Manual verification is recommended for Critical/High findings.")

        vulns = d.get("vulnerabilities", []) or []
        stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
        enriched = []

        for idx, v in enumerate(vulns, start=1):
            vv = dict(v or {})
            vv["idx"] = idx
            vv["name"] = vv.get("name") or "Unnamed Finding"
            vv["severity"] = _norm_sev(vv.get("severity", "info"))
            vv["url"] = vv.get("url") or vv.get("endpoint") or "N/A"
            vv["parameter"] = vv.get("parameter") or "N/A"
            vv["description"] = vv.get("description") or ""
            vv["evidence"] = vv.get("evidence") or vv.get("proof") or vv.get("poc") or ""
            vv["recommendation"] = vv.get("recommendation") or ""

            vv["category"] = vv.get("category") or _guess_category(vv["name"])
            vv["cwe_id"] = vv.get("cwe_id") or "CWE-000"

            rr = vv.get("request_response")
            vv["request_raw"] = ""
            vv["response_raw"] = ""
            if isinstance(rr, dict):
                vv["request_raw"] = rr.get("request", "") or rr.get("raw_request", "") or ""
                vv["response_raw"] = rr.get("response", "") or rr.get("raw_response", "") or ""
            elif isinstance(rr, str):
                vv["request_raw"] = rr

            cvss_val = vv.get("cvss")
            cvss_vector = vv.get("cvss_vector")
            if isinstance(cvss_val, dict):
                cvss_score = _safe_float(cvss_val.get("score", 0.0))
                cvss_vector = cvss_val.get("vector", cvss_vector or "N/A")
            else:
                cvss_score = _safe_float(cvss_val, 0.0)

            if cvss_score <= 0.0:
                cvss_score, vec = _estimate_cvss(vv["severity"], vv["name"])
                cvss_vector = cvss_vector or vec

            vv["cvss_score"] = round(cvss_score, 1) if cvss_score else 0.0
            vv["cvss_vector"] = cvss_vector or "N/A"

            vv["impact"] = vv.get("impact") or _default_impact(vv["severity"])
            if not vv["recommendation"]:
                vv["recommendation"] = _default_remediation(vv["name"])

            vv["poc_steps"] = vv.get("poc_steps") or [
                f"Navigate to: {vv['url']}",
                f"Inject/test parameter: {vv['parameter']}",
                "Observe response behavior/evidence as noted."
            ]

            shots = []
            candidates = []
            if vv.get("screenshot"):
                candidates.append(vv.get("screenshot"))
            if isinstance(vv.get("screenshots"), list):
                candidates.extend([x for x in vv.get("screenshots") if x])

            
            for c in candidates:
                if not c:
                    continue

                # 1) Dict entries from screenshot module
                if isinstance(c, dict):
                    data = c.get("data") or c.get("data_uri") or c.get("dataUrl")
                    cap = c.get("caption") or c.get("name") or "Screenshot"
                    if isinstance(data, str) and data:
                        if not data.startswith("data:image/"):
                            # assume PNG when raw b64
                            data = "data:image/png;base64," + data
                        shots.append({"data_uri": data, "caption": cap})
                    else:
                        # If only path is present
                        p = c.get("path")
                        if isinstance(p, str) and os.path.exists(p):
                            uri = _read_b64_data_uri(p)
                            if uri:
                                shots.append({"data_uri": uri, "caption": Path(p).name})
                    continue

                # 2) String entries (data-uri, file path, or raw base64)
                if isinstance(c, str):
                    if c.startswith("data:image/"):
                        shots.append({"data_uri": c, "caption": "Screenshot"})
                        continue
                    if os.path.exists(c):
                        uri = _read_b64_data_uri(c)
                        if uri:
                            shots.append({"data_uri": uri, "caption": Path(c).name})
                        continue
                    # Raw base64 (from older builds)
                    if len(c) > 80:
                        shots.append({"data_uri": "data:image/png;base64," + c, "caption": "Screenshot"})
                        continue

            vv["screenshots_embedded"] = shots

            stats[vv["severity"]] += 1
            stats["total"] += 1
            enriched.append(vv)

        d["vulnerabilities"] = enriched
        d["stats"] = stats

        score, label = _risk_score(stats)
        d["risk_score"] = score
        d["risk_label"] = label

        heatmap = {}
        for v in enriched:
            cat = v["category"]
            heatmap.setdefault(cat, {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
            heatmap[cat][v["severity"]] += 1
        rows = []
        for cat in sorted(heatmap.keys()):
            row = {"category": cat, "cells": heatmap[cat], "total": sum(heatmap[cat].values())}
            rows.append(row)
        d["heatmap_rows"] = rows

        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        d["vulnerabilities_sorted"] = sorted(enriched, key=lambda x: (sev_order.get(x["severity"], 9), -_safe_float(x.get("cvss_score", 0.0))))

        d["roadmap"] = []
        if stats["critical"] > 0:
            d["roadmap"].append({"priority":"P0","sla":"24-72 hours","effort":"High","title":"Remediate Critical Findings","detail":"Address Critical findings immediately."})
        if stats["high"] > 0:
            d["roadmap"].append({"priority":"P1","sla":"7 days","effort":"Medium","title":"Fix High Risk Vulnerabilities","detail":"Apply secure coding controls and patches."})
        if stats["medium"] > 0:
            d["roadmap"].append({"priority":"P2","sla":"30 days","effort":"Low-Med","title":"Resolve Medium Findings","detail":"Reduce attack surface and chaining risk."})
        if stats["low"] > 0 or stats["info"] > 0:
            d["roadmap"].append({"priority":"P3","sla":"60-90 days","effort":"Low","title":"Hardening & Hygiene","detail":"Headers, logging, least privilege, monitoring."})

        d["attack_narrative"] = [
            "Automated endpoint discovery and parameter analysis across the target scope.",
            "Payload-driven testing executed against parameters and forms to identify input validation weaknesses.",
            "Confirmed findings captured with evidence, request/response traces, and screenshots where possible.",
            "Remediation priorities assigned focusing on Critical and High findings first."
        ] if enriched else []

        return d

    def generate_html(self, data: Dict[str, Any], report_id: Optional[Any] = None, template_name: str = DEFAULT_TEMPLATE_NAME) -> Optional[str]:
        try:
            base = self._report_basename(report_id)
            out_path = self.output_dir / f"{base}.html"
            d = self._enrich(data)
            d["report_id"] = report_id if report_id is not None else base.split("_")[-1]
            d["report_basename"] = base
            template = self.env.get_template(template_name)
            html = template.render(**d)
            out_path.write_text(html, encoding="utf-8")
            logger.info("HTML report generated: %s", out_path)
            return str(out_path)
        except Exception as e:
            logger.exception("Failed to generate HTML report: %s", e)
            return None

    def generate_json(self, data: Dict[str, Any], report_id: Optional[Any] = None) -> Optional[str]:
        try:
            base = self._report_basename(report_id)
            out_path = self.output_dir / f"{base}.json"
            d = self._enrich(data)
            out_path.write_text(json.dumps(d, indent=2, ensure_ascii=False), encoding="utf-8")
            logger.info("JSON report generated: %s", out_path)
            return str(out_path)
        except Exception as e:
            logger.exception("Failed to generate JSON report: %s", e)
            return None

    def generate_csv(self, data: Dict[str, Any], report_id: Optional[Any] = None) -> Optional[str]:
        try:
            base = self._report_basename(report_id)
            out_path = self.output_dir / f"{base}.csv"
            d = self._enrich(data)
            rows = d.get("vulnerabilities_sorted", []) or d.get("vulnerabilities", [])
            fields = ["idx","name","severity","cvss_score","cvss_vector","category","cwe_id","url","parameter","impact","recommendation"]
            with out_path.open("w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=fields)
                w.writeheader()
                for r in rows:
                    w.writerow({k: r.get(k, "") for k in fields})
            logger.info("CSV report generated: %s", out_path)
            return str(out_path)
        except Exception as e:
            logger.exception("Failed to generate CSV report: %s", e)
            return None

    def generate_pdf(self, html_path: str, data: Optional[Dict[str, Any]] = None, report_id: Optional[Any] = None) -> Optional[str]:
        try:
            base = self._report_basename(report_id) if report_id is not None else Path(html_path).stem
            out_path = self.output_dir / f"{base}.pdf"

            if HAS_WEASYPRINT and weasyprint is not None:
                try:
                    weasyprint.HTML(filename=str(html_path), base_url=str(Path(html_path).parent)).write_pdf(str(out_path))
                    logger.info("PDF report generated (WeasyPrint): %s", out_path)
                    return str(out_path)
                except Exception as e:
                    logger.warning("WeasyPrint PDF failed, falling back to ReportLab: %s", e)

            if HAS_REPORTLAB and data is not None:
                self._generate_pdf_reportlab(out_path=str(out_path), data=self._enrich(data))
                logger.info("PDF report generated (ReportLab fallback): %s", out_path)
                return str(out_path)

            logger.error("PDF generation failed: WeasyPrint unavailable/failed and ReportLab fallback not possible.")
            return None

        except Exception as e:
            logger.exception("Failed to generate PDF report: %s", e)
            return None

    def _generate_pdf_reportlab(self, out_path: str, data: Dict[str, Any]) -> None:
        if not HAS_REPORTLAB:
            raise RuntimeError("ReportLab is not available")

        styles = getSampleStyleSheet()
        title = styles["Title"]
        h2 = styles["Heading2"]
        h3 = styles["Heading3"]
        body = styles["BodyText"]

        mono = ParagraphStyle("MonoSmall", parent=styles["BodyText"], fontName="Courier", fontSize=8, leading=10)

        doc = SimpleDocTemplate(out_path, pagesize=A4,
                                leftMargin=1.6*cm, rightMargin=1.6*cm,
                                topMargin=1.8*cm, bottomMargin=1.8*cm)

        story = []
        story.append(Paragraph("CHOMBEZA - VAPT / Bug Bounty Report", title))
        story.append(Paragraph(f"<b>Target:</b> {data.get('target','N/A')}", body))
        story.append(Paragraph(f"<b>Classification:</b> {data.get('classification', DEFAULT_CLASSIFICATION)}", body))
        story.append(Paragraph(f"<b>Generated:</b> {data.get('generated_at','')}", body))
        story.append(Paragraph(f"<b>Author:</b> {data.get('author', DEFAULT_AUTHOR)}", body))
        story.append(Spacer(1, 12))

        stats = data.get("stats", {})
        story.append(Paragraph("Executive Summary", h2))
        story.append(Paragraph(
            f"Total findings: <b>{stats.get('total',0)}</b> "
            f"(Critical {stats.get('critical',0)}, High {stats.get('high',0)}, "
            f"Medium {stats.get('medium',0)}, Low {stats.get('low',0)}, Info {stats.get('info',0)})",
            body
        ))
        story.append(Paragraph(
            f"Overall Risk Score: <b>{data.get('risk_score',0)}</b> ({data.get('risk_label','INFO')})",
            body
        ))
        story.append(Spacer(1, 10))

        story.append(Paragraph("Remediation Roadmap", h2))
        for r in data.get("roadmap", []):
            story.append(Paragraph(
                f"<b>{r.get('priority')}</b> - {r.get('title')} (SLA: {r.get('sla')}, Effort: {r.get('effort')})<br/>{r.get('detail')}",
                body
            ))
            story.append(Spacer(1, 6))

        story.append(PageBreak())

        story.append(Paragraph("Findings Summary", h2))
        rows = [["#", "Severity", "CVSS", "Finding", "URL"]]
        for v in data.get("vulnerabilities_sorted", []):
            rows.append([
                str(v.get("idx")),
                v.get("severity", "").upper(),
                str(v.get("cvss_score", "")),
                (v.get("name", "")[:60] + ("…" if len(v.get("name","")) > 60 else "")),
                (v.get("url", "")[:55] + ("…" if len(v.get("url","")) > 55 else "")),
            ])
        tbl = Table(rows, colWidths=[1.0*cm, 2.2*cm, 1.5*cm, 7.5*cm, 5.2*cm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#111827")),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE", (0,0), (-1,0), 9),
            ("GRID", (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ("FONTSIZE", (0,1), (-1,-1), 8),
            ("VALIGN", (0,0), (-1,-1), "TOP"),
        ]))
        story.append(tbl)
        story.append(PageBreak())

        story.append(Paragraph("Detailed Findings", h2))
        for v in data.get("vulnerabilities_sorted", []):
            story.append(Paragraph(f"{v.get('idx')}. {v.get('name')}", h3))
            story.append(Paragraph(f"<b>Severity:</b> {v.get('severity','').upper()} | <b>CVSS:</b> {v.get('cvss_score','')} | <b>CWE:</b> {v.get('cwe_id','')}", body))
            story.append(Paragraph(f"<b>Category:</b> {v.get('category','Other')}", body))
            story.append(Paragraph(f"<b>Affected URL:</b> {v.get('url','N/A')}", body))
            story.append(Paragraph(f"<b>Parameter:</b> {v.get('parameter','N/A')}", body))
            story.append(Spacer(1, 6))

            if v.get("description"):
                story.append(Paragraph("<b>Description</b>", body))
                story.append(Paragraph(v.get("description"), body))
                story.append(Spacer(1, 6))

            story.append(Paragraph("<b>Impact</b>", body))
            story.append(Paragraph(v.get("impact",""), body))
            story.append(Spacer(1, 6))

            story.append(Paragraph("<b>Remediation</b>", body))
            story.append(Paragraph(v.get("recommendation",""), body))
            story.append(Spacer(1, 6))

            if v.get("evidence"):
                story.append(Paragraph("<b>Evidence / PoC</b>", body))
                story.append(Paragraph(v.get("evidence",""), body))
                story.append(Spacer(1, 6))

            req = (v.get("request_raw","") or "").strip()
            resp = (v.get("response_raw","") or "").strip()
            if req:
                story.append(Paragraph("<b>Request</b>", body))
                story.append(Paragraph(f"<pre>{self._escape_for_pre(req[:6000])}</pre>", mono))
                story.append(Spacer(1, 6))
            if resp:
                story.append(Paragraph("<b>Response</b>", body))
                story.append(Paragraph(f"<pre>{self._escape_for_pre(resp[:6000])}</pre>", mono))
                story.append(Spacer(1, 10))

            story.append(Spacer(1, 10))

        story.append(PageBreak())
        story.append(Paragraph("Appendix", h2))
        story.append(Paragraph(data.get("methodology", ""), body))
        story.append(Spacer(1, 12))
        story.append(Paragraph(f"Generated by CHOMBEZA • Author: {data.get('author', DEFAULT_AUTHOR)}", body))

        doc.build(story)

    @staticmethod
    def _escape_for_pre(text: str) -> str:
        return (text.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;"))
