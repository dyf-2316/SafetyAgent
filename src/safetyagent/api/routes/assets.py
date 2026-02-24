"""API routes for Asset Scanning."""

import asyncio
import threading
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

# Import from internal asset_scanner module
try:
    from safetyagent.asset_scanner import AssetScanner
except ImportError:
    AssetScanner = None

router = APIRouter()

# --------------- In-memory scan task store ---------------
# {scan_id: { status, scanner, scanned_count, ignored_count, error, result }}
_scan_tasks: dict[str, dict] = {}


# Pydantic schemas
class ScanRequest(BaseModel):
    """Request schema for asset scanning."""

    path: str | None = Field(None, description="Specific path to scan (default: full system scan)")
    max_depth: int | None = Field(None, ge=1, le=500, description="Maximum scan depth")
    scan_system_root: bool = Field(True, description="Whether to scan system root directory")


class AssetDetail(BaseModel):
    """Detail info for a single scanned asset."""

    path: str
    file_type: str
    owner: str
    risk_level: int
    size: int | None = None
    direct_size: int | None = None
    permissions: str | None = None
    real_path: str | None = None
    resolved_risk: int | None = None
    metadata: dict | None = None


class RiskGroupDetail(BaseModel):
    """Assets grouped under a single risk level."""

    count: int
    percentage: float
    description: str
    assets: list[AssetDetail] = []          # first N items
    total_in_level: int = 0                 # total items for this level


class ScanResponse(BaseModel):
    """Response schema for scan results."""

    status: str
    total_scanned: int
    total_ignored: int
    total_assets: int
    risk_distribution: dict[str, RiskGroupDetail]
    message: str


class HardwareScanResponse(BaseModel):
    """Response schema for hardware scan."""

    status: str
    hardware_info: dict
    message: str


class RiskLevelStats(BaseModel):
    """Statistics for a specific risk level."""

    count: int
    percentage: float
    description: str


class AssetListResponse(BaseModel):
    """Response schema for asset listing."""

    assets: list[dict]
    total: int
    risk_level: int | None
    description: str


def _build_scan_response(scanner: "AssetScanner", assets: list, per_level_limit: int = 200) -> dict:
    """Build the ScanResponse dict from scanner + assets (reusable helper)."""
    summary = scanner.get_scan_summary()

    descriptions = {
        0: "Operating System Core and Applications",
        1: "Sensitive Credentials",
        2: "User Data",
        3: "Cleanable Content",
    }

    risk_stats: dict[str, dict] = {}
    for level in range(4):
        level_assets = [a for a in assets if a.risk_level == level]
        count = len(level_assets)
        percentage = (count / len(assets) * 100) if assets else 0

        detail_list = []
        for a in level_assets[:per_level_limit]:
            d = a.to_dict()
            detail_list.append({
                "path": d["path"],
                "file_type": d["file_type"],
                "owner": d["owner"],
                "risk_level": d["risk_level"],
                "size": d.get("size"),
                "direct_size": d.get("direct_size"),
                "permissions": d.get("permissions"),
                "real_path": d.get("real_path"),
                "resolved_risk": d.get("resolved_risk"),
                "metadata": d.get("metadata"),
            })

        risk_stats[f"LEVEL_{level}"] = {
            "count": count,
            "percentage": round(percentage, 2),
            "description": descriptions[level],
            "assets": detail_list,
            "total_in_level": count,
        }

    return {
        "status": "completed",
        "total_scanned": summary["scanned_count"],
        "total_ignored": summary["ignored_count"],
        "total_assets": len(assets),
        "risk_distribution": risk_stats,
        "message": f"Successfully scanned {summary['scanned_count']} items",
    }


def _run_scan_sync(scan_id: str, request_path: str | None, max_depth: int, scan_system_root: bool):
    """Run the scan in a background thread; updates _scan_tasks in-place."""
    task = _scan_tasks[scan_id]
    scanner: AssetScanner = task["scanner"]
    try:
        if request_path:
            assets = scanner.scan_assets(
                target_path=Path(request_path),
                max_depth=max_depth,
                scan_system_root=False,
            )
        else:
            assets = scanner.scan_assets(
                max_depth=max_depth,
                scan_system_root=scan_system_root,
            )
        task["result"] = _build_scan_response(scanner, assets)
        task["status"] = "completed"
    except Exception as e:
        task["status"] = "failed"
        task["error"] = str(e)


@router.post("/scan")
async def scan_assets(request: ScanRequest) -> Any:
    """
    Start an async asset scan. Returns a scan_id immediately.
    Use GET /scan/progress?scan_id=xxx to poll progress.
    """
    if AssetScanner is None:
        raise HTTPException(
            status_code=500,
            detail="Asset Scanner module not available. Please check installation.",
        )

    scan_id = uuid.uuid4().hex[:12]
    scanner = AssetScanner()

    _scan_tasks[scan_id] = {
        "status": "running",
        "scanner": scanner,
        "result": None,
        "error": None,
    }

    # Launch scan in a background thread (non-blocking)
    thread = threading.Thread(
        target=_run_scan_sync,
        args=(scan_id, request.path, request.max_depth or 200, request.scan_system_root),
        daemon=True,
    )
    thread.start()

    return {"scan_id": scan_id, "status": "running", "message": "Scan started"}


@router.get("/scan/progress")
async def scan_progress(scan_id: str = Query(..., description="Scan task ID")) -> Any:
    """
    Poll the progress of a running scan.

    Returns:
    - status: running | completed | failed
    - scanned_count / ignored_count: live counters
    - result: full ScanResponse when completed
    """
    task = _scan_tasks.get(scan_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Scan task not found")

    scanner: AssetScanner = task["scanner"]

    resp: dict[str, Any] = {
        "scan_id": scan_id,
        "status": task["status"],
        "scanned_count": scanner.scanned_count,
        "ignored_count": scanner.ignored_count,
    }

    if task["status"] == "completed":
        resp["result"] = task["result"]
        # Clean up old tasks to avoid memory leak (keep last 5)
        _cleanup_old_tasks(scan_id)
    elif task["status"] == "failed":
        resp["error"] = task["error"]
        _cleanup_old_tasks(scan_id)

    return resp


def _cleanup_old_tasks(keep_id: str):
    """Remove old completed/failed tasks, keep at most 5."""
    finished = [k for k, v in _scan_tasks.items() if v["status"] in ("completed", "failed") and k != keep_id]
    for old_id in finished[:-4]:  # keep the 4 most recent + current
        _scan_tasks.pop(old_id, None)


@router.get("/hardware", response_model=HardwareScanResponse)
async def scan_hardware() -> Any:
    """
    Scan system hardware information.
    
    Collects comprehensive hardware information including:
    - CPU (model, cores, usage)
    - Memory (total, used, free)
    - Disk (all partitions)
    - GPU (if available)
    - System info (OS, architecture, hostname)
    """
    if AssetScanner is None:
        raise HTTPException(
            status_code=500,
            detail="Asset Scanner module not available."
        )
    
    try:
        scanner = AssetScanner()
        hardware_asset = scanner.scan_hardware_info()
        
        if hardware_asset is None:
            raise HTTPException(
                status_code=500,
                detail="Hardware scan returned no data."
            )
        
        return HardwareScanResponse(
            status="completed",
            hardware_info=hardware_asset.to_dict(),
            message="Hardware scan completed successfully"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Hardware scan failed: {str(e)}")


@router.get("/risk-level/{level}", response_model=AssetListResponse)
async def get_assets_by_risk_level(
    level: int,
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of assets to return"),
) -> Any:
    """
    Get assets by risk level.
    
    Returns a list of assets for a specific risk level.
    Note: This requires a recent scan to have been performed.
    """
    if AssetScanner is None:
        raise HTTPException(status_code=500, detail="Asset Scanner module not available.")
    
    descriptions = {
        0: "Operating System Core and Applications (Red)",
        1: "Sensitive Credentials (Orange)",
        2: "User Data (Yellow)",
        3: "Cleanable Content (Green)"
    }
    
    # Check if scan results exist
    level_file = Path(f"level_{level}.json")
    if not level_file.exists():
        raise HTTPException(
            status_code=404,
            detail=f"No scan results found. Please run /scan first."
        )
    
    try:
        import json
        with open(level_file, 'r', encoding='utf-8') as f:
            assets = json.load(f)
        
        # Limit results
        limited_assets = assets[:limit]
        
        return AssetListResponse(
            assets=limited_assets,
            total=len(assets),
            risk_level=level,
            description=descriptions[level]
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load assets: {str(e)}")


@router.get("/assess-path")
async def assess_path_risk(
    path: str = Query(..., description="File or directory path to assess")
) -> dict:
    """
    Assess the risk level of a specific path.
    
    Quick risk assessment without performing a full scan.
    Useful for checking if an Agent can safely access/modify a path.
    """
    if AssetScanner is None:
        raise HTTPException(status_code=500, detail="Asset Scanner module not available.")
    
    try:
        scanner = AssetScanner()
        file_path = Path(path)
        
        if not file_path.exists():
            raise HTTPException(status_code=404, detail=f"Path not found: {path}")
        
        risk_level = scanner.assess_risk_level(file_path)
        
        risk_descriptions = {
            0: {
                "level": "LEVEL_0",
                "color": "red",
                "label": "Critical System File",
                "recommendation": "DO NOT modify or delete",
                "safety": "dangerous"
            },
            1: {
                "level": "LEVEL_1",
                "color": "orange",
                "label": "Sensitive Credential",
                "recommendation": "DO NOT access or share",
                "safety": "dangerous"
            },
            2: {
                "level": "LEVEL_2",
                "color": "yellow",
                "label": "User Data",
                "recommendation": "Use caution when modifying",
                "safety": "caution"
            },
            3: {
                "level": "LEVEL_3",
                "color": "green",
                "label": "Cleanable Content",
                "recommendation": "Safe to delete or modify",
                "safety": "safe"
            }
        }
        
        result = risk_descriptions[int(risk_level)]
        result["path"] = str(file_path)
        result["risk_level"] = int(risk_level)
        result["is_file"] = file_path.is_file()
        result["is_directory"] = file_path.is_dir()
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Assessment failed: {str(e)}")


@router.get("/stats/overview")
async def get_scan_overview() -> dict:
    """
    Get overview of the most recent scan.
    
    Returns statistics from the last full scan including:
    - Total items scanned
    - Risk level distribution
    - System information
    """
    full_scan_file = Path("full_scan.json")
    
    if not full_scan_file.exists():
        raise HTTPException(
            status_code=404,
            detail="No scan results found. Please run /scan first."
        )
    
    try:
        import json
        with open(full_scan_file, 'r', encoding='utf-8') as f:
            report = json.load(f)
        
        return {
            "status": "available",
            "report_metadata": report.get("report_metadata", {}),
            "scan_summary": report.get("scan_summary", {}),
            "risk_statistics": report.get("risk_statistics", {}),
            "hardware_available": "hardware_assets" in report
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load overview: {str(e)}")
