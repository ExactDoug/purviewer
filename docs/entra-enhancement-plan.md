# Purviewer Entra Sign-In Analysis Enhancement Plan

**Created**: November 21, 2025
**Updated**: November 21, 2025
**Status**: v0.5.0 Complete (ML + GeoIP)
**Priority**: High - Addresses critical gaps identified in market analysis

---

## Executive Summary

Based on comprehensive market research, Purviewer is the **only existing Python tool** that analyzes exported Entra ID sign-in logs offline. However, it lacks critical forensic capabilities needed for breach investigation. This plan adds those missing features.

**Reference**: See `entra-signin-log-analysis-tools-reference.md` for full gap analysis.

---

## Implementation Status

### v0.4.0 MVP - COMPLETED

| Phase | Component | Status | Notes |
|-------|-----------|--------|-------|
| 1 | Data Foundation | ✅ Complete | `data_loader.py`, `field_extractor.py` |
| 2 | Baseline Profiling | ✅ Complete | `baseline.py` with UserBaseline class |
| 3.1 | Impossible Travel | ✅ Complete | Haversine distance, 900 km/h threshold |
| 3.2 | New Location | ✅ Complete | Country/city/IP detection |
| 3.3 | New Device | ✅ Complete | OS/browser/deviceId detection |
| 3.4 | Failure Spike | ✅ Complete | Z-score based (3σ default) |
| 6 | First Compromise | ✅ Complete | Multi-heuristic with confidence scoring |
| 7 | Reporting | ✅ Complete | Markdown + CSV export |
| - | CLI Integration | ✅ Complete | 4 new arguments |
| - | Test Fixtures | ✅ Complete | `tests/fixtures/entra_signin_sample.json` |

### v0.5.0 - COMPLETED

| Phase | Component | Status | Notes |
|-------|-----------|--------|-------|
| 4 | GeoIP Integration | ✅ Complete | `geoip.py` with MaxMind + city fallback |
| 5.1 | ML Feature Engineering | ✅ Complete | `ml/features.py` with cyclical encoding |
| 5.2 | Isolation Forest | ✅ Complete | `ml/anomaly_model.py` per-user models |
| 7+ | JSON Report Format | ✅ Complete | Full report in JSON format |
| - | CLI Integration | ✅ Complete | `--entra-ml-detect`, `--entra-report-json` |

---

## Current Capabilities

### v0.4.0 Features

✅ **Data Loading**
- JSON and CSV export support
- Multiple encoding detection (UTF-8, ISO-8859-1, CP1252)
- Nested field extraction (location, status, deviceDetail)
- Timestamp parsing to datetime objects

✅ **Baseline Profiling**
- Per-user baseline calculation
- Top IPs, countries, cities, OS, browsers
- Typical sign-in hours
- Device ID tracking

✅ **Anomaly Detection**
- Impossible travel (geographic distance vs time)
- New location (country, city, IP)
- New device (OS, browser, device ID)
- Failed login spikes (z-score based)

✅ **First Compromise Identification**
- High-confidence: First risky successful login
- Medium-confidence: Success after failures from new IP
- Medium-confidence: Success after impossible travel
- Low-confidence: First login from new country

✅ **Reporting**
- Markdown incident reports with executive summary
- CSV export of all anomalies
- Per-user analysis option

✅ **CLI Arguments**
```bash
--entra-anomalies              # Enable anomaly detection
--entra-user USER              # Analyze specific user
--entra-report-md FILE         # Generate markdown report
--entra-export-anomalies FILE  # Export anomalies to CSV
--entra-ml-detect              # Enable ML-based detection (v0.5.0)
--entra-report-json FILE       # Generate JSON report (v0.5.0)
```

---

## File Structure (Current)

```
src/purviewer/entra/
├── __init__.py               # Module exports
├── entra_ops.py              # Original: Basic CSV analysis
├── analyzer.py               # Main orchestrator (updated v0.5.0)
├── data_loader.py            # JSON/CSV loading
├── field_extractor.py        # Nested field parsing
├── baseline.py               # Per-user baseline profiling
├── first_compromise.py       # Breach identification
├── reporting.py              # Report generation (JSON added v0.5.0)
├── geoip.py                  # NEW v0.5.0: GeoIP service
├── detectors/
│   ├── __init__.py
│   ├── impossible_travel.py  # Geographic anomaly (GeoIP v0.5.0)
│   ├── new_location.py       # Country/city changes
│   ├── new_device.py         # Device changes
│   └── failure_spike.py      # Failed login spikes
└── ml/                       # NEW v0.5.0
    ├── __init__.py
    ├── features.py           # Feature engineering
    └── anomaly_model.py      # Isolation Forest detector

tests/fixtures/
└── entra_signin_sample.json  # Test data with scenarios
```

---

## Usage Examples

### Basic Anomaly Detection
```bash
purviewer signin_logs.json --entra-anomalies
```

### Full Analysis with Reports
```bash
purviewer signin_logs.json --entra-anomalies \
  --entra-user john.doe@contoso.com \
  --entra-report-md incident_report.md \
  --entra-export-anomalies anomalies.csv
```

### Sample Output
```
=== Entra Anomaly Analysis Summary ===

Total sign-ins: 8
Users analyzed: 2
Date range: 2025-11-14 09:00:00+00:00 to 2025-11-16 14:30:00+00:00

Anomalies Detected:
  Impossible Travel: 2
  New Locations: 0
  New Devices: 0
  Failure Spikes: 0

Potential Compromises:
  john.doe@contoso.com: 2025-11-14 10:00:00+00:00 (high confidence)
    Reason: First successful login with risk flag
```

---

## Enhancement Phases (Reference)

### Phase 1: Data Foundation - COMPLETE
**Goal**: Prepare data structures for advanced analysis

#### 1.1 Enhanced Data Loading
- **File**: `entra/data_loader.py` ✅
- **Changes**:
  - Add JSON export support (currently CSV-only) ✅
  - Parse nested fields (location, status, deviceDetail) ✅
  - Convert to pandas DataFrame with typed columns ✅
  - Extract timestamps as datetime objects ✅

#### 1.2 Field Extraction
- **File**: `entra/field_extractor.py` ✅
- **Extract**:
  - `location.countryOrRegion`, `location.city`, `location.state` ✅
  - `status.errorCode`, `status.failureReason` ✅
  - `deviceDetail.operatingSystem`, `deviceDetail.browser`, `deviceDetail.deviceId` ✅
  - `riskLevel`, `riskState`, `riskDetail` ✅

#### 1.3 Configuration Updates
- **Note**: Configuration handled in analyzer class, not AuditConfig (simpler approach)

---

### Phase 2: Baseline Profiling - COMPLETE
**Goal**: Establish per-user normal behavior

#### 2.1 Baseline Calculator
- **File**: `entra/baseline.py` ✅
- **Class**: `UserBaseline` ✅
- **Calculate per user**:
  - Typical IP addresses (top 10) ✅
  - Typical countries/cities (top 10) ✅
  - Typical devices (OS, browser) ✅
  - Typical sign-in hours (0-23) ✅
  - Typical applications ✅
  - Sign-in count ✅

---

### Phase 3: Rule-Based Anomaly Detection - COMPLETE
**Goal**: Implement deterministic detection rules

#### 3.1 Impossible Travel Detector ✅
- **File**: `entra/detectors/impossible_travel.py`
- **Logic**:
  - Calculate Haversine distance between consecutive sign-ins
  - Flag if required travel speed > 900 km/h
  - Uses built-in city coordinates (simplified approach for MVP)

#### 3.2 New Location Detector ✅
- **File**: `entra/detectors/new_location.py`
- **Logic**:
  - Compare sign-in country/city/IP against baseline
  - Flag new_country, new_city, or new_ip

#### 3.3 New Device Detector ✅
- **File**: `entra/detectors/new_device.py`
- **Logic**:
  - Compare device OS, browser, deviceId against baseline
  - Flag any new combination

#### 3.4 Failed Login Spike Detector ✅
- **File**: `entra/detectors/failure_spike.py`
- **Logic**:
  - Calculate daily failure counts per user
  - Use z-score to detect spikes (default: 3σ)

---

### Phase 4: GeoIP Integration - COMPLETE (v0.5.0)
**Goal**: Add geolocation enrichment

#### 4.1 GeoIP Service ✅
- **File**: `entra/geoip.py`
- **Features**:
  - MaxMind GeoLite2 database support (optional)
  - Built-in coordinates for 100+ major cities worldwide
  - IP address → coordinate caching
  - Geodesic distance calculation (geopy)

#### 4.2 Coordinate Extraction ✅
- **IP lookup**: Uses MaxMind if database provided
- **City fallback**: Uses built-in city coordinates
- **Distance**: Accurate geodesic calculation via geopy

---

### Phase 5: ML Anomaly Detection - COMPLETE (v0.5.0)
**Goal**: Add behavioral anomaly scoring

#### 5.1 Feature Engineering ✅
- **File**: `entra/ml/features.py`
- **Features**:
  - Cyclical time encoding (hour_sin, hour_cos, dow_sin, dow_cos)
  - IP address (label encoded)
  - Country/city (label encoded)
  - Operating system/browser (label encoded)
  - Risk level (ordinal: none=0, low=1, medium=2, high=3)
  - Success/failure, managed/compliant status

#### 5.2 Isolation Forest Model ✅
- **File**: `entra/ml/anomaly_model.py`
- **Algorithm**: `sklearn.ensemble.IsolationForest`
- **Training**: Per-user models (minimum 10 sign-ins)
- **Scoring**: Normalized 0-1 (higher = more anomalous)
- **Factors**: Automatic identification of contributing factors

#### 5.3 CLI Integration ✅
- **New args**:
  ```bash
  --entra-ml-detect              # Enable ML detection
  --entra-report-json FILE       # JSON report with ML results
  ```

---

### Phase 6: First Compromise Identification - COMPLETE
**Goal**: Pinpoint initial breach

#### 6.1 Compromise Detector ✅
- **File**: `entra/first_compromise.py`
- **Heuristics** (priority order):
  1. First successful login with `riskLevel` = high ✅
  2. First successful login from new IP after failed attempts ✅
  3. First successful login after impossible travel ✅
  4. First successful login from new country/device ✅

---

### Phase 7: Reporting & Export - COMPLETE (Basic)
**Goal**: Produce actionable reports

#### 7.1 Incident Report Generator ✅
- **File**: `entra/reporting.py`
- **Formats**:
  - Markdown (human-readable) ✅
  - CSV (filtered anomalies) ✅
  - JSON (machine-readable) ✅ v0.5.0

#### 7.2 Report Contents ✅
- Executive summary
- User baseline profile
- Anomalies detected
- First compromise details

#### 7.3 CLI Integration ✅
- **New args**:
  ```python
  --entra-report-md FILE        # Generate markdown report
  --entra-export-anomalies FILE # Export anomalies to CSV
  ```

---

## Dependencies

### v0.4.0
Uses existing pandas, numpy.

### v0.5.0 - ADDED
```toml
dependencies = [
    # ... existing ...
    "scikit-learn (>=1.3.0)",  # ML anomaly detection
    "geopy (>=2.3.0)",         # Geodesic distance calculations
    "geoip2 (>=4.7.0)",        # MaxMind GeoLite2 (optional)
]
```

---

## Testing Strategy

### Completed
- ✅ Test fixture created: `tests/fixtures/entra_signin_sample.json`
- ✅ Manual testing with synthetic data
- ✅ All Python syntax validation passed

### Pending (v0.5.0)
- Unit tests for each detector
- Integration tests for full workflow
- Performance testing with large datasets

---

## Success Metrics

### v0.4.0 Results
- ✅ Detect impossible travel: Working (2 detections in test data)
- ✅ Identify first compromise: Working (high confidence scoring)
- ✅ Generate markdown report: Working
- ✅ Export anomalies to CSV: Working

### v0.5.0 Results
- ✅ Improved impossible travel with GeoIP (100+ cities + MaxMind support)
- ✅ ML-based anomaly scoring (Isolation Forest per-user)
- ✅ JSON report format for automation
- ✅ Contributing factor identification for ML anomalies

---

## Future Enhancements (Post v0.5.0)

- **Real-time monitoring**: Watch directory for new exports
- **Correlation**: Cross-reference with Purview audit logs
- **Risk scoring**: Weighted anomaly scoring system
- **Interactive mode**: Jupyter notebook integration
- **Dashboard**: Web-based visualization (Plotly Dash)

---

## Git History

### v0.4.0 Commits
- `feat(entra): add anomaly detection and compromise identification` - All MVP features

### v0.5.0 Commits
- `feat(entra): add ML anomaly detection and GeoIP integration` - Full v0.5.0 features

### Branch
- `feature/entra-anomaly-detection`

---

**Next Action**: Create PR to merge v0.5.0 features to main.
